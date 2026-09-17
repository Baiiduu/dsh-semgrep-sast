import { realpath, stat } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-user-approval'
import type { SastScanResult } from '@aaub-software/dsh-sast-contract'
import {
  approveEscalation,
  escalationHintMarker,
  sandboxDenialMarker,
  validateEscalationArgs,
} from '@deepseek-ai/dsh-sandbox'
import { defineTool } from '@deepseek-ai/dsh-tools'
import {
  createSemgrepSastResult,
} from './agent-result.js'
import { DEFAULT_RULESET, type ResolvedConfig } from './config.js'
import type { ResolvedRuntime } from './runtime.js'
import { runSemgrep } from './semgrep.js'
import type { SemgrepScanInput } from './types.js'

function isInside(root: string, candidate: string): boolean {
  const relativePath = relative(root, candidate)
  return relativePath === ''
    || (relativePath !== '..' && !relativePath.startsWith(`..${sep}`) && !isAbsolute(relativePath))
}

async function resolveTargets(workspaceRoot: string, paths: readonly string[]): Promise<string[]> {
  const canonicalRoot = await realpath(workspaceRoot)
  const resolved = await Promise.all(paths.map(async (requestedPath, index) => {
    if (requestedPath.trim() === '') {
      throw new Error(`semgrep_scan: paths[${index}] must be a non-empty workspace-relative path`)
    }
    if (isAbsolute(requestedPath)) {
      throw new Error(`semgrep_scan: paths[${index}] must be relative to the workspace`)
    }

    const lexicalTarget = resolve(canonicalRoot, requestedPath)
    if (!isInside(canonicalRoot, lexicalTarget)) {
      throw new Error(`semgrep_scan: paths[${index}] escapes the workspace`)
    }
    const canonicalTarget = await realpath(lexicalTarget)
    if (!isInside(canonicalRoot, canonicalTarget)) {
      throw new Error(`semgrep_scan: paths[${index}] resolves outside the workspace`)
    }
    const targetInfo = await stat(canonicalTarget)
    if (!targetInfo.isFile() && !targetInfo.isDirectory()) {
      throw new Error(`semgrep_scan: paths[${index}] must identify a file or directory`)
    }

    const relativeTarget = relative(canonicalRoot, canonicalTarget)
    return relativeTarget === '' ? '.' : relativeTarget
  }))
  return [...new Set(resolved)]
}

function renderResult(result: SastScanResult): string {
  return JSON.stringify(result)
}

const locationSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    path: { type: 'string', required: true },
    startLine: { type: 'integer', required: true },
    startColumn: { type: 'integer', required: true },
    endLine: { type: 'integer', required: true },
    endColumn: { type: 'integer', required: true },
  },
} as const

const ruleSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string', required: true },
    name: { type: 'string' },
    severity: { type: 'string', enum: ['info', 'warning', 'error'], required: true },
    cwe: { type: 'array', items: { type: 'string' } },
    owasp: { type: 'array', items: { type: 'string' } },
    references: { type: 'array', items: { type: 'string' } },
  },
} as const

const evidenceSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    type: { type: 'string', required: true },
    description: { type: 'string' },
    locations: { type: 'array', items: locationSchema },
    data: { type: 'object', additionalProperties: true },
  },
} as const

const findingSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    id: { type: 'string', required: true },
    scanner: { type: 'string', required: true },
    rule: { ...ruleSchema, required: true },
    message: { type: 'string', required: true },
    location: { ...locationSchema, required: true },
    fingerprint: { type: 'string' },
    evidence: { type: 'array', items: evidenceSchema, required: true },
  },
} as const

const diagnosticSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    level: { type: 'string', enum: ['error', 'warning', 'info'], required: true },
    type: { type: 'string', required: true },
    message: { type: 'string', required: true },
    code: { oneOf: [{ type: 'integer' }, { type: 'string' }] },
    location: locationSchema,
  },
} as const

/** Build the model-facing Semgrep tool around one resolved runtime and Registry config. */
export function createSemgrepScanTool(
  ctx: Context,
  config: ResolvedConfig,
  runtime: ResolvedRuntime,
  configSpecifier: string,
) {
  return defineTool({
    name: 'semgrep_scan',
    description: 'Run a read-only Semgrep SAST scan over workspace-relative files or directories. '
      + 'Returns exact finding locations and reports partial coverage separately from result truncation. '
      + 'On Windows, Semgrep Core cannot open the system certificate store under the Harness ACL sandbox. '
      + 'Call normally first; after the reported denial, retry the exact scan once with '
      + 'sandbox_permissions="danger-full-access" and a one-sentence justification so Harness can ask the user for approval. '
      + 'Returns the versioned ssc-sast/v1 normalized result contract.',
    parameters: {
      paths: {
        type: 'array',
        items: { type: 'string' },
        description: 'Workspace-relative files or directories to scan. Defaults to the workspace root.',
      },
      ruleset: {
        type: 'string',
        enum: [DEFAULT_RULESET],
        default: DEFAULT_RULESET,
        description: 'Semgrep Registry ruleset to use. The first release supports p/default.',
      },
      sandbox_permissions: {
        type: 'string',
        enum: ['workspace-write', 'danger-full-access'],
        description: 'One-shot retry after a sandbox denial. Windows scans require danger-full-access because '
          + 'Semgrep Core is incompatible with the Harness ACL sandbox; requires justification and user approval.',
      },
      justification: {
        type: 'string',
        description: 'Required with sandbox_permissions: one sentence explaining why this scan needs wider process access.',
      },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          schemaVersion: { type: 'string', const: 'ssc-sast/v1', required: true },
          status: { type: 'string', enum: ['completed', 'partial'], required: true },
          scanner: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              name: { type: 'string', required: true },
              version: { type: 'string', required: true },
              configuration: { type: 'string' },
            },
          },
          scannedPaths: { type: 'array', items: { type: 'string' }, required: true },
          findings: { type: 'array', items: findingSchema, required: true },
          diagnostics: { type: 'array', items: diagnosticSchema, required: true },
          summary: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              scannedFiles: { type: 'integer' },
              totalFindings: { type: 'integer', required: true },
              returnedFindings: { type: 'integer', required: true },
              truncated: { type: 'boolean', required: true },
              durationMs: { type: 'number', required: true },
            },
          },
        },
      },
      render: (_args, result) => [{ type: 'text', text: renderResult(result) }],
    },
    async execute(args: SemgrepScanInput, exec) {
      const workspaceRoot = exec.agent?.session.header.cwd
      if (workspaceRoot === undefined) {
        throw new Error('semgrep_scan: the calling session does not define a workspace')
      }
      if (args.paths !== undefined && args.paths.length === 0) {
        throw new Error('semgrep_scan: paths must not be an empty array')
      }
      if (args.ruleset !== undefined && args.ruleset !== config.defaultRuleset) {
        throw new Error(`semgrep_scan: ruleset ${JSON.stringify(args.ruleset)} is not available`)
      }
      validateEscalationArgs(args.sandbox_permissions, args.justification)

      const standingPolicy = ctx.sandboxPolicy.resolve(
        exec.agent === undefined ? {} : { session: exec.agent.session },
      )
      const approvedMode = args.sandbox_permissions !== undefined && args.justification !== undefined
        ? await approveEscalation(
            {
              requestedMode: args.sandbox_permissions,
              justification: args.justification,
              effectiveMode: standingPolicy.mode,
              subject: 'scan',
            },
            {
              approver: ctx.get('approval'),
              agent: exec.agent,
              callId: exec.callId,
              toolName: 'semgrep_scan',
              signal: exec.signal,
            },
          )
        : undefined
      const sandboxPolicy = approvedMode === undefined
        ? standingPolicy
        : { ...standingPolicy, mode: approvedMode }
      if (process.platform === 'win32' && sandboxPolicy.mode !== 'danger-full-access') {
        throw new Error(
          'semgrep-sast: Semgrep Core cannot access the Windows certificate store under the Harness ACL sandbox; '
          + 'this scan requires explicit danger-full-access approval\n'
          + `${sandboxDenialMarker(sandboxPolicy.mode)}\n`
          + escalationHintMarker('scan'),
        )
      }
      if (sandboxPolicy.mode === 'read-only') {
        throw new Error(
          'semgrep-sast: Semgrep requires a writable private temporary directory\n'
          + `${sandboxDenialMarker(sandboxPolicy.mode)}\n`
          + escalationHintMarker('scan'),
        )
      }

      const targets = await resolveTargets(workspaceRoot, args.paths ?? ['.'])
      exec.signal.throwIfAborted()
      const scan = await runSemgrep(ctx, {
        runtime,
        cwd: workspaceRoot,
        targets,
        configSpecifier,
        timeoutMs: config.timeoutMs,
        signal: exec.signal,
        sandboxPolicy,
      })
      return createSemgrepSastResult(scan, configSpecifier, config.maxFindings)
    },
  })
}

import { realpath, stat } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { DEFAULT_RULESET, type ResolvedConfig } from './config.js'
import type { ResolvedRuntime } from './runtime.js'
import { runSemgrep } from './semgrep.js'
import type { SemgrepDiagnostic, SemgrepFinding, SemgrepScanResult } from './types.js'

const SEVERITY_ORDER: Readonly<Record<SemgrepFinding['severity'], number>> = {
  error: 0,
  warning: 1,
  info: 2,
}

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

function compareFindings(left: SemgrepFinding, right: SemgrepFinding): number {
  return SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
    || left.path.localeCompare(right.path)
    || left.startLine - right.startLine
    || left.startColumn - right.startColumn
    || left.ruleId.localeCompare(right.ruleId)
}

function renderDiagnostic(diagnostic: SemgrepDiagnostic): string {
  const message = diagnostic.message === undefined ? '' : `: ${diagnostic.message}`
  return `- [${diagnostic.level}] code ${diagnostic.code}, ${diagnostic.type}${message}`
}

function renderResult(result: SemgrepScanResult): string {
  const lines = [
    `Semgrep scan ${result.status}.`,
    `Engine: Semgrep ${result.engine.version} (${result.engine.runtimeMode} runtime).`,
    `Scanned paths: ${result.scannedPaths.length}.`,
    `Findings: ${result.totalFindings}; returned: ${result.returnedFindings}; truncated: ${String(result.truncated)}.`,
    `Duration: ${result.durationMs}ms.`,
  ]

  if (result.findings.length > 0) {
    lines.push('', 'Findings:')
    for (const finding of result.findings) {
      lines.push(
        `- [${finding.severity}] ${finding.ruleId} at ${finding.path}:${finding.startLine}:${finding.startColumn}`
        + `-${finding.endLine}:${finding.endColumn}: ${finding.message}`,
      )
    }
  }
  if (result.diagnostics.length > 0) {
    lines.push('', 'Diagnostics:', ...result.diagnostics.map(renderDiagnostic))
  }
  return lines.join('\n')
}

const findingSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ruleId: { type: 'string', required: true },
    severity: { type: 'string', enum: ['info', 'warning', 'error'], required: true },
    message: { type: 'string', required: true },
    path: { type: 'string', required: true },
    startLine: { type: 'integer', required: true },
    startColumn: { type: 'integer', required: true },
    endLine: { type: 'integer', required: true },
    endColumn: { type: 'integer', required: true },
    fingerprint: { type: 'string' },
  },
} as const

const diagnosticSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    level: { type: 'string', enum: ['error', 'warn', 'info'], required: true },
    code: { type: 'integer', required: true },
    type: { type: 'string', required: true },
    message: { type: 'string' },
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
      + 'Returns exact finding locations and reports partial coverage separately from result truncation.',
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
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          status: { type: 'string', enum: ['completed', 'partial'], required: true },
          engine: {
            type: 'object',
            additionalProperties: false,
            required: true,
            properties: {
              name: { type: 'string', const: 'semgrep', required: true },
              version: { type: 'string', required: true },
              runtimeMode: { type: 'string', enum: ['bundled', 'system'], required: true },
            },
          },
          scannedPaths: { type: 'array', items: { type: 'string' }, required: true },
          findings: { type: 'array', items: findingSchema, required: true },
          diagnostics: { type: 'array', items: diagnosticSchema, required: true },
          totalFindings: { type: 'integer', required: true },
          returnedFindings: { type: 'integer', required: true },
          truncated: { type: 'boolean', required: true },
          durationMs: { type: 'integer', required: true },
        },
      },
      render: (_args, result) => [{ type: 'text', text: renderResult(result) }],
    },
    async execute(args, exec) {
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

      const targets = await resolveTargets(workspaceRoot, args.paths ?? ['.'])
      exec.signal.throwIfAborted()
      const scan = await runSemgrep(ctx, {
        runtime,
        cwd: workspaceRoot,
        targets,
        configSpecifier,
        timeoutMs: config.timeoutMs,
        signal: exec.signal,
        sandboxPolicy: ctx.sandboxPolicy.resolve(
          exec.agent === undefined ? {} : { session: exec.agent.session },
        ),
      })
      const findings = [...scan.findings].sort(compareFindings).slice(0, config.maxFindings)
      const result: SemgrepScanResult = {
        status: scan.status,
        engine: {
          name: 'semgrep',
          version: scan.version,
          runtimeMode: runtime.mode,
        },
        scannedPaths: scan.scannedPaths,
        findings,
        diagnostics: scan.diagnostics,
        totalFindings: scan.findings.length,
        returnedFindings: findings.length,
        truncated: findings.length < scan.findings.length,
        durationMs: scan.durationMs,
      }
      return result
    },
  })
}

import type { Context } from '@deepseek-ai/cordis'
import type { SandboxExecutionPolicy, SandboxPolicy } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-subprocess'
import { parseSemgrepOutput } from './parser.js'
import type { ResolvedRuntime } from './runtime.js'
import type { SemgrepDiagnostic, SemgrepFinding } from './types.js'

const STDOUT_MAX_BYTES = 32 * 1024 * 1024
const STDERR_MAX_BYTES = 1024 * 1024
const TERMINATION_GRACE_MS = 2_000

export interface RunSemgrepRequest {
  runtime: ResolvedRuntime
  cwd: string
  targets: readonly string[]
  configSpecifier: string
  timeoutMs: number
  signal?: AbortSignal
  sandboxPolicy: SandboxExecutionPolicy
}

export interface RunSemgrepResult {
  status: 'completed' | 'partial'
  version: string
  scannedPaths: string[]
  findings: SemgrepFinding[]
  diagnostics: SemgrepDiagnostic[]
  durationMs: number
}

function boundedDiagnostic(text: string): string {
  const trimmed = text.trim()
  if (trimmed.length <= 4_000) return trimmed
  return `${trimmed.slice(0, 4_000)}\n[diagnostic truncated]`
}

function confinedPolicy(policy: SandboxExecutionPolicy): SandboxPolicy {
  if (policy.mode === 'danger-full-access') {
    throw new Error('semgrep-sast: danger-full-access is not a confined sandbox policy')
  }
  return { ...policy, mode: policy.mode }
}

/** Execute one foreground Semgrep scan through Harness-managed process services. */
export async function runSemgrep(
  ctx: Context,
  request: RunSemgrepRequest,
): Promise<RunSemgrepResult> {
  if (request.targets.length === 0) throw new Error('semgrep-sast: at least one scan target is required')

  const baseArgv = [
    request.runtime.executable,
    ...request.runtime.arguments,
    'scan',
    '--json',
    '--quiet',
    '--metrics=off',
    '--config',
    request.configSpecifier,
    ...request.targets,
  ]
  const argv = request.sandboxPolicy.mode === 'danger-full-access'
    ? baseArgv
    : ctx.sandbox.confine(baseArgv, confinedPolicy(request.sandboxPolicy)).argv

  const timeoutSignal = AbortSignal.timeout(request.timeoutMs)
  const signal = request.signal === undefined
    ? timeoutSignal
    : AbortSignal.any([request.signal, timeoutSignal])
  const startedAt = Date.now()
  const processHandle = ctx.subprocess.spawn({
    argv,
    cwd: request.cwd,
    stdio: {
      stdin: 'ignore',
      stdout: { maxBytes: STDOUT_MAX_BYTES },
      stderr: { maxBytes: STDERR_MAX_BYTES },
    },
    graceMs: TERMINATION_GRACE_MS,
    signal,
    env: { ...request.runtime.environment },
  })
  const outcome = await processHandle.done
  const durationMs = Date.now() - startedAt
  const stdout = processHandle.collected.stdout?.readFrom(0)
  const stderr = processHandle.collected.stderr?.readFrom(0)

  if (request.signal?.aborted === true) throw request.signal.reason
  if (timeoutSignal.aborted) {
    throw new Error(`semgrep-sast: scan timed out after ${request.timeoutMs}ms`)
  }
  if (stdout === undefined || stderr === undefined) {
    throw new Error('semgrep-sast: subprocess did not provide collected output')
  }
  if (stdout.lossy) {
    throw new Error(`semgrep-sast: JSON output exceeded ${STDOUT_MAX_BYTES} bytes`)
  }
  if (outcome.exitCode !== 0) {
    const diagnostic = boundedDiagnostic(stderr.text)
    throw new Error(
      `semgrep-sast: Semgrep exited with code ${String(outcome.exitCode)}`
      + (diagnostic === '' ? '' : `\n${diagnostic}`),
    )
  }

  let parsed
  try {
    parsed = parseSemgrepOutput(stdout.text)
  } catch (cause) {
    const diagnostic = boundedDiagnostic(stderr.text)
    throw new Error(
      'semgrep-sast: failed to parse Semgrep JSON output'
      + (diagnostic === '' ? '' : `\n${diagnostic}`),
      { cause },
    )
  }
  const status = parsed.reportedErrors.some(
    diagnostic => diagnostic.level === 'error' || diagnostic.level === 'warn',
  ) ? 'partial' : 'completed'

  return {
    status,
    version: parsed.version ?? request.runtime.version,
    scannedPaths: parsed.scannedPaths,
    findings: parsed.findings,
    diagnostics: parsed.reportedErrors,
    durationMs,
  }
}

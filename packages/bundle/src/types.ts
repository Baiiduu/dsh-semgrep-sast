/** Runtime source selected for a Semgrep scan. */
export type RuntimeMode = 'bundled' | 'system'

/** Arguments accepted by the model-facing `semgrep_scan` tool. */
export interface SemgrepScanInput {
  /** Workspace-relative files or directories. Defaults to the workspace root. */
  paths?: string[]
  /** Semgrep Registry ruleset used by the first release. */
  ruleset?: 'p/default'
  /** One-shot wider mode requested after a sandbox denial. */
  sandbox_permissions?: 'workspace-write' | 'danger-full-access'
  /** User-facing reason required with `sandbox_permissions`. */
  justification?: string
}

/** Rule metadata emitted by Semgrep and retained for deterministic normalization. */
export interface SemgrepRuleMetadata {
  cwe?: string[]
  owasp?: string[]
  references?: string[]
}

/** One validated finding parsed from native Semgrep JSON output. */
export interface ParsedSemgrepFinding {
  ruleId: string
  severity: 'info' | 'warning' | 'error'
  message: string
  path: string
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
  fingerprint?: string
  metadata?: SemgrepRuleMetadata
  matchedCode?: string
  metavariables?: Record<string, string>
}

/** Backward-compatible internal name used by the current execution pipeline. */
export type SemgrepFinding = ParsedSemgrepFinding

/** One diagnostic emitted by Semgrep while processing rules or source files. */
export interface SemgrepDiagnostic {
  level: 'error' | 'warn' | 'info'
  code: number
  type: string
  message?: string
}

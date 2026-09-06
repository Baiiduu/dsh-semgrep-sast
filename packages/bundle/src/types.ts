/** Runtime source selected for a Semgrep scan. */
export type RuntimeMode = 'bundled' | 'system'

/** Arguments accepted by the model-facing `semgrep_scan` tool. */
export interface SemgrepScanInput {
  /** Workspace-relative files or directories. Defaults to the workspace root. */
  paths?: string[]
  /** Semgrep Registry ruleset used by the first release. */
  ruleset?: 'p/default'
}

/** One source location reported by Semgrep. */
export interface SemgrepFinding {
  ruleId: string
  severity: 'info' | 'warning' | 'error'
  message: string
  path: string
  startLine: number
  startColumn: number
  endLine: number
  endColumn: number
  fingerprint?: string
}

/** Semgrep engine identity used for a completed scan. */
export interface SemgrepEngine {
  name: 'semgrep'
  version: string
  runtimeMode: RuntimeMode
}

/** One diagnostic emitted by Semgrep while processing rules or source files. */
export interface SemgrepDiagnostic {
  level: 'error' | 'warn' | 'info'
  code: number
  type: string
  message?: string
}

/** Canonical usable result returned by the `semgrep_scan` tool. */
export interface SemgrepScanResult {
  status: 'completed' | 'partial'
  engine: SemgrepEngine
  scannedPaths: string[]
  findings: SemgrepFinding[]
  diagnostics: SemgrepDiagnostic[]
  totalFindings: number
  returnedFindings: number
  truncated: boolean
  durationMs: number
}

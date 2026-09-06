import type { SemgrepDiagnostic, SemgrepFinding } from './types.js'

/** Validated subset of `semgrep scan --json` consumed by the plugin. */
export interface ParsedSemgrepOutput {
  version?: string
  scannedPaths: string[]
  findings: SemgrepFinding[]
  reportedErrors: SemgrepDiagnostic[]
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`semgrep output ${field} must be an object`)
  return value
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`semgrep output ${field} must be a non-empty string`)
  }
  return value
}

function requirePositiveInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`semgrep output ${field} must be a positive integer`)
  }
  return value as number
}

function requireInteger(value: unknown, field: string): number {
  if (!Number.isInteger(value)) {
    throw new Error(`semgrep output ${field} must be an integer`)
  }
  return value as number
}

function normalizePath(path: string): string {
  return path.replaceAll('\\', '/')
}

function normalizeSeverity(value: unknown, field: string): SemgrepFinding['severity'] {
  const severity = requireString(value, field).toUpperCase()
  switch (severity) {
    case 'CRITICAL':
    case 'HIGH':
    case 'ERROR':
      return 'error'
    case 'MEDIUM':
    case 'WARNING':
      return 'warning'
    case 'LOW':
    case 'INFO':
    case 'EXPERIMENT':
    case 'INVENTORY':
      return 'info'
    default:
      throw new Error(`semgrep output ${field} has unsupported severity ${JSON.stringify(value)}`)
  }
}

function parseFinding(value: unknown, index: number): SemgrepFinding {
  const field = `results[${index}]`
  const finding = requireRecord(value, field)
  const start = requireRecord(finding.start, `${field}.start`)
  const end = requireRecord(finding.end, `${field}.end`)
  const extra = requireRecord(finding.extra, `${field}.extra`)
  const fingerprint = extra.fingerprint

  if (fingerprint !== undefined && typeof fingerprint !== 'string') {
    throw new Error(`semgrep output ${field}.extra.fingerprint must be a string when present`)
  }

  return {
    ruleId: requireString(finding.check_id, `${field}.check_id`),
    severity: normalizeSeverity(extra.severity, `${field}.extra.severity`),
    message: requireString(extra.message, `${field}.extra.message`),
    path: normalizePath(requireString(finding.path, `${field}.path`)),
    startLine: requirePositiveInteger(start.line, `${field}.start.line`),
    startColumn: requirePositiveInteger(start.col, `${field}.start.col`),
    endLine: requirePositiveInteger(end.line, `${field}.end.line`),
    endColumn: requirePositiveInteger(end.col, `${field}.end.col`),
    ...(fingerprint !== undefined ? { fingerprint } : {}),
  }
}

function parseReportedError(value: unknown, index: number): SemgrepDiagnostic {
  const field = `errors[${index}]`
  const error = requireRecord(value, field)
  const type = typeof error.type === 'string'
    ? requireString(error.type, `${field}.type`)
    : JSON.stringify(error.type) ?? 'unknown error'
  const level = requireString(error.level, `${field}.level`)
  if (level !== 'error' && level !== 'warn' && level !== 'info') {
    throw new Error(`semgrep output ${field}.level has unsupported value ${JSON.stringify(level)}`)
  }
  const message = error.message
  if (message !== undefined && typeof message !== 'string') {
    throw new Error(`semgrep output ${field}.message must be a string when present`)
  }

  return {
    level,
    code: requireInteger(error.code, `${field}.code`),
    type,
    ...(message !== undefined && message.trim() !== '' ? { message } : {}),
  }
}

/** Parse and validate the stable fields emitted by `semgrep scan --json`. */
export function parseSemgrepOutput(text: string): ParsedSemgrepOutput {
  let value: unknown
  try {
    value = JSON.parse(text) as unknown
  } catch (cause) {
    throw new Error('semgrep produced invalid JSON output', { cause })
  }

  const output = requireRecord(value, 'root')
  if (!Array.isArray(output.results)) throw new Error('semgrep output results must be an array')
  if (!Array.isArray(output.errors)) throw new Error('semgrep output errors must be an array')
  const paths = requireRecord(output.paths, 'paths')
  if (!Array.isArray(paths.scanned)
    || !paths.scanned.every(path => typeof path === 'string' && path.trim() !== '')) {
    throw new Error('semgrep output paths.scanned must be an array of non-empty strings')
  }
  if (output.version !== undefined && typeof output.version !== 'string') {
    throw new Error('semgrep output version must be a string when present')
  }

  return {
    ...(output.version !== undefined ? { version: output.version } : {}),
    scannedPaths: paths.scanned.map(path => normalizePath(path as string)),
    findings: output.results.map(parseFinding),
    reportedErrors: output.errors.map(parseReportedError),
  }
}

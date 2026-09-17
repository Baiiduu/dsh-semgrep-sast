import {
  SAST_SCHEMA_VERSION,
  type SastDiagnostic,
  type SastEvidence,
  type SastFinding,
  type SastRule,
  type SastScanResult,
} from '@aaub-software/dsh-sast-contract'
import type { RunSemgrepResult } from './semgrep.js'
import type { SemgrepFinding } from './types.js'

export interface SemgrepMatchedCodeEvidence extends SastEvidence {
  type: 'semgrep.matched-code'
  data: {
    text: string
  }
}

export interface SemgrepMetavariablesEvidence extends SastEvidence {
  type: 'semgrep.metavariables'
  data: Record<string, string>
}

export type SemgrepEvidence = SemgrepMatchedCodeEvidence | SemgrepMetavariablesEvidence

/** Public model-facing result produced by the Semgrep adapter. */
export type SemgrepSastScanResult = SastScanResult<SemgrepEvidence>

const SEVERITY_ORDER: Readonly<Record<SemgrepFinding['severity'], number>> = {
  error: 0,
  warning: 1,
  info: 2,
}

function compareFindings(left: SemgrepFinding, right: SemgrepFinding): number {
  return SEVERITY_ORDER[left.severity] - SEVERITY_ORDER[right.severity]
    || left.path.localeCompare(right.path)
    || left.startLine - right.startLine
    || left.startColumn - right.startColumn
    || left.ruleId.localeCompare(right.ruleId)
}

function normalizeCwe(values: readonly string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.flatMap((value) => {
    const match = /\bCWE-[1-9][0-9]*\b/i.exec(value)
    return match === null ? [] : [match[0].toUpperCase()]
  })
  const uniqueValues = [...new Set(normalized)]
  return uniqueValues.length === 0 ? undefined : uniqueValues
}

function normalizeOwasp(values: readonly string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.flatMap((value) => {
    const match = /\bA[0-9]{1,2}:[0-9]{4}\b/i.exec(value)
    return match === null ? [] : [match[0].toUpperCase()]
  })
  const uniqueValues = [...new Set(normalized)]
  return uniqueValues.length === 0 ? undefined : uniqueValues
}

function normalizeReferences(values: readonly string[] | undefined): string[] | undefined {
  if (values === undefined) return undefined
  const normalized = values.filter((value) => {
    try {
      const url = new URL(value)
      return url.protocol === 'https:' || url.protocol === 'http:'
    } catch {
      return false
    }
  })
  const uniqueValues = [...new Set(normalized)]
  return uniqueValues.length === 0 ? undefined : uniqueValues
}

function createRule(finding: SemgrepFinding): SastRule {
  const cwe = normalizeCwe(finding.metadata?.cwe)
  const owasp = normalizeOwasp(finding.metadata?.owasp)
  const references = normalizeReferences(finding.metadata?.references)
  return {
    id: finding.ruleId,
    severity: finding.severity,
    ...(cwe === undefined ? {} : { cwe }),
    ...(owasp === undefined ? {} : { owasp }),
    ...(references === undefined ? {} : { references }),
  }
}

function createEvidence(finding: SemgrepFinding): SemgrepEvidence[] {
  const evidence: SemgrepEvidence[] = []
  if (finding.matchedCode !== undefined) {
    evidence.push({
      type: 'semgrep.matched-code',
      data: { text: finding.matchedCode },
    })
  }
  if (finding.metavariables !== undefined) {
    evidence.push({
      type: 'semgrep.metavariables',
      data: { ...finding.metavariables },
    })
  }
  return evidence
}

function createFindingId(finding: SemgrepFinding): string {
  const fingerprint = finding.fingerprint?.trim()
  if (fingerprint !== undefined && fingerprint !== '') return `semgrep:${fingerprint}`
  return [
    'semgrep',
    encodeURIComponent(finding.ruleId),
    encodeURIComponent(finding.path),
    String(finding.startLine),
    String(finding.startColumn),
  ].join(':')
}

function createFinding(finding: SemgrepFinding): SastFinding<SemgrepEvidence> {
  return {
    id: createFindingId(finding),
    scanner: 'semgrep',
    rule: createRule(finding),
    message: finding.message,
    location: {
      path: finding.path,
      startLine: finding.startLine,
      startColumn: finding.startColumn,
      endLine: finding.endLine,
      endColumn: finding.endColumn,
    },
    ...(finding.fingerprint === undefined ? {} : { fingerprint: finding.fingerprint }),
    evidence: createEvidence(finding),
  }
}

function createDiagnostic(
  diagnostic: RunSemgrepResult['diagnostics'][number],
): SastDiagnostic {
  return {
    level: diagnostic.level === 'warn' ? 'warning' : diagnostic.level,
    type: diagnostic.type,
    message: diagnostic.message?.trim() || `Semgrep diagnostic code ${diagnostic.code}`,
    code: diagnostic.code,
  }
}

/** Convert one validated Semgrep execution result into the public SSC SAST contract. */
export function createSemgrepSastResult(
  scan: RunSemgrepResult,
  configuration: string,
  maxFindings: number,
): SemgrepSastScanResult {
  if (!Number.isInteger(maxFindings) || maxFindings < 1) {
    throw new Error('semgrep-sast: maxFindings must be a positive integer')
  }

  const selectedFindings = [...scan.findings]
    .sort(compareFindings)
    .slice(0, maxFindings)
    .map(createFinding)

  return {
    schemaVersion: SAST_SCHEMA_VERSION,
    status: scan.status,
    scanner: {
      name: 'semgrep',
      version: scan.version,
      configuration,
    },
    scannedPaths: [...scan.scannedPaths],
    findings: selectedFindings,
    diagnostics: scan.diagnostics.map(createDiagnostic),
    summary: {
      totalFindings: scan.findings.length,
      returnedFindings: selectedFindings.length,
      truncated: selectedFindings.length < scan.findings.length,
      durationMs: scan.durationMs,
    },
  }
}

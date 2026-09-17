import assert from 'node:assert/strict'
import test from 'node:test'
import { createSemgrepSastResult } from '../lib/agent-result.js'
import { parseSemgrepOutput } from '../lib/parser.js'

test('normalizes representative Semgrep JSON into ssc-sast/v1', () => {
  const parsed = parseSemgrepOutput(JSON.stringify({
    version: '1.175.0',
    results: [
      {
        check_id: 'javascript.lang.security.audit.detect-eval-with-expression',
        path: 'src\\server.js',
        start: { line: 2, col: 18, offset: 56 },
        end: { line: 2, col: 44, offset: 82 },
        extra: {
          severity: 'ERROR',
          message: 'Detected eval with a non-literal expression.',
          fingerprint: 'f2b91e32bb169fc1',
          lines: 'eval(req.query.expression)',
          metavars: {
            $EXPR: {
              abstract_content: 'req.query.expression',
              start: { line: 2, col: 23, offset: 61 },
              end: { line: 2, col: 43, offset: 81 },
            },
          },
          metadata: {
            cwe: ['CWE-95: Dynamic Code Evaluation'],
            owasp: ['A03:2021 - Injection'],
            references: [
              'https://owasp.org/example',
              'not-a-valid-reference',
            ],
          },
        },
      },
    ],
    errors: [],
    paths: {
      scanned: ['src\\server.js'],
      skipped: [],
    },
  }))

  const result = createSemgrepSastResult(
    {
      status: 'completed',
      version: parsed.version ?? 'unknown',
      scannedPaths: parsed.scannedPaths,
      findings: parsed.findings,
      diagnostics: parsed.reportedErrors,
      durationMs: 125,
    },
    'p/default',
    200,
  )

  assert.deepEqual(result, {
    schemaVersion: 'ssc-sast/v1',
    status: 'completed',
    scanner: {
      name: 'semgrep',
      version: '1.175.0',
      configuration: 'p/default',
    },
    scannedPaths: ['src/server.js'],
    findings: [
      {
        id: 'semgrep:f2b91e32bb169fc1',
        scanner: 'semgrep',
        rule: {
          id: 'javascript.lang.security.audit.detect-eval-with-expression',
          severity: 'error',
          cwe: ['CWE-95'],
          owasp: ['A03:2021'],
          references: ['https://owasp.org/example'],
        },
        message: 'Detected eval with a non-literal expression.',
        location: {
          path: 'src/server.js',
          startLine: 2,
          startColumn: 18,
          endLine: 2,
          endColumn: 44,
        },
        fingerprint: 'f2b91e32bb169fc1',
        evidence: [
          {
            type: 'semgrep.matched-code',
            data: {
              text: 'eval(req.query.expression)',
            },
          },
          {
            type: 'semgrep.metavariables',
            data: {
              $EXPR: 'req.query.expression',
            },
          },
        ],
      },
    ],
    diagnostics: [],
    summary: {
      totalFindings: 1,
      returnedFindings: 1,
      truncated: false,
      durationMs: 125,
    },
  })
})

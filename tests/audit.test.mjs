import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, symlink, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { createSemgrepSastResult } from '../lib/agent-result.js'
import { attachSourceContext } from '../lib/source-context.js'


function finding(path, line, cwe = 'CWE-22', severity = 'info') {
  return { ruleId: 'audit', path, startLine: line, endLine: line, startColumn: 1,
    endColumn: 2, severity, message: 'candidate', metadata: { cwe: [cwe] } }
}
function scan(findings) {
  return { status: 'partial', version: '1.163.0', findings, scannedPaths: [], durationMs: 1,
    diagnostics: [{ level: 'warn', code: 2, type: 'parse', message: 'partial coverage' }] }
}
test('focus applies before cap; diversification prevents one file occupying the response', () => {
  const raw = scan([finding('a.js', 1, 'CWE-78', 'error'), finding('b.js', 1),
    finding('b.js', 2), finding('c.js', 1)])
  const result = createSemgrepSastResult(raw, 'cwe-audit', 2, { focusCwes: ['CWE-22'], diversify: true })
  assert.deepEqual(result.findings.map(x => x.location.path), ['b.js', 'c.js'])
  assert.equal(result.summary.totalFindings, 4)
  assert.equal(result.summary.truncated, true)
  assert.equal(result.status, 'partial')
  assert.equal(result.diagnostics.length, 1)
  assert.throws(() => createSemgrepSastResult(raw, 'cwe-audit', 2, { focusCwes: ['CWE-2oops'] }))
})
test('context retains a preceding guard and refuses symlink escape or large reads', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sast-context-'))
  try {
    const workspace = join(root, 'workspace')
    await mkdir(workspace)
    await writeFile(join(workspace, 'guard.py'), 'if not allowed(path):\n    raise ValueError()\nopen(path)\n')
    await writeFile(join(root, 'secret.txt'), 'outside-root')
    await symlink(root, join(workspace, 'outside'), 'junction')
    await writeFile(join(workspace, 'big.py'), 'x'.repeat(512 * 1024 + 2))
    const result = await attachSourceContext(createSemgrepSastResult(scan([
      finding('guard.py', 3), finding('outside/secret.txt', 1), finding('big.py', 1),
    ]), 'cwe-audit', 3), workspace, 3)
    const safe = result.findings.find(x => x.location.path === 'guard.py')
    assert.match(safe.evidence[0].data.text, /allowed\(path\)/)
    assert.equal(result.diagnostics.filter(x => x.type === 'context-unavailable').length, 2)
    assert.ok(!JSON.stringify(result).includes('outside-root'))
  } finally { await rm(root, { recursive: true, force: true }) }
})

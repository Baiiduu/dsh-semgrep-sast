import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtemp, mkdir, rm, writeFile, symlink, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { resolveTargets, runProcess, scanWorkspace, validateInput } from '../lib/runner.js'

test('validates scan arguments and rejects obsolete Harness permissions', () => {
  for (const args of [{ paths: [] }, { ruleset: '--help' }, { focus_cwes: ['CWE-22oops'] },
    { max_findings: 201 }, { context_lines: -1 }, { diversify: 'yes' }, { sandbox_permissions: 'danger-full-access' }]) {
    assert.throws(() => validateInput(args))
  }
})

test('rejects traversal, absolute paths and symlink escapes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sast-path-test-'))
  try {
    const workspace = join(root, 'workspace')
    await mkdir(workspace)
    await symlink(root, join(workspace, 'outside'), 'junction')
    for (const path of ['..', root, 'C:\\Windows', 'C:relative', 'outside']) {
      await assert.rejects(resolveTargets(workspace, [path]), /workspace/)
    }
    assert.deepEqual(await resolveTargets(workspace, ['.', '.']), ['.'])
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('process runner enforces timeout, cancellation, output limits and launch errors', async () => {
  await assert.rejects(runProcess([process.execPath, '-e', 'setInterval(()=>{},1000)'], { timeoutMs: 150 }), /timed out/)
  await assert.rejects(runProcess([process.execPath, '-e', 'setInterval(()=>{},1000)'], { signal: AbortSignal.timeout(150) }), /timeout/i)
  await assert.rejects(runProcess([process.execPath, '-e', 'console.log("x".repeat(10000))'], { stdoutLimit: 100 }), /exceeded/)
  await assert.rejects(runProcess(['semgrep-nonexistent-test-executable']), /ENOENT/)
})

test('adapter preserves partial status, ranking, truncation and source context', async () => {
  const root = await mkdtemp(join(tmpdir(), 'sast-adapter-test-'))
  try {
    await writeFile(join(root, 'a b.py'), 'if allowed(path):\n    open(path)\n')
    const raw = { version: 'test', paths: { scanned: ['a b.py'] }, errors: [{ level: 'warn', code: 3, type: 'parse', message: 'partial' }],
      results: ['CWE-78', 'CWE-22'].map(cwe => ({ check_id: cwe, path: 'a b.py', start: { line: 2, col: 5 }, end: { line: 2, col: 15 },
        extra: { severity: 'INFO', message: 'candidate', metadata: { cwe: [cwe] } } })) }
    const fake = join(root, 'fake.mjs')
    await writeFile(fake, `import assert from 'node:assert/strict'; assert.equal(process.argv.at(-2),'--'); assert.equal(process.argv.at(-1),'a b.py'); console.log(${JSON.stringify(JSON.stringify(raw))})`)
    const result = await scanWorkspace({ paths: ['a b.py'], ruleset: 'cwe-audit', focus_cwes: ['CWE-22'], max_findings: 1, context_lines: 2 },
      { cwd: root, runtime: { executable: process.execPath, arguments: [fake], environment: {} } })
    assert.equal(result.status, 'partial')
    assert.equal(result.summary.truncated, true)
    assert.deepEqual(result.findings[0].rule.cwe, ['CWE-22'])
    assert.match(result.findings[0].evidence[0].data.text, /allowed/)
  } finally { await rm(root, { recursive: true, force: true }) }
})

test('real offline scan with an explicitly supplied runtime manifest', { skip: !process.env.SEMGREP_TEST_MANIFEST }, async () => {
  const manifestPath = process.env.SEMGREP_TEST_MANIFEST
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  const { dirname, resolve } = await import('node:path')
  const root = await mkdtemp(join(tmpdir(), 'sast-real-test-'))
  try {
    await writeFile(join(root, 'sample.py'), 'def load(path):\n    return open(path).read()\n')
    const result = await scanWorkspace({ ruleset: 'cwe-audit', context_lines: 1 }, { cwd: root,
      runtime: { executable: resolve(dirname(manifestPath), manifest.launcher.executable), arguments: manifest.launcher.arguments, environment: manifest.environment } })
    assert.equal(result.schemaVersion, 'ssc-sast/v1')
    assert.ok(result.scannedPaths.includes('sample.py'))
    assert.ok(result.findings.length > 0)
    assert.equal(result.scanner.version, manifest.semgrepVersion)
  } finally { await rm(root, { recursive: true, force: true }) }
})

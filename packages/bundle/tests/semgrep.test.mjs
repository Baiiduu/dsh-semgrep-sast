import assert from 'node:assert/strict'
import { setTimeout as delay } from 'node:timers/promises'
import test from 'node:test'
import { runSemgrep } from '../lib/semgrep.js'

const request = {
  runtime: { executable: 'python', arguments: ['launcher.py'], environment: {}, version: '1.163.0' },
  cwd: process.cwd(),
  targets: ['src'],
  configSpecifier: 'p/default',
  timeoutMs: 10_000,
  sandboxPolicy: { mode: 'danger-full-access' },
}

function context({ stderr = '', waitForAbort = false, exitCode = 0 } = {}) {
  let captured
  return {
    get captured() { return captured },
    subprocess: {
      spawn(options) {
        captured = options
        return {
          done: waitForAbort
            ? delay(1_000, undefined, { signal: options.signal }).catch(() => ({ exitCode: 1 }))
            : Promise.resolve({ exitCode }),
          collected: {
            stdout: { readFrom: () => ({ text: '{"version":"1.163.0","results":[],"errors":[],"paths":{"scanned":["src/a.py"]}}', lossy: false }) },
            stderr: { readFrom: () => ({ text: stderr, lossy: false }) },
          },
        }
      },
    },
  }
}

test('preserves targets and enables diagnostics without changing project-root or ignore options', async () => {
  const ctx = context()
  const result = await runSemgrep(ctx, request)
  assert.equal(result.status, 'completed')
  assert.deepEqual(result.scannedPaths, ['src/a.py'])
  assert.deepEqual(ctx.captured.argv, [
    'python', 'launcher.py', 'scan', '--json', '--verbose', '--metrics=off', '--config', 'p/default', 'src',
  ])
  assert.equal(ctx.captured.cwd, request.cwd)
})

test('timeout keeps the start and end of stderr with a bounded diagnostic', async () => {
  const ctx = context({ waitForAbort: true, stderr: 'rules loaded\n' + 'x'.repeat(10_000) + '\nget_targets: junction loop' })
  await assert.rejects(runSemgrep(ctx, { ...request, timeoutMs: 10 }), error => {
    assert.match(error.message, /scan timed out after 10ms\nrules loaded/)
    assert.match(error.message, /\[diagnostic truncated\]/)
    assert.match(error.message, /get_targets: junction loop$/)
    assert.ok(error.message.length < 4_200)
    return true
  })
})

test('timeout reports when stderr is empty without guessing the cause', async () => {
  await assert.rejects(runSemgrep(context({ waitForAbort: true }), { ...request, timeoutMs: 10 }),
    /No stderr diagnostics were captured/)
})

test('caller cancellation retains its original reason', async () => {
  const controller = new AbortController()
  const reason = new Error('caller cancelled')
  controller.abort(reason)
  await assert.rejects(runSemgrep(context({ waitForAbort: true }), { ...request, signal: controller.signal }),
    error => error === reason)
})

test('nonzero exit reports stderr', async () => {
  await assert.rejects(runSemgrep(context({ exitCode: 2, stderr: 'invalid rule' }), request),
    /Semgrep exited with code 2\ninvalid rule/)
})

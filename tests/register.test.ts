import { expect, test } from 'claude-code/testing'

const tool = 'mcp__dsh-semgrep-sast-cc__semgrep_scan'

test('registers the scan schema without starting a process', async ($, on) => {
  let registered
  on('tool.register', (_$, event) => { registered = event; return {} })
  on('session.start', (_$, event) => ({ cwd: event.cwd }))
  await $.session.start({ cwd: '/workspace', surface: 'terminal', isInteractive: true })
  expect(registered.name).toBe('semgrep_scan')
  expect(registered.inputSchema.properties.ruleset.enum).toEqual(['p/default', 'cwe-audit'])
})

test('passes flat tool arguments as JSON stdin with workspace cwd', async ($, on) => {
  let request
  on('session.cwd', () => ({ value: '/workspace with spaces' }))
  on('process.run', (_$, event) => {
    request = event
    return { value: { exitCode: 0, stdout: JSON.stringify({ schemaVersion: 'ssc-sast/v1', findings: [] }), stderr: '' } }
  })
  const answer = await $.tool.call({ tool, paths: ['src/a b.py'], ruleset: 'cwe-audit', context_lines: 3 })
  expect(answer.result.schemaVersion).toBe('ssc-sast/v1')
  expect(request.argv[0]).toBe('node')
  expect(request.init.cwd).toBe('/workspace with spaces')
  expect(JSON.parse(request.init.stdin)).toEqual({ paths: ['src/a b.py'], ruleset: 'cwe-audit', context_lines: 3 })
})

test('reports scan failure and invalid output instead of a clean scan', async ($, on) => {
  on('session.cwd', () => ({ value: '/workspace' }))
  on('process.run', () => ({ value: { exitCode: 2, stdout: '', stderr: 'scanner unavailable' } }))
  const answer = await $.tool.call({ tool })
  expect(answer.result).toBe('Semgrep scan failed: scanner unavailable')
})

test('rejects truncated JSON and leaves other tools alone', async ($, on) => {
  on('session.cwd', () => ({ value: '/workspace' }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: '{', stderr: '' } }))
  on('tool.call', () => ({ result: 'other tool' }))
  const answer = await $.tool.call({ tool })
  expect(String(answer.result).startsWith('Semgrep scan failed:')).toBe(true)
  expect((await $.tool.call({ tool: 'Read', file_path: 'a' })).result).toBe('other tool')
})

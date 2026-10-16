import { scanWorkspace } from '../lib/runner.js'

const controller = new AbortController()
const cancel = () => controller.abort(new Error('Scan cancelled'))
process.once('SIGTERM', cancel)
process.once('SIGINT', cancel)
try {
  let input = ''
  process.stdin.setEncoding('utf8')
  for await (const chunk of process.stdin) {
    input += chunk
    if (Buffer.byteLength(input) > 64 * 1024) throw new Error('Scan input exceeds 64 KiB')
  }
  const result = await scanWorkspace(JSON.parse(input || '{}'), { signal: controller.signal })
  const output = JSON.stringify(result)
  if (Buffer.byteLength(output) > 512 * 1024) throw new Error('Scan result exceeds 512 KiB; narrow paths or reduce max_findings/context_lines')
  process.stdout.write(output + '\n')
} catch (error) {
  process.stderr.write((error instanceof Error ? error.message : String(error)).slice(-4000) + '\n')
  process.exitCode = 1
} finally {
  process.removeListener('SIGTERM', cancel)
  process.removeListener('SIGINT', cancel)
}

import { spawn } from 'node:child_process'
import { mkdtemp, readFile, realpath, rm, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, relative, resolve, sep, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseSemgrepOutput } from './parser.js'
import { createSemgrepSastResult } from './agent-result.js'
import { attachSourceContext } from './source-context.js'

function isInside(root, candidate) {
  const path = relative(root, candidate)
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path))
}

export function validateInput(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) throw new Error('Scan arguments must be an object')
  const keys = ['paths', 'ruleset', 'focus_cwes', 'diversify', 'context_lines', 'max_findings']
  for (const key of Object.keys(args)) if (!keys.includes(key)) throw new Error(`Unknown scan argument: ${key}`)
  const paths = args.paths ?? ['.']
  if (!Array.isArray(paths) || paths.length === 0 || paths.some(path => typeof path !== 'string' || !path.trim() || path.includes('\0'))) {
    throw new Error('paths must contain non-empty workspace-relative strings')
  }
  const ruleset = args.ruleset ?? 'p/default'
  if (!['p/default', 'cwe-audit'].includes(ruleset)) throw new Error('ruleset must be p/default or cwe-audit')
  const focusCwes = args.focus_cwes ?? []
  if (!Array.isArray(focusCwes) || focusCwes.some(cwe => typeof cwe !== 'string' || !/^CWE-[1-9][0-9]*$/.test(cwe))) {
    throw new Error('focus_cwes must contain canonical CWE identifiers')
  }
  if (args.diversify !== undefined && typeof args.diversify !== 'boolean') throw new Error('diversify must be boolean')
  const contextLines = args.context_lines ?? 0
  const maxFindings = args.max_findings ?? 200
  if (!Number.isInteger(contextLines) || contextLines < 0 || contextLines > 20) throw new Error('context_lines must be 0..20')
  if (!Number.isInteger(maxFindings) || maxFindings < 1 || maxFindings > 200) throw new Error('max_findings must be 1..200')
  return { paths, ruleset, focusCwes, diversify: args.diversify ?? false, contextLines, maxFindings }
}

export async function resolveTargets(workspace, paths) {
  const root = await realpath(workspace)
  const targets = []
  for (const path of paths) {
    if (isAbsolute(path) || win32.isAbsolute(path) || /^[a-z]:/i.test(path)) throw new Error('Scan paths must be workspace-relative')
    const lexical = resolve(root, path)
    if (!isInside(root, lexical)) throw new Error('Scan path escapes the workspace')
    const canonical = await realpath(lexical)
    if (!isInside(root, canonical)) throw new Error('Scan path resolves outside the workspace')
    const info = await stat(canonical)
    if (!info.isFile() && !info.isDirectory()) throw new Error('Scan target must be a file or directory')
    targets.push(relative(root, canonical) || '.')
  }
  return [...new Set(targets)]
}

export async function resolveRuntime() {
  const executable = process.env.DSH_SEMGREP_EXECUTABLE?.trim()
  if (executable) return { executable, arguments: [], environment: {} }
  if (process.platform !== 'win32') return { executable: 'semgrep', arguments: [], environment: {} }
  if (process.arch !== 'x64') throw new Error('Set DSH_SEMGREP_EXECUTABLE for this Windows architecture')
  let manifestPath
  try {
    manifestPath = fileURLToPath(import.meta.resolve('@aaub-software/semgrep-runtime-win32-x64/runtime-manifest.json'))
  } catch {
    throw new Error('Install @aaub-software/semgrep-runtime-win32-x64 in the plugin directory (see README), or set DSH_SEMGREP_EXECUTABLE')
  }
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  const root = dirname(manifestPath)
  const candidate = resolve(root, manifest.launcher.executable)
  if (manifest.manifestVersion !== 1 || manifest.platform !== 'win32' || manifest.architecture !== 'x64' || !isInside(root, candidate)) {
    throw new Error('Invalid bundled runtime manifest')
  }
  await stat(candidate)
  return { executable: candidate, arguments: manifest.launcher.arguments, environment: manifest.environment }
}

// The hook calls this in a separate Node process; it never imports Node APIs itself.
export function runProcess(argv, { cwd, env, timeoutMs = 300000, signal, stdoutLimit = 32 * 1024 * 1024, stderrLimit = 1024 * 1024 } = {}) {
  signal?.throwIfAborted()
  return new Promise((resolveResult, reject) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd, env: { ...process.env, ...env }, shell: false, windowsHide: true,
      detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
    })
    const output = { stdout: [], stderr: [] }
    const sizes = { stdout: 0, stderr: 0 }
    let failure
    let killing
    function stop(error) {
      if (failure) return
      failure = error
      if (!child.pid) return
      if (process.platform === 'win32') {
        killing = new Promise(done => {
          const killer = spawn(join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'taskkill.exe'),
            ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' })
          killer.once('error', () => { child.kill(); done() })
          killer.once('close', code => { if (code !== 0) child.kill(); done() })
        })
      } else {
        try { process.kill(-child.pid, 'SIGKILL') } catch { child.kill('SIGKILL') }
      }
    }
    const timer = setTimeout(() => stop(new Error(`Semgrep timed out after ${timeoutMs}ms`)), timeoutMs)
    const abort = () => stop(signal.reason ?? new Error('Scan cancelled'))
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort()
    for (const [name, limit] of [['stdout', stdoutLimit], ['stderr', stderrLimit]]) {
      child[name].on('data', chunk => {
        sizes[name] += chunk.length
        if (sizes[name] > limit) stop(new Error(`Semgrep ${name} exceeded ${limit} bytes`))
        else output[name].push(chunk)
      })
    }
    child.once('error', error => { failure ??= error })
    child.once('close', async code => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      await killing
      if (failure) reject(failure)
      else resolveResult({ exitCode: code, stdout: Buffer.concat(output.stdout).toString('utf8'), stderr: Buffer.concat(output.stderr).toString('utf8') })
    })
  })
}

export async function scanWorkspace(args, { cwd = process.cwd(), signal, runtime, timeoutMs = 300000 } = {}) {
  const input = validateInput(args)
  const root = await realpath(cwd)
  const targets = await resolveTargets(root, input.paths)
  runtime ??= await resolveRuntime()
  const config = input.ruleset === 'cwe-audit'
    ? fileURLToPath(new URL('../rules/cwe-audit.json', import.meta.url)) : input.ruleset
  const tempRoot = await mkdtemp(join(tmpdir(), 'dsh-semgrep-cc-'))
  const startedAt = Date.now()
  try {
    const output = await runProcess([
      runtime.executable, ...runtime.arguments, 'scan', '--json', '--verbose', '--metrics=off',
      '--disable-version-check', '--config', config, '--', ...targets,
    ], {
      cwd: root, signal, timeoutMs,
      env: {
        ...runtime.environment, PYTHONUTF8: '1', SEMGREP_SEND_METRICS: 'off',
        TMP: tempRoot, TEMP: tempRoot, TMPDIR: tempRoot,
        XDG_CACHE_HOME: tempRoot, XDG_CONFIG_HOME: tempRoot,
        SEMGREP_SETTINGS_FILE: join(tempRoot, 'settings.yml'),
        SEMGREP_LOG_FILE: join(tempRoot, 'semgrep.log'),
        SEMGREP_VERSION_CACHE_PATH: join(tempRoot, 'version'),
      },
    })
    if (output.exitCode !== 0) throw new Error(`Semgrep exited with code ${output.exitCode}: ${output.stderr.slice(-4000)}`)
    const parsed = parseSemgrepOutput(output.stdout)
    const result = createSemgrepSastResult({
      status: parsed.reportedErrors.some(item => item.level === 'error' || item.level === 'warn') ? 'partial' : 'completed',
      version: parsed.version ?? 'unknown', scannedPaths: parsed.scannedPaths,
      findings: parsed.findings, diagnostics: parsed.reportedErrors, durationMs: Date.now() - startedAt,
    }, input.ruleset, input.maxFindings, input)
    return await attachSourceContext(result, root, input.contextLines)
  } finally {
    // tempRoot is the unique directory created by mkdtemp above.
    await rm(tempRoot, { recursive: true, force: true })
  }
}

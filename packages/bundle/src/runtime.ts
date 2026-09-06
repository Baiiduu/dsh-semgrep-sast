import { readFile } from 'node:fs/promises'
import { dirname, isAbsolute, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-subprocess'
import type { ResolvedConfig } from './config.js'
import type { RuntimeMode } from './types.js'

const WIN32_X64_RUNTIME_MANIFEST =
  '@aaub-software/semgrep-runtime-win32-x64/runtime-manifest.json'

interface RuntimeManifest {
  manifestVersion: 1
  semgrepVersion: string
  platform: 'win32'
  architecture: 'x64'
  launcher: {
    executable: string
    arguments: string[]
  }
  environment: Record<string, string>
}

/** An executable Semgrep runtime with all implicit launcher details resolved. */
export interface ResolvedRuntime {
  mode: RuntimeMode
  version: string
  executable: string
  arguments: readonly string[]
  environment: Readonly<Record<string, string>>
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function parseRuntimeManifest(value: unknown): RuntimeManifest {
  if (!isRecord(value)) throw new Error('runtime manifest must be an object')
  if (value.manifestVersion !== 1) throw new Error('runtime manifestVersion must be 1')
  if (typeof value.semgrepVersion !== 'string' || value.semgrepVersion.trim() === '') {
    throw new Error('runtime semgrepVersion must be a non-empty string')
  }
  if (value.platform !== 'win32' || value.architecture !== 'x64') {
    throw new Error('runtime platform must be win32-x64')
  }
  if (!isRecord(value.launcher)) throw new Error('runtime launcher must be an object')
  if (typeof value.launcher.executable !== 'string' || value.launcher.executable.trim() === '') {
    throw new Error('runtime launcher.executable must be a non-empty string')
  }
  if (!Array.isArray(value.launcher.arguments)
    || !value.launcher.arguments.every(argument => typeof argument === 'string')) {
    throw new Error('runtime launcher.arguments must be an array of strings')
  }
  if (!isRecord(value.environment)
    || !Object.values(value.environment).every(entry => typeof entry === 'string')) {
    throw new Error('runtime environment must contain only string values')
  }

  return value as unknown as RuntimeManifest
}

function assertPathInside(packageRoot: string, candidate: string): void {
  const relativePath = relative(packageRoot, candidate)
  if (relativePath === '' || (!relativePath.startsWith('..') && !isAbsolute(relativePath))) return
  throw new Error('runtime launcher executable must remain inside its npm package')
}

async function resolveBundledRuntime(
  ctx: Context,
  signal?: AbortSignal,
): Promise<ResolvedRuntime> {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    throw new Error(`semgrep-sast: bundled runtime does not support ${process.platform}-${process.arch}`)
  }

  let manifestUrl: string
  try {
    manifestUrl = import.meta.resolve(WIN32_X64_RUNTIME_MANIFEST)
  } catch (cause) {
    throw new Error(
      'semgrep-sast: bundled win32-x64 runtime package is not installed',
      { cause },
    )
  }

  const manifestPath = fileURLToPath(manifestUrl)
  const packageRoot = dirname(manifestPath)
  let rawManifest: unknown
  try {
    rawManifest = JSON.parse(await readFile(manifestPath, 'utf8')) as unknown
  } catch (cause) {
    throw new Error(`semgrep-sast: failed to read runtime manifest at ${manifestPath}`, { cause })
  }
  const manifest = parseRuntimeManifest(rawManifest)
  const executableCandidate = resolve(packageRoot, manifest.launcher.executable)
  assertPathInside(packageRoot, executableCandidate)
  const executable = await ctx.subprocess.resolveExecutable(executableCandidate, undefined, signal)

  return {
    mode: 'bundled',
    version: manifest.semgrepVersion,
    executable,
    arguments: [...manifest.launcher.arguments],
    environment: { ...manifest.environment },
  }
}

/** Resolve either the managed package runtime or an explicitly configured system executable. */
export async function resolveRuntime(
  ctx: Context,
  config: ResolvedConfig,
  signal?: AbortSignal,
): Promise<ResolvedRuntime> {
  if (config.runtimeMode === 'bundled') return resolveBundledRuntime(ctx, signal)
  if (config.executable === undefined) {
    throw new Error('semgrep-sast: executable is required when runtimeMode is system')
  }

  return {
    mode: 'system',
    version: 'unknown',
    executable: await ctx.subprocess.resolveExecutable(config.executable, undefined, signal),
    arguments: [],
    environment: {},
  }
}

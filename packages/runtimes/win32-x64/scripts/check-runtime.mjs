import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const manifest = JSON.parse(readFileSync(resolve(packageRoot, 'runtime-manifest.json'), 'utf8'))
// A checkout may still contain an ignored payload from the previous release.
// Refuse to package it with a manifest claiming the corrected runtime version.
const result = spawnSync(resolve(packageRoot, manifest.launcher.executable), [
  '-c', 'import importlib.metadata; print(importlib.metadata.version("semgrep"))',
], {
  env: { ...process.env, ...manifest.environment },
  encoding: 'utf8',
  timeout: 30_000,
  windowsHide: true,
})
if (result.error || result.status !== 0 || result.stdout.trim() !== manifest.semgrepVersion) {
  throw new Error(`Runtime payload must contain Semgrep ${manifest.semgrepVersion}; assemble it before packing.`,
    { cause: result.error ?? new Error(result.stderr || result.stdout) })
}
console.log(`Verified runtime payload: Semgrep ${manifest.semgrepVersion}`)

// Development only: refresh the three pure/core modules from a DSH source checkout.
import { readFile, writeFile, copyFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { stripTypeScriptTypes } from 'node:module'

const sourceRoot = resolve(process.argv[2] ?? '../dsh-semgrep-sast')
const pluginRoot = fileURLToPath(new URL('../', import.meta.url))
for (const name of ['parser', 'agent-result', 'source-context']) {
  let source = await readFile(resolve(sourceRoot, `packages/bundle/src/${name}.ts`), 'utf8')
  if (name === 'agent-result') {
    source = source.replace(/import \{[\s\S]*?from '@aaub-software\/dsh-sast-contract'\r?\n/, '')
      .replace('schemaVersion: SAST_SCHEMA_VERSION', 'schemaVersion: "ssc-sast/v1"')
  }
  await writeFile(resolve(pluginRoot, `lib/${name}.js`),
    '// Adapted from dsh-semgrep-sast 0.3.0 (MIT); see scripts/sync-core.mjs.\n'
    + stripTypeScriptTypes(source, { mode: 'transform' }).trim() + '\n')
}
await copyFile(resolve(sourceRoot, 'packages/bundle/rules/cwe-audit.json'), resolve(pluginRoot, 'rules/cwe-audit.json'))

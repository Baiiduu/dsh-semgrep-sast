/**
 * Cordis entry point for the DeepSeek Harness Semgrep SAST bundle.
 * @module @aaub-software/dsh-semgrep-sast
 */

import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-subprocess'
import type {} from '@deepseek-ai/dsh-tools'
import { resolveConfig, type Config as PluginConfig } from './config.js'
import { resolveRuntime } from './runtime.js'
import { createSemgrepScanTool } from './tool.js'

export { Config } from './config.js'
export type { ResolvedConfig } from './config.js'
export type {
  RuntimeMode,
  SemgrepDiagnostic,
  SemgrepEngine,
  SemgrepFinding,
  SemgrepScanInput,
  SemgrepScanResult,
} from './types.js'

/** Cordis plugin name used in diagnostics. */
export const name = 'semgrep-sast'

/** Harness services required by runtime resolution and scan execution. */
export const inject = ['tools', 'subprocess', 'sandbox', 'sandboxPolicy']

/** Resolve the configured runtime and register the model-facing Semgrep tool. */
export async function apply(ctx: Context, config: PluginConfig = {}): Promise<void> {
  const resolvedConfig = resolveConfig(config)
  const runtime = await resolveRuntime(ctx, resolvedConfig)
  ctx.tools.register(createSemgrepScanTool(
    ctx,
    resolvedConfig,
    runtime,
    resolvedConfig.defaultRuleset,
  ))
}

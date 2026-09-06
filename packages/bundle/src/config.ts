import z from '@deepseek-ai/schemastery'
import type { RuntimeMode } from './types.js'

export const DEFAULT_TIMEOUT_MS = 300_000
export const DEFAULT_MAX_FINDINGS = 200
export const DEFAULT_RULESET = 'p/default' as const

/** User-facing configuration accepted by the Cordis plugin. */
export interface Config {
  runtimeMode?: RuntimeMode
  defaultRuleset?: typeof DEFAULT_RULESET
  timeoutMs?: number
  maxFindings?: number
  executable?: string
}

/** Fully resolved configuration used by the scanner implementation. */
export interface ResolvedConfig {
  runtimeMode: RuntimeMode
  defaultRuleset: typeof DEFAULT_RULESET
  timeoutMs: number
  maxFindings: number
  executable?: string
}

/** Runtime schema consumed by the Cordis loader. */
export const Config: z<Config> = z.object({
  runtimeMode: z.union(['bundled', 'system'] as const).default('bundled'),
  defaultRuleset: z.const(DEFAULT_RULESET).default(DEFAULT_RULESET),
  timeoutMs: z.number().step(1).min(1).max(3_600_000).default(DEFAULT_TIMEOUT_MS),
  maxFindings: z.number().step(1).min(1).max(10_000).default(DEFAULT_MAX_FINDINGS),
  executable: z.string(),
})

/** Apply defaults and reject ambiguous runtime configuration. */
export function resolveConfig(config: Config = {}): ResolvedConfig {
  const runtimeMode = config.runtimeMode ?? 'bundled'
  const executable = config.executable?.trim()

  if (runtimeMode === 'system' && (executable === undefined || executable.length === 0)) {
    throw new Error('semgrep-sast: executable is required when runtimeMode is system')
  }
  if (runtimeMode === 'bundled' && executable !== undefined) {
    throw new Error('semgrep-sast: executable is not allowed when runtimeMode is bundled')
  }

  return {
    runtimeMode,
    defaultRuleset: config.defaultRuleset ?? DEFAULT_RULESET,
    timeoutMs: config.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxFindings: config.maxFindings ?? DEFAULT_MAX_FINDINGS,
    ...(executable !== undefined ? { executable } : {}),
  }
}

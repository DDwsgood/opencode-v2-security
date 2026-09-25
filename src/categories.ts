/** Canonical bypass categories shared by /bypass, escalation, classifiers,
 * and both LLM reviewers. Keep this file dependency-free so config.ts and the
 * reviewer can both import it without a cycle. */
export const STATIC_BYPASS_CATEGORIES = [
  "filesystem",
  "host",
  "privilege",
  "secret",
  "network",
  "remote",
  "indirection",
] as const

export const LAYER_BYPASS_CATEGORIES = ["dynamic", "sandbox", "slow"] as const

export const BYPASS_CATEGORIES = [
  ...STATIC_BYPASS_CATEGORIES,
  ...LAYER_BYPASS_CATEGORIES,
] as const

export type BypassCategory = (typeof BYPASS_CATEGORIES)[number]
export type StaticBypassCategory = (typeof STATIC_BYPASS_CATEGORIES)[number]

/** Compatibility spellings accepted at user/config boundaries only. Internal
 * state always stores the expanded canonical names. */
export const LEGACY_CATEGORY_ALIASES: Readonly<Record<string, readonly BypassCategory[]>> = {
  fs: ["filesystem"],
  os: ["host", "privilege", "indirection"],
  web: ["network", "remote"],
}

export function expandBypassCategoryToken(raw: string): readonly BypassCategory[] | undefined {
  const token = raw.trim().toLowerCase()
  const direct = BYPASS_CATEGORIES.find((category) => category === token)
  if (direct) return [direct]
  return LEGACY_CATEGORY_ALIASES[token]
}

export function isStaticBypassCategory(value: string): value is StaticBypassCategory {
  return (STATIC_BYPASS_CATEGORIES as readonly string[]).includes(value)
}

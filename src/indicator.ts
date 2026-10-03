// Pure badge-segment logic for the permission/bypass indicator, split out of
// tui.tsx so it can be unit-tested without the solid-js / @opentui runtime.

/** Per-session state backing the persistent indicator. */
export type IndicatorState = {
  /** Effective triple rendered unix-style ("rwx", "r-x", "--x"). */
  permission: string
  /** Bypass categories currently in effect (temporary + permanent). */
  active: string[]
  /** Whether the last authoritative snapshot applied. RPC events carry
   *  complete per-field data but are partial overall and ephemeral — only a
   *  full `status` reply marks the entry synced. False (or absent on entries
   *  written by older plugin generations) renders an honest "unknown" badge
   *  instead of a possibly stale claim like [YOLO ON]. */
  synced?: boolean
}

/** Structural slice of the reactive theme the indicator reads (kept loose so
 * the entrypoint stays free of runtime imports beyond solid-js). */
export type IndicatorTheme = {
  readonly text: {
    readonly subdued: string
    readonly feedback: {
      readonly success: { readonly subdued: string }
      readonly warning: { readonly default: string }
      /** Optional danger/error tokens — the ALL-OFF badge prefers the first
       * present, falling back to warning.default. */
      readonly danger?: { readonly default?: string; readonly subdued?: string }
      readonly error?: { readonly default?: string; readonly subdued?: string }
    }
  }
}

export type Segment = { readonly text: string; readonly fg: string }

/** The `all` kill switch rides the same `active` list as a literal "all"
 * entry (RPC schema is closed, so no separate flag field). */
export function allIsOff(active: readonly string[]): boolean {
  return active.includes("ALL")
}

export function dangerColor(theme: IndicatorTheme): string {
  return (
    theme.text.feedback.danger?.default ??
    theme.text.feedback.danger?.subdued ??
    theme.text.feedback.error?.default ??
    theme.text.feedback.error?.subdued ??
    theme.text.feedback.warning.default
  )
}

/** Badge label for the r/w bits. Both bits matter: a "-w-" ceiling is
 * [Write Only], not "Read + Write", and a ceiling without `r` must never
 * render as "Read Only". Combos outside the three named modes fall back to
 * the raw unix-style triple so the indicator never lies. */
export function permissionLabel(permission: string): string {
  const r = permission.includes("r")
  const w = permission.includes("w")
  if (r && w) return "Read + Write"
  if (r) return "Read Only"
  if (w) return "Write Only"
  return permission || "none"
}

/** [Read Only] light green (success.subdued) · [Read + Write,
 * Bypassing Category(ies):...] orange (warning.default) · [YOLO ON, Bypassing
 * all permissions] danger/error · plain [Read + Write] subdued.
 * With the kill switch armed the danger badge REPLACES the bypass label —
 * individual categories are moot while all enforcement is off. */
export function segmentsFor(state: IndicatorState, theme: IndicatorTheme): Segment[] {
  // A badge that cannot prove freshness must not make a confident claim —
  // e.g. still showing [YOLO ON] after the bypass actually expired is worse
  // than admitting the state is unknown until the next snapshot lands.
  if (state.synced !== true) {
    return [{ text: "[Security state unknown]", fg: theme.text.subdued }]
  }
  const writable = state.permission.includes("w")
  if (allIsOff(state.active)) {
    // While the kill switch is armed the badge is just [YOLO ON, Bypassing all
    // permissions] — category and permission detail is moot while every
    // enforcement layer is off.
    return [{ text: "[YOLO ON, Bypassing all permissions]", fg: dangerColor(theme) }]
  }
  if (state.active.length > 0) {
    return [
      {
        text: `[${permissionLabel(state.permission)}, Bypassing Category(ies): ${state.active.join(",")}]`,
        fg: theme.text.feedback.warning.default,
      },
    ]
  }
  if (!writable) {
    return [{ text: `[${permissionLabel(state.permission)}]`, fg: theme.text.feedback.success.subdued }]
  }
  // A "-w-" ceiling is write-only, not read+write — render the real bits.
  return [{ text: `[${permissionLabel(state.permission)}]`, fg: theme.text.subdued }]
}

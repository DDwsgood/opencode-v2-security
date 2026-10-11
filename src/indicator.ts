// Pure badge-segment logic for the permission/bypass indicator, split out of
// tui.tsx so it can be unit-tested without the solid-js / @opentui runtime.
//
// The user-facing surface is exactly three modes (see permissions.ts):
// [Read only], [Auto mode, bypassing: ...] and [Bypass mode]. The raw r/w/x
// triple is never rendered — only its write bit is consulted, to derive the
// mode against older servers that predate the explicit `mode` field.
import { securityModeFor, securityModeLabel, type SecurityMode } from "./permissions"

/** Per-session state backing the persistent indicator. */
export type IndicatorState = {
  /** Effective triple rendered unix-style ("rwx", "r-x", "--x"). Kept only to
   *  derive the mode on older servers; never displayed. */
  permission: string
  /** Bypass categories currently in effect (temporary + permanent). */
  active: string[]
  /** Explicit user-visible mode from the server; absent on older servers, in
   *  which case it is derived from `permission` + `active`. */
  mode?: SecurityMode
  /** Whether any verbatim custom bypass scope is armed. Only a boolean is
   *  kept: the raw scope text can be sensitive and is never displayed. */
  custom?: boolean
  /** Whether the last authoritative snapshot applied. RPC events carry
   *  complete per-field data but are partial overall and ephemeral — only a
   *  full `status` reply marks the entry synced. False (or absent on entries
   *  written by older plugin generations) renders an honest "unknown" badge
   *  instead of a possibly stale claim like [Bypass mode]. */
  synced?: boolean
}

/** Structural slice of the reactive theme the indicator reads (kept loose so
 *  the entrypoint stays free of runtime imports beyond solid-js). */
export type IndicatorTheme = {
  readonly text: {
    readonly subdued: string
    readonly feedback: {
      readonly success: { readonly subdued: string }
      readonly warning: { readonly default: string }
      /** Optional danger/error tokens — the Bypass badge prefers the first
       * present, falling back to warning.default. */
      readonly danger?: { readonly default?: string; readonly subdued?: string }
      readonly error?: { readonly default?: string; readonly subdued?: string }
    }
  }
}

export type Segment = { readonly text: string; readonly fg: string }

/** The `all` kill switch rides the same `active` list as a literal "ALL"
 * entry (RPC schema is closed, so no separate flag field). */
export function allIsOff(active: readonly string[]): boolean {
  return active.includes("ALL") || active.includes("all")
}

/** Categories that drive the Auto label: the ALL kill switch is a mode, not a
 * category, so it is excluded. */
function bypassingCategories(active: readonly string[]): string[] {
  return active.filter((category) => category !== "ALL" && category !== "all")
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

/** Effective display mode: the server's explicit `mode` when present, else
 *  derived from the legacy fields exactly like `securityModeFor` — an
 *  inherited read-only ceiling wins, then the ALL kill switch means Bypass,
 *  otherwise Auto. */
export function modeForState(state: IndicatorState): SecurityMode {
  if (state.mode) return state.mode
  return securityModeFor(
    { r: true, w: state.permission.includes("w"), x: true },
    allIsOff(state.active),
  )
}

/** The single three-mode composer badge. [Read only] light green,
 *  [Bypass mode] danger/error, [Auto mode, bypassing: ...] orange while any
 *  category/custom scope is armed and subdued otherwise. Unsynced state
 *  renders an honest unknown label rather than a possibly stale claim. */
export function segmentsFor(state: IndicatorState, theme: IndicatorTheme): Segment[] {
  // A badge that cannot prove freshness must not make a confident claim —
  // e.g. still showing [Bypass mode] after the bypass actually expired is
  // worse than admitting the state is unknown until the next snapshot lands.
  if (state.synced !== true) {
    return [{ text: "[Security state unknown]", fg: theme.text.subdued }]
  }
  const mode = modeForState(state)
  const label = securityModeLabel(mode, state.active, state.custom === true)
  const fg =
    mode === "readonly"
      ? theme.text.feedback.success.subdued
      : mode === "bypass"
        ? dangerColor(theme)
        : state.custom === true || bypassingCategories(state.active).length > 0
          ? theme.text.feedback.warning.default
          : theme.text.subdued
  return [{ text: label, fg }]
}

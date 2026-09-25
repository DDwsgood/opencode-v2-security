// Session read/write permission layer (tighten-only ceiling).
//
// Model: every session carries a baseline {r,w,x} triple; the effective
// permission is the bitwise intersection along the session's ancestor chain.
// Entries only ever tighten a session: `tightenPerm` clamps the requested
// triple to the current effective set (no widening), and spawned subagents
// start at min(parentEffective, declared). `/perm` is the user-side control
// that may reset the baseline arbitrarily (ancestors still cap the result).
//
// MVP semantics (user decision 2026-09-15): only r and w are enforceable.
// The x bit still exists in the internal triple (PERM_FULL keeps it set so
// baselines stay forward-compatible), but no action maps to it and every
// input that would grant it is rejected outright rather than silently
// stripped — chmod-consistent octal (1=x, 2=w, 4=r) means 1, 3, 5, 7 error.
//
// The layer is deliberately orthogonal to BypassClassifier: bypasses relax
// rules, permissions hard-deny whole capability classes, and any DENY wins.

export type Perm = { r: boolean; w: boolean; x: boolean }

export const PERM_FULL: Perm = { r: true, w: true, x: true }
export const PERM_NONE: Perm = { r: false, w: false, x: false }

const PERM_ALIAS: Record<string, Perm> = {
  r: { r: true, w: false, x: false },
  ro: { r: true, w: false, x: false },
  read: { r: true, w: false, x: false },
  "r--": { r: true, w: false, x: false },
  w: { r: false, w: true, x: false },
  "-w-": { r: false, w: true, x: false },
  rw: { r: true, w: true, x: false },
  "rw-": { r: true, w: true, x: false },
  none: PERM_NONE,
  off: PERM_NONE,
  "0": PERM_NONE,
}

/** Accepts `r`/`ro`/`read`/`r--`/`4`, `w`/`-w-`/`2`, `rw`/`rw-`/`6`,
 * `none`/`off`/`0`, `-`-padded unix triples and letters in any order
 * (`wr` = `rw`). Anything that would grant the x bit — octal 1/3/5/7,
 * `x`/`rx`/`wx`/`rwx`, `--x`/`r-x`/`-wx` — is rejected: x is not part of
 * this MVP, and silently stripping it would hide the caller's intent. */
export function parsePerm(raw: string): Perm | undefined {
  const value = raw.trim().toLowerCase()
  if (!value) return undefined
  const aliased = PERM_ALIAS[value]
  if (aliased) return { ...aliased }
  if (/^[0-7]$/.test(value)) {
    const bits = Number.parseInt(value, 8)
    if (bits & 1) return undefined // x-bearing octal (1, 3, 5, 7): rejected
    return { r: (bits & 4) !== 0, w: (bits & 2) !== 0, x: false }
  }
  if (/^[rwx-]{1,3}$/.test(value) && /[rwx]/.test(value)) {
    if (value.includes("x")) return undefined // x-bearing letters: rejected
    if (value.includes("-")) {
      // Unix-triple shape (`r--`, `-w-`, `rw-`): positions must match r/w/x order.
      if (value.length === 3) {
        return { r: value[0] === "r", w: value[1] === "w", x: false }
      }
      return undefined
    }
    return { r: value.includes("r"), w: value.includes("w"), x: false }
  }
  return undefined
}

export function permBits(perm: Perm): number {
  return (perm.r ? 4 : 0) + (perm.w ? 2 : 0) + (perm.x ? 1 : 0)
}

/** Unix-style label with the x bit always shown SET: execution is always
 *  available in this MVP (x exists in the triple for forward-compat but no
 *  action maps to it), so hiding it as "-" misleads the user. Displays:
 *  r-x (ro), rwx (rw), --x (none). x remains non-togglable on input. */
export function permLabel(perm: Perm): string {
  return `${perm.r ? "r" : "-"}${perm.w ? "w" : "-"}x`
}

export function permIntersect(a: Perm, b: Perm): Perm {
  return { r: a.r && b.r, w: a.w && b.w, x: a.x && b.x }
}

export function permSubset(inner: Perm, outer: Perm): boolean {
  return (!inner.r || outer.r) && (!inner.w || outer.w) && (!inner.x || outer.x)
}

export function permEqual(a: Perm, b: Perm): boolean {
  return a.r === b.r && a.w === b.w && a.x === b.x
}

/**
 * Tighten-only write: returns the new baseline iff `next` is a subset of the
 * session's current effective permission. Widening through this path is never
 * allowed — only the user-side `/perm` may relax a baseline.
 */
export function tightenPerm(currentEffective: Perm, next: Perm): Perm | undefined {
  return permSubset(next, currentEffective) ? next : undefined
}

/**
 * Maps a permission action (packages/core permission.assert `action` field)
 * to the r/w bit it requires. Actions absent from the map are handled by
 * `fallbackPermBit`, not by this lookup.
 * `edit` covers the edit/write/patch tools (verified: all three assert
 * `action: "edit"`); `skill`/`question` are read-class — RO sessions keep
 * reading skill docs and asking the user. `subagent` is read-class:
 * creating a child does not itself widen authority, and the child inherits the
 * parent's effective ceiling. `shell` is deliberately absent:
 * read-only shell must stay usable under RO (its write-shaped segments are
 * denied by the classifier's permScope fallback, and the kernel sandbox is
 * the eventual hard write boundary).
 */
export const DEFAULT_ACTION_PERM: Record<string, keyof Perm> = {
  edit: "w",
  read: "r",
  external_directory: "r",
  grep: "r",
  glob: "r",
  webfetch: "r",
  websearch: "r",
  skill: "r",
  question: "r",
  subagent: "r",
}

/** Which permission bit an action needs; `undefined` = defer to
 * `fallbackPermBit`. When `map` is given it is authoritative for the actions
 * it contains (a resolved map may deliberately delete actions, e.g.
 * webIsRead=false removes webfetch/websearch — those land in the caller's
 * `ungatedActions` set so the fallback honors the exemption). */
export function requiredPermBit(action: string, map?: Record<string, keyof Perm>): keyof Perm | undefined {
  if (map) return map[action]
  return DEFAULT_ACTION_PERM[action]
}

/** Fallback for actions absent from the resolved map. MCP tools assert
 * composed `${server}_${tool}` action names (core/tool/mcp.ts `name()`), so
 * they cannot be enumerated in advance; every unmapped action therefore
 * requires the write bit — read-only sessions deny the whole MCP class,
 * unrestricted sessions are unaffected. Two exemptions: `shell` (the
 * classifier's permScope already denies write-shaped segments when `w` is
 * missing, and RO must keep read-only shell usable) and actions the user
 * deliberately ungated (`webIsRead: false`). */
export function fallbackPermBit(
  action: string,
  opts: { ungated?: ReadonlySet<string> } = {},
): keyof Perm | undefined {
  if (action === "shell") return undefined
  if (opts.ungated?.has(action)) return undefined
  return "w"
}

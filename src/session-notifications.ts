// session-notifications.ts — no-wake session state notices for /perm and /bypass.
//
// Why this exists: the previous mechanism appended `ctx.session.synthetic`
// reminders (a durable user-role inbox item) on permission/bypass transitions.
// A synthetic admission is a session INPUT — on hosts where admission promotes
// pending work it can start a Runner for an idle session, and it permanently
// lands in the transcript. State notices are not inputs: they describe the
// CURRENT state and only matter when the model is about to be called anyway.
//
// Verified no-wake mechanism (~/src/opencode2, branch v2):
//   - packages/plugin/src/effect/session.ts:21  SessionContext { system, messages, ... }
//   - packages/plugin/src/effect/session.ts:67  SessionHooks["context"]
//   - packages/plugin/src/effect/session.ts:73  SessionDomain.hook = ModelHooks<SessionHooks>
//   - packages/core/src/session/model-request.ts:301-333  the context hook is invoked
//     while the next model request is being built (`hooks.trigger("session","context")`)
//     and `context.system` ships verbatim as the request's system parts.
//   - Host precedent for mutating it in place: packages/core/src/plugin/system-prompt.ts:36.
//   - packages/ai/src/schema/messages.ts:21  SystemPart = {type:"text", text, cache?, metadata?}
//
// So: mutate `event.system` inside `ctx.session.hook("context", ...)`. No
// session.synthetic/prompt/generate/interrupt/wait/resume call, no inbox
// admission, no wake — an idle session stays idle, and the very next real
// model call (whenever the user causes one) already sees the latest state.
//
// Ownership contract: callers (index.ts) decide *when* state changed —
// transitions, descendant-inherited moves, lease expiry, bypass restore —
// and pass the exact reminder text they would previously have synthetic'd.
// This module never invents text and never reads model output: state only
// enters through setPerm/setBypass, i.e. plugin code paths. Passing
// `undefined` clears that notice — callers use it to suppress the default/
// baseline state so no noise is injected.

import { Effect } from "effect"

/** Marker carried on injected SystemPart.metadata so a rebuild/second hook
 *  pass updates the same part instead of stacking duplicates. */
const MARKER = "opencode-v2-security-session-state"

type SystemPartLike = {
  type: "text"
  text: string
  metadata?: Record<string, unknown>
}

/** Minimal structural shape of the hook event we touch (verified against
 *  SessionContext; extra fields are ignored). */
export interface SessionContextEvent {
  readonly sessionID: string
  system: Array<SystemPartLike>
}

interface SessionState {
  perm?: string
  bypass?: string
}

export interface SessionStateNotices {
  /** Latest /perm notice text for the session, or undefined to clear. */
  setPerm(sessionID: string, text: string | undefined): void
  /** Latest /bypass notice text for the session, or undefined to clear. */
  setBypass(sessionID: string, text: string | undefined): void
  /** Drop all notices (e.g. session.deleted). */
  clear(sessionID: string): void
  /** Combined notice text for the session as it would be injected now. */
  snapshot(sessionID: string): string | undefined
}

export function createSessionStateNotices(): SessionStateNotices {
  const states = new Map<string, SessionState>()

  const set =
    (key: keyof SessionState) =>
    (sessionID: string, text: string | undefined): void => {
      const cur = states.get(sessionID) ?? {}
      if (cur[key] === text) return
      const next = { ...cur, [key]: text }
      if (!next.perm && !next.bypass) states.delete(sessionID)
      else states.set(sessionID, next)
    }

  return {
    setPerm: set("perm"),
    setBypass: set("bypass"),
    clear(sessionID) {
      states.delete(sessionID)
    },
    snapshot(sessionID) {
      const s = states.get(sessionID)
      if (!s) return undefined
      const parts = [s.perm, s.bypass].filter(
        (t): t is string => typeof t === "string" && t.length > 0,
      )
      if (parts.length === 0) return undefined
      return `opencode-v2-security: ${parts.join("\n")}`
    },
  }
}

/** Apply the session's current notices to a context-hook event. Exported for
 *  tests; `attachSessionContextHook` wires it to the host hook. */
export function applyNoticesToContext(
  notices: SessionStateNotices,
  event: SessionContextEvent,
): void {
  const text = notices.snapshot(event.sessionID)
  const existing = event.system.find(
    (p) => p.metadata && p.metadata[MARKER] === true,
  )
  if (text === undefined) {
    if (existing) event.system.splice(event.system.indexOf(existing), 1)
    return
  }
  if (existing) {
    existing.text = text
    return
  }
  // Trailing system part: the cached prefix stays intact and the latest
  // state reads as current, not as a stale earlier instruction.
  event.system.push({
    type: "text",
    text,
    metadata: { [MARKER]: true, source: "opencode-v2-security" },
  })
}

/** Structural minimum of the plugin ctx slice this needs. `session.hook` is
 *  optional so older hosts still load: when absent the function reports false
 *  and callers keep whatever user-facing channel they already have. */
export type SessionContextHookHost = {
  session: {
    hook?: (
      name: "context",
      callback: (event: SessionContextEvent) => Effect.Effect<void>,
    ) => Effect.Effect<unknown>
  }
}

/** Register the context hook. Returns Effect<boolean>: true when the hook was
 *  registered. Registers NOTHING else — no inbox admission, no resume, no
 *  wake; the callback only runs while the host is already building a model
 *  request. */
export function attachSessionContextHook(
  ctx: SessionContextHookHost,
  notices: SessionStateNotices,
): Effect.Effect<boolean> {
  if (typeof ctx.session.hook !== "function") return Effect.succeed(false)
  return ctx.session
    .hook("context", (event) =>
      Effect.sync(() => applyNoticesToContext(notices, event)),
    )
    .pipe(Effect.as(true))
}

// Permission transitions are append-only user-role notifications. Never edit
// the model's system prompt, existing messages, or any historical prefix.
//
// A state change only records the latest text. It is admitted to the
// transcript while the host prepares the next real user prompt (the
// session "prompt" hook), right before that prompt's own admission, so both
// are promoted together into one model request. Admitting at the moment of
// the change would leave a pending steer item in the inbox: a runner that is
// finishing its last step treats it as new input and starts another model
// request (and a later wake would do the same for an idle session).
// While a run is in progress, the latest text also rides the next completed
// tool result, which that run's next model step reads anyway.

interface SessionState {
  perm?: string
  bypass?: string
}

/** Shared notice snapshot store: several plugin instances run in one server
 *  process, and a session's notice must exist once regardless of which
 *  instance recorded the change or which instance handles the delivery
 *  channel. `claims` holds the text an instance is publishing right now, so
 *  a second instance never publishes the same notice twice. */
export interface NoticeStore {
  states: Map<string, SessionState>
  delivered: Map<string, string>
  claims: Map<string, { token: symbol; text: string; done: Promise<void> }>
}

export function createNoticeStore(): NoticeStore {
  return { states: new Map(), delivered: new Map(), claims: new Map() }
}

export interface SessionStateNotification {
  sessionID: string
  text: string
  description: string
  metadata: Record<string, unknown>
  resume: false
  delivery: "steer"
}

export interface SessionStateNotices {
  setPerm(sessionID: string, text: string | undefined): void
  setBypass(sessionID: string, text: string | undefined): void
  clear(sessionID: string): void
  snapshot(sessionID: string): string | undefined
  /** Admit the latest undelivered notice ahead of a user prompt that is
   *  being prepared. A queued prompt is skipped: queued inbox items are
   *  promoted one per turn, so a notice queued before it would get a model
   *  request of its own. The notice then rides the next steering prompt. */
  deliverWithPrompt(sessionID: string, delivery: string | undefined): Promise<void>
  /** Take the latest undelivered notice for a tool result that the running
   *  session's next model step will read anyway. Only exists mid-run, so it
   *  never starts a request; the text then counts as delivered. */
  takeForToolResult(sessionID: string): string | undefined
  /** Wait for in-progress admissions. */
  flush(): Promise<void>
}

export function createSessionStateNotices(
  publish?: (notice: SessionStateNotification) => Promise<unknown>,
  store: NoticeStore = createNoticeStore(),
): SessionStateNotices {
  const { states, delivered, claims } = store
  let pending = Promise.resolve()

  const snapshot = (sessionID: string): string | undefined => {
    const state = states.get(sessionID)
    if (!state) return undefined
    const parts = [state.perm, state.bypass].filter(
      (text): text is string => typeof text === "string" && text.length > 0,
    )
    return parts.length ? `opencode-v2-security: ${parts.join("\n")}` : undefined
  }

  const set = (key: keyof SessionState) => (sessionID: string, text: string | undefined) => {
    const current = states.get(sessionID) ?? {}
    if (current[key] === text) return
    const next = { ...current, [key]: text }
    if (!next.perm && !next.bypass) states.delete(sessionID)
    else states.set(sessionID, next)
  }

  return {
    setPerm: set("perm"),
    setBypass: set("bypass"),
    snapshot,
    clear(sessionID) {
      states.delete(sessionID)
      delivered.delete(sessionID)
      claims.delete(sessionID)
    },
    deliverWithPrompt(sessionID, delivery) {
      if (!publish || (delivery !== undefined && delivery !== "steer")) return Promise.resolve()
      const run = pending.then(async () => {
        // All location instances serialize on this session's shared claim.
        // Read the snapshot only after the preceding publisher finishes.
        while (claims.has(sessionID)) await claims.get(sessionID)!.done
        const text = snapshot(sessionID)
        if (!text || delivered.get(sessionID) === text) return
        let release!: () => void
        const claim = { token: Symbol("notice-publisher"), text,
          done: new Promise<void>((resolve) => { release = resolve }) }
        claims.set(sessionID, claim)
        try {
          await publish({
            sessionID,
            text,
            description: "Security mode changed",
            metadata: { source: "opencode-v2-security", securityStateNotice: true },
            resume: false,
            delivery: "steer",
          })
          if (claims.get(sessionID)?.token === claim.token) delivered.set(sessionID, text)
        } finally {
          if (claims.get(sessionID)?.token === claim.token) claims.delete(sessionID)
          release()
        }
      }).catch(() => {
        // No error bodies: admission failures may contain unrelated host data.
        console.warn("[opencode-v2-security] security state notification was not delivered (enforcement unchanged)")
      })
      pending = run
      return run
    },
    takeForToolResult(sessionID) {
      const text = snapshot(sessionID)
      if (!text || delivered.get(sessionID) === text) return undefined
      // Another instance is admitting this exact text right now: the notice
      // is on its way into the transcript through that channel. Do NOT mark
      // it delivered yet — the publisher marks it on success; if that
      // admission fails, its claim clears and the next channel retries.
      if (claims.has(sessionID)) return undefined
      delivered.set(sessionID, text)
      return text
    },
    async flush() {
      for (;;) {
        const current = pending
        await current
        if (pending === current) return
      }
    },
  }
}

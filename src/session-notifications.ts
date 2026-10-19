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
// During a run, the next existing model request receives a separate user-role
// notice. This does not admit inbox work or claim durable delivery.

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
  modelSnapshots: Map<string, string>
  backgroundBlocks: Map<string, string[]>
  claims: Map<string, { token: symbol; text: string; done: Promise<void> }>
}

export function createNoticeStore(): NoticeStore {
  return { states: new Map(), delivered: new Map(), modelSnapshots: new Map(), backgroundBlocks: new Map(), claims: new Map() }
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
  /** Repeat a transient user notice until a real prompt durably admits it. */
  forModelContext(sessionID: string): string | undefined
  recordBackgroundBlock(sessionID: string, text: string): void
  /** Transient context copies do not claim delivery; tool results/prompts do. */
  backgroundForModelContext(sessionID: string): string | undefined
  takeBackgroundForToolResult(sessionID: string): string | undefined
  /** Wait for in-progress admissions. */
  flush(): Promise<void>
}

export function createSessionStateNotices(
  publish?: (notice: SessionStateNotification) => Promise<unknown>,
  store: NoticeStore = createNoticeStore(),
): SessionStateNotices {
  // Plugin instances can reuse a store created before this field existed.
  store.modelSnapshots ??= new Map()
  store.backgroundBlocks ??= new Map()
  const { states, delivered, modelSnapshots, backgroundBlocks, claims } = store
  let pending = Promise.resolve()

  const snapshot = (sessionID: string): string | undefined => {
    const state = states.get(sessionID)
    if (!state) return undefined
    const parts = [state.perm, state.bypass].filter(
      (text): text is string => typeof text === "string" && text.length > 0,
    )
    return parts.length ? `[opencode-v2-security] ${parts.join("\n")}` : undefined
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
      modelSnapshots.delete(sessionID)
      backgroundBlocks.delete(sessionID)
      claims.delete(sessionID)
    },
    deliverWithPrompt(sessionID, delivery) {
      if (!publish || (delivery !== undefined && delivery !== "steer")) return Promise.resolve()
      const run = pending.then(async () => {
        // All location instances serialize on this session's shared claim.
        // Read the snapshot only after the preceding publisher finishes.
        while (claims.has(sessionID)) await claims.get(sessionID)!.done
        const stateText = snapshot(sessionID)
        const statePending = stateText !== undefined && delivered.get(sessionID) !== stateText
        const queued = backgroundBlocks.get(sessionID)
        const background = queued ? [...queued] : []
        if (!statePending && background.length === 0) return
        const text = [statePending ? stateText : undefined, ...background]
          .filter((part): part is string => typeof part === "string").join("\n\n")
        let release!: () => void
        const claim = { token: Symbol("notice-publisher"), text,
          done: new Promise<void>((resolve) => { release = resolve }) }
        claims.set(sessionID, claim)
        try {
          await publish({
            sessionID,
            text,
            description: background.length ? "Background command stopped" : "Security mode changed",
            metadata: {
              source: "opencode-v2-security",
              ...(statePending ? { securityStateNotice: true } : {}),
              ...(background.length ? { backgroundBlockNotice: true } : {}),
            },
            resume: false,
            delivery: "steer",
          })
          if (claims.get(sessionID)?.token === claim.token) {
            if (statePending) {
              delivered.set(sessionID, stateText!)
              modelSnapshots.delete(sessionID)
            }
            const current = backgroundBlocks.get(sessionID)
            if (current && current === queued) {
              current.splice(0, background.length)
              if (current.length === 0) backgroundBlocks.delete(sessionID)
            }
          }
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
    forModelContext(sessionID) {
      const text = snapshot(sessionID)
      if (!text) return undefined
      const previousModelSnapshot = modelSnapshots.get(sessionID)
      if (delivered.get(sessionID) === text && (previousModelSnapshot === undefined || previousModelSnapshot === text)) return undefined
      // Another instance is admitting this exact text right now: the notice
      // is on its way into the transcript through that channel. Do NOT mark
      // it delivered yet — the publisher marks it on success; if that
      // admission fails, its claim clears and the next channel retries.
      if (claims.has(sessionID)) return undefined
      // A return to the durable mode must correct a different transient mode.
      // This tracks request assembly, not successful or durable delivery.
      modelSnapshots.set(sessionID, text)
      return text
    },
    recordBackgroundBlock(sessionID, text) {
      const queued = backgroundBlocks.get(sessionID) ?? []
      queued.push(text)
      backgroundBlocks.set(sessionID, queued)
    },
    backgroundForModelContext(sessionID) {
      if (claims.has(sessionID)) return undefined
      return backgroundBlocks.get(sessionID)?.join("\n\n")
    },
    takeBackgroundForToolResult(sessionID) {
      if (claims.has(sessionID)) return undefined
      const queued = backgroundBlocks.get(sessionID)
      if (!queued?.length) return undefined
      backgroundBlocks.delete(sessionID)
      return queued.join("\n\n")
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

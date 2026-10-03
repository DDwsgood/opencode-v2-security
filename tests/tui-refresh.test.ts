import { describe, expect, jest, mock, spyOn, test } from "bun:test"
import { StatusRevisions, sessionsToRefresh } from "../src/indicator-refresh"

// The TUI entrypoint is a .tsx compiled by the host at load time; its peers
// (solid-js, @opentui/solid) are runtime-provided and not installed here, so
// the test stubs the module specifiers. The slot's render function is never
// invoked — only setup() wiring runs — so the stubs are inert.
mock.module("solid-js", () => ({
  createEffect: (fn: () => void) => fn(),
  For: () => null,
  Show: () => null,
}))
mock.module("@opentui/solid/jsx-runtime", () => ({
  jsx: () => null,
  jsxs: () => null,
  Fragment: "fragment",
}))
mock.module("@opentui/solid/jsx-dev-runtime", () => ({
  jsxDEV: () => null,
  jsx: () => null,
  jsxs: () => null,
  Fragment: "fragment",
}))

const { default: tuiPlugin } = await import("../src/tui.tsx")

// Ordering rules that keep the indicator from going stale in either
// direction: a status snapshot is authoritative only while it is still the
// newest pull and no live event arrived after it started.

describe("StatusRevisions", () => {
  test("a snapshot applies when nothing newer exists", () => {
    const revisions = new StatusRevisions()
    const ticket = revisions.beginPull("s1")
    expect(revisions.mayApply("s1", ticket)).toBe(true)
  })

  test("an event arriving mid-pull invalidates the in-flight snapshot", () => {
    const revisions = new StatusRevisions()
    const ticket = revisions.beginPull("s1")
    // The server pushed a newer state (e.g. a bypass lease expired) while the
    // status RPC was in flight — the stale reply must not overwrite it.
    revisions.markEvent("s1")
    expect(revisions.mayApply("s1", ticket)).toBe(false)
  })

  test("a pull started after the event applies normally", () => {
    const revisions = new StatusRevisions()
    revisions.markEvent("s1")
    const ticket = revisions.beginPull("s1")
    expect(revisions.mayApply("s1", ticket)).toBe(true)
  })

  test("a newer pull supersedes an older in-flight pull", () => {
    const revisions = new StatusRevisions()
    const first = revisions.beginPull("s1")
    const second = revisions.beginPull("s1")
    expect(revisions.mayApply("s1", first)).toBe(false)
    expect(revisions.mayApply("s1", second)).toBe(true)
  })

  test("revisions are per-session", () => {
    const revisions = new StatusRevisions()
    const ticket = revisions.beginPull("s1")
    revisions.markEvent("s2")
    revisions.beginPull("s2")
    expect(revisions.mayApply("s1", ticket)).toBe(true)
  })

  test("drop() forgets the session so stale tickets cannot revive it", () => {
    const revisions = new StatusRevisions()
    const ticket = revisions.beginPull("s1")
    revisions.drop("s1")
    expect(revisions.mayApply("s1", ticket)).toBe(false)
    // A pull for a re-created session of the same id starts clean, and the
    // pre-drop ticket must stay dead even though the fresh pull reuses the
    // same pull/event counters — the generation distinguishes them.
    const fresh = revisions.beginPull("s1")
    expect(revisions.mayApply("s1", fresh)).toBe(true)
    expect(revisions.mayApply("s1", ticket)).toBe(false)
  })

  test("an event recorded before the pull still allows the pull", () => {
    const revisions = new StatusRevisions()
    revisions.markEvent("s1")
    revisions.markEvent("s1")
    const ticket = revisions.beginPull("s1")
    expect(revisions.mayApply("s1", ticket)).toBe(true)
  })
})

describe("sessionsToRefresh", () => {
  test("descendants and the rest of the family re-pull, the source does not", () => {
    // The server only emits for the mutated session; children that inherit
    // its bypass lease / permission ceiling refresh via snapshot pulls.
    expect(sessionsToRefresh("parent", ["parent", "child-a", "child-b"])).toEqual(["child-a", "child-b"])
  })

  test("source missing from the family list still refreshes the others", () => {
    expect(sessionsToRefresh("parent", ["child-a"])).toEqual(["child-a"])
  })

  test("empty or self-only family yields nothing", () => {
    expect(sessionsToRefresh("s1", [])).toEqual([])
    expect(sessionsToRefresh("s1", ["s1"])).toEqual([])
  })

  test("duplicates in the family list are pulled once", () => {
    expect(sessionsToRefresh("s1", ["s2", "s2", "s1"])).toEqual(["s2"])
  })
})

// ---------------------------------------------------------------------------
// setup()-level wiring tests: a fake Plugin.Context exercises the real
// event/subscription/pull logic without rendering JSX.
// ---------------------------------------------------------------------------

type StatusReply = {
  sessionID: string
  permission: string
  active: string[]
  temporary: string[]
  permanent: string[]
  // Same optional shape as the RPC schema: number = finite lease deadline,
  // null = armed without natural expiry, absent = no live lease.
  expiresAt?: number | null
}

type HarnessStore = Record<string, { permission: string; active: string[]; synced?: boolean }>

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const HERE = { directory: "/proj", workspaceID: "ws-1" }

function makeHarness() {
  // storage.memory is shared per key across setup() generations — like the
  // real host, where the store survives a plugin hot reload.
  const stores = new Map<string, Record<string, unknown>>()
  const sessions = new Map<string, { id: string; location: { directory: string; workspaceID?: string } }>()
  const families = new Map<string, string[]>()
  const dataListeners = new Map<string, Set<(event: unknown) => void>>()
  const rpcHandlers = new Map<string, Set<(event: unknown) => void>>()
  const rpcOnCalls: string[] = []
  const statusCalls: { sessionID: string; location: unknown }[] = []
  const toasts: { title?: string; message: string }[] = []
  let mutateFailures = 0
  let statusReply: (sessionID: string) => Promise<StatusReply> | StatusReply = (sessionID) => ({
    sessionID,
    permission: "rwx",
    active: [],
    temporary: [],
    permanent: [],
  })

  const context = {
    location: HERE,
    client: {
      rpc: () => ({
        events: {
          on: (name: string, handler: (event: unknown) => void) => {
            rpcOnCalls.push(name)
            let set = rpcHandlers.get(name)
            if (!set) rpcHandlers.set(name, (set = new Set()))
            set.add(handler)
            return () => set.delete(handler)
          },
        },
        status: (input: { sessionID: string }, options: { location: unknown }) => {
          statusCalls.push({ sessionID: input.sessionID, location: options.location })
          return Promise.resolve(statusReply(input.sessionID))
        },
      }),
    },
    storage: {
      memory: (key: string, options: { initial: Record<string, unknown> }) => {
        if (!stores.has(key)) stores.set(key, options.initial)
        const store = stores.get(key)!
        return [
          store,
          (mutate: (draft: Record<string, unknown>) => void) => {
            if (mutateFailures > 0) {
              mutateFailures--
              throw new Error("store fault")
            }
            mutate(store)
          },
        ] as const
      },
    },
    data: {
      on: (type: string, handler: (event: unknown) => void) => {
        let set = dataListeners.get(type)
        if (!set) dataListeners.set(type, (set = new Set()))
        set.add(handler)
        return () => set.delete(handler)
      },
      session: {
        get: (sessionID: string) => sessions.get(sessionID),
        family: (sessionID: string) => families.get(sessionID) ?? [],
      },
    },
    ui: {
      toast: { show: (toast: { title?: string; message: string }) => toasts.push(toast) },
      slot: () => () => {},
    },
  }

  const emitData = (type: string, event: unknown) => {
    for (const handler of [...(dataListeners.get(type) ?? [])]) handler(event)
  }
  // Mirrors promise/rpc.js: `for await (const e of source) await handler(e)` —
  // a throwing handler rejects the pump and the subscription dies for good,
  // which this mock reproduces by deleting a throwing handler.
  const emitRpc = (name: string, data: unknown, location: unknown = HERE) => {
    for (const handler of [...(rpcHandlers.get(name) ?? [])]) {
      try {
        handler({ data, location })
      } catch {
        rpcHandlers.get(name)!.delete(handler)
      }
    }
  }
  const flush = () => new Promise((resolve) => setTimeout(resolve, 0))
  const indicator = () => stores.get("opencode-v2-security.indicator") as HarnessStore | undefined
  return {
    context,
    sessions,
    families,
    dataListeners,
    rpcHandlers,
    rpcOnCalls,
    statusCalls,
    toasts,
    emitData,
    emitRpc,
    flush,
    indicator,
    setStatusReply: (fn: typeof statusReply) => {
      statusReply = fn
    },
    failMutations: (count: number) => {
      mutateFailures = count
    },
  }
}

// Payloads below mirror the generated V2Event union (@opencode/client
// types.d.ts): session-scoped events carry `data.sessionID`; session.created
// carries `data.location`; session.forked carries top-level `location`;
// session.moved carries `data.location`; server.connected carries `data: {}`.

describe("plugin.setup refresh wiring", () => {
  test("server.connected re-subscribes the RPC handlers and re-pulls every tracked session", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    const stop = tuiPlugin.setup(h.context as never)
    // Track the session via an event (the normal entry path), with the server
    // still reporting the armed category.
    h.setStatusReply((id) => ({ sessionID: id, permission: "r-x", active: ["filesystem"], temporary: ["filesystem"], permanent: [] }))
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    await h.flush()
    expect(h.indicator()!.s1).toEqual({ permission: "r-x", active: ["filesystem"], synced: true })

    // The shared event stream restarted: the lease has since expired server
    // side but no event could reach the dead subscription.
    h.setStatusReply((id) => ({ sessionID: id, permission: "r-x", active: [], temporary: [], permanent: [] }))
    const subscriptionsBefore = h.rpcOnCalls.length
    h.emitData("server.connected", { type: "server.connected", data: {} })
    // Both handlers re-registered exactly once each.
    expect(h.rpcOnCalls.length).toBe(subscriptionsBefore + 2)
    expect(h.rpcHandlers.get("changed")!.size).toBe(1)
    expect(h.rpcHandlers.get("permission")!.size).toBe(1)
    await h.flush()
    // The tracked session was re-pulled and converged to the server state.
    expect(h.statusCalls.filter((c) => c.sessionID === "s1").length).toBe(2)
    expect(h.indicator()!.s1.active).toEqual([])
    stop()
  })

  test("a changed event for a parent pulls a fresh snapshot for its children", async () => {
    const h = makeHarness()
    h.sessions.set("parent", { id: "parent", location: HERE })
    const childLocation = { directory: "/proj-child", workspaceID: "ws-1" }
    h.sessions.set("child", { id: "child", location: childLocation })
    h.families.set("parent", ["parent", "child"])
    const stop = tuiPlugin.setup(h.context as never)

    // The server only emits for the mutated session; the child inherits the
    // expired lease silently and must converge via a status pull. The parent's
    // own entry is created unsynced by the event, so it is re-pulled too.
    h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
    h.emitRpc("changed", { sessionID: "parent", reason: "expired", active: [], temporary: [], permanent: [] })
    await h.flush()
    const pulled = h.statusCalls.map((c) => c.sessionID)
    expect(pulled).toContain("parent")
    expect(pulled).toContain("child")
    // ...each addressed at the session's own location, not the TUI's.
    expect(h.statusCalls.find((c) => c.sessionID === "child")!.location).toEqual(childLocation)
    expect(h.statusCalls.find((c) => c.sessionID === "parent")!.location).toEqual(HERE)
    expect(h.indicator()!.child.active).toEqual([])
    expect(h.indicator()!.child.synced).toBe(true)
    stop()
  })

  test("session.compaction.ended re-pulls the session's authoritative state", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    const stop = tuiPlugin.setup(h.context as never)
    h.emitRpc("changed", { sessionID: "s1", reason: "armed", active: ["network"], temporary: ["network"], permanent: [] })
    expect(h.indicator()!.s1.active).toEqual(["network"])

    h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    await h.flush()
    expect(h.statusCalls).toContainEqual({ sessionID: "s1", location: HERE })
    expect(h.indicator()!.s1.active).toEqual([])
    expect(h.indicator()!.s1.synced).toBe(true)
    stop()
  })

  test("a throwing store write cannot kill the permission subscription", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    const stop = tuiPlugin.setup(h.context as never)
    const errorSpy = spyOn(console, "error").mockImplementation(() => {})
    try {
      h.failMutations(1)
      h.emitRpc("permission", { sessionID: "s1", reason: "set", permission: "r-x" })
      // The handler caught the fault internally — the pump's subscription is
      // still registered instead of silently dead.
      expect(h.rpcHandlers.get("permission")!.size).toBe(1)
      h.emitRpc("permission", { sessionID: "s1", reason: "set", permission: "r--" })
      expect(h.indicator()!.s1.permission).toBe("r--")
    } finally {
      errorSpy.mockRestore()
      stop()
    }
  })

  test("a status reply still in flight at disposal cannot write the shared store", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    const stopA = tuiPlugin.setup(h.context as never)
    const resolvers: Array<(reply: StatusReply) => void> = []
    h.setStatusReply(() => new Promise<StatusReply>((resolve) => resolvers.push(resolve)))
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    // A's pull is in flight. The host hot-reloads: A is disposed, B mounts
    // against the same storage.memory store.
    stopA()
    const stopB = tuiPlugin.setup(h.context as never)
    h.emitRpc("changed", { sessionID: "s1", reason: "armed", active: ["filesystem"], temporary: ["filesystem"], permanent: [] })
    expect(h.indicator()!.s1.active).toEqual(["filesystem"])
    // The event created an unsynced entry, so B also has a pull in flight.
    expect(resolvers.length).toBe(2)

    // A's stale snapshot lands late — it must not overwrite B's state.
    resolvers[0]!({ sessionID: "s1", permission: "r-x", active: [], temporary: [], permanent: [] })
    await h.flush()
    expect(h.indicator()!.s1.permission).toBe("rwx")
    expect(h.indicator()!.s1.active).toEqual(["filesystem"])
    // B's own pull then converges the entry normally.
    resolvers[1]!({ sessionID: "s1", permission: "rwx", active: ["filesystem"], temporary: ["filesystem"], permanent: [] })
    await h.flush()
    expect(h.indicator()!.s1.synced).toBe(true)
    stopB()
  })
})

describe("lease-deadline fallback timer", () => {
  // Helper: get a synced entry for s1 via a successful status pull so later
  // assertions isolate timer behavior from the unsynced-recovery pull.
  const syncSession = async (h: ReturnType<typeof makeHarness>, sessionID = "s1") => {
    h.sessions.set(sessionID, { id: sessionID, location: HERE })
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID } })
    await h.flush()
  }

  test("a finite lease reaching its deadline without any event re-subscribes and pulls", async () => {
    const h = makeHarness()
    h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    const callsAtStart = h.statusCalls.length
    const subsAtStart = h.rpcOnCalls.length

    // The user armed the kill switch with a short timeout; the server's
    // expiry emit never arrives (dropped event / dead subscription).
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["ALL"],
      temporary: [],
      permanent: [],
      expiresAt: Date.now() + 50,
    })
    expect(h.indicator()!.s1.active).toEqual(["ALL"])

    await sleep(150)
    // The deadline timer fired: handlers re-subscribed and a fresh snapshot
    // replaced the stale YOLO state without any user action.
    expect(h.rpcOnCalls.length).toBe(subsAtStart + 2)
    expect(h.statusCalls.length).toBe(callsAtStart + 1)
    expect(h.statusCalls.at(-1)).toEqual({ sessionID: "s1", location: HERE })
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: [], synced: true })
    stop()
  })

  test("a cleared event clears the badge, shows the toast, and disarms the timer", async () => {
    const h = makeHarness()
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["filesystem"],
      temporary: ["filesystem"],
      permanent: [],
      expiresAt: Date.now() + 50,
    })
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "cleared",
      active: [],
      temporary: [],
      permanent: [],
      // expiresAt absent = no live lease → the pending deadline is disarmed.
    })
    expect(h.indicator()!.s1.active).toEqual([])
    expect(h.toasts.some((t) => t.title === "Classifier bypass cleared")).toBe(true)

    const callsAfterClear = h.statusCalls.length
    await sleep(120)
    expect(h.statusCalls.length).toBe(callsAfterClear)
    stop()
  })

  test("mixed permanent + temporary categories survive a snapshot pull", async () => {
    const h = makeHarness()
    h.setStatusReply((id) => ({
      sessionID: id,
      permission: "r-x",
      active: ["filesystem", "network"],
      temporary: ["network"],
      permanent: ["filesystem"],
      expiresAt: null,
    }))
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    expect(h.indicator()!.s1).toEqual({
      permission: "r-x",
      active: ["filesystem", "network"],
      synced: true,
    })
    // null = armed without natural expiry → no timer ever fires.
    const callsAfterSync = h.statusCalls.length
    await sleep(120)
    expect(h.statusCalls.length).toBe(callsAfterSync)
    stop()
  })

  test("a null expiresAt arms no timer", async () => {
    const h = makeHarness()
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["ALL"],
      temporary: [],
      permanent: [],
      expiresAt: null,
    })
    const callsAfterArm = h.statusCalls.length
    await sleep(120)
    expect(h.statusCalls.length).toBe(callsAfterArm)
    expect(h.indicator()!.s1.active).toEqual(["ALL"])
    stop()
  })

  test("a newer deadline replaces the pending timer", async () => {
    const h = makeHarness()
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 50,
    })
    // A follow-up event pushes the deadline out — the near timer must be
    // cancelled, not fire a spurious pull.
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "updated",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 60_000,
    })
    const callsAfterUpdate = h.statusCalls.length
    await sleep(150)
    expect(h.statusCalls.length).toBe(callsAfterUpdate)
    stop()
  })

  test("disposal and session.deleted both cancel the pending timer", async () => {
    const h = makeHarness()
    const stopA = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 50,
    })
    const callsBeforeStop = h.statusCalls.length
    stopA()
    await sleep(120)
    expect(h.statusCalls.length).toBe(callsBeforeStop)

    // session.deleted clears the entry, the revisions, and the timer.
    const h2 = makeHarness()
    const stopB = tuiPlugin.setup(h2.context as never)
    await syncSession(h2)
    h2.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 50,
    })
    const callsBeforeDelete = h2.statusCalls.length
    h2.emitData("session.deleted", { type: "session.deleted", data: { sessionID: "s1" } })
    expect(h2.indicator()!.s1).toBeUndefined()
    await sleep(120)
    expect(h2.statusCalls.length).toBe(callsBeforeDelete)
    stopB()
  })

  test("a failed snapshot marks the badge unknown instead of trusting stale state, and a later success restores it", async () => {
    const h = makeHarness()
    h.setStatusReply((id) => ({
      sessionID: id,
      permission: "rwx",
      active: ["ALL"],
      temporary: ["ALL"],
      permanent: [],
      expiresAt: Date.now() + 50,
    }))
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: ["ALL"], synced: true })

    // The deadline fires but the status RPC is broken — the badge must drop
    // its confident [YOLO ON] claim rather than keep lying.
    h.setStatusReply(() => Promise.reject(new Error("status RPC failed")))
    await sleep(150)
    expect(h.indicator()!.s1.synced).toBe(false)

    // A later successful pull restores the honest state (lease long gone).
    h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    await h.flush()
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: [], synced: true })
    stop()
  })

  test("past-deadline retries are spaced, not a tight loop", async () => {
    const h = makeHarness()
    // The server keeps reporting a deadline already in the past (its sweep
    // has not pruned the lease yet): every pull re-arms, never instantly.
    h.setStatusReply((id) => ({
      sessionID: id,
      permission: "rwx",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() - 1000,
    }))
    const stop = tuiPlugin.setup(h.context as never)
    await syncSession(h)
    // The initial snapshot armed a past deadline: marked unsynced at once,
    // and the retry fires after DEADLINE_RETRY_MS — not immediately.
    expect(h.indicator()!.s1.synced).toBe(false)
    const callsAfterSync = h.statusCalls.length
    await sleep(150)
    expect(h.statusCalls.length).toBe(callsAfterSync)
    stop()
  })
})

describe("workspace filtering", () => {
  test("events are judged against their session's own location, not the TUI default", async () => {
    const h = makeHarness()
    // The terminal's default location and the open session's location are
    // routinely different workspaces.
    h.context.location = { directory: "/home/user", workspaceID: "ws-A" }
    h.sessions.set("s-b", { id: "s-b", location: { directory: "/proj", workspaceID: "ws-B" } })
    h.sessions.set("s-b2", { id: "s-b2", location: { directory: "/proj2", workspaceID: "ws-B" } })
    const stop = tuiPlugin.setup(h.context as never)

    // A legitimate OFF for a ws-B session — must NOT be dropped just because
    // the TUI's default workspace is ws-A.
    h.emitRpc(
      "changed",
      { sessionID: "s-b", reason: "cleared", active: [], temporary: [], permanent: [] },
      { directory: "/proj", workspaceID: "ws-B" },
    )
    expect(h.indicator()!["s-b"]).toBeDefined()
    expect(h.toasts.some((t) => t.title === "Classifier bypass cleared")).toBe(true)

    // The same kind of event under a genuinely different workspace for a
    // known session is still filtered.
    h.emitRpc(
      "changed",
      { sessionID: "s-b2", reason: "armed", active: ["ALL"], temporary: [], permanent: [] },
      { directory: "/other", workspaceID: "ws-C" },
    )
    expect(h.indicator()!["s-b2"]).toBeUndefined()

    // A transient lookup miss must never drop: the entry is written and the
    // recovery pull converges it later.
    h.emitRpc(
      "changed",
      { sessionID: "s-x", reason: "armed", active: ["network"], temporary: ["network"], permanent: [] },
      { directory: "/other", workspaceID: "ws-C" },
    )
    expect(h.indicator()!["s-x"]).toBeDefined()
    // No location at all is also accepted (nothing reliable to compare).
    h.emitRpc("changed", { sessionID: "s-y", reason: "armed", active: ["network"], temporary: [], permanent: [] }, undefined)
    expect(h.indicator()!["s-y"]).toBeDefined()
    stop()
  })
})

describe("stale pull rejection races", () => {
  test("a stale pull's late rejection cannot mark unsynced or disarm the newer timer", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    const pending: Array<{ resolve: (r: StatusReply) => void; reject: (e: unknown) => void }> = []
    h.setStatusReply(() => new Promise<StatusReply>((resolve, reject) => pending.push({ resolve, reject })))
    const stop = tuiPlugin.setup(h.context as never)
    // Two pulls in flight; the newer one wins and arms a fresh deadline.
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    expect(pending.length).toBe(2)
    pending[1]!.resolve({
      sessionID: "s1",
      permission: "rwx",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 60_000,
    })
    await h.flush()
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: ["network"], synced: true })

    // The older pull rejects late: it is handled state, not a failure — the
    // fresh badge and its timer must be left alone.
    pending[0]!.reject(new Error("stale transport"))
    await h.flush()
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: ["network"], synced: true })
    const calls = h.statusCalls.length
    await sleep(150)
    expect(h.statusCalls.length).toBe(calls)
    stop()
  })

  test("a deadline pull superseded by a fresher event does not retry the old deadline on rejection", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
    const stop = tuiPlugin.setup(h.context as never)
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    await h.flush()

    // Arm a short lease, then stall the next status reply so the deadline
    // pull is in flight when a fresher event lands.
    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "armed",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 50,
    })
    const pending: Array<{ resolve: (r: StatusReply) => void; reject: (e: unknown) => void }> = []
    h.setStatusReply(() => new Promise<StatusReply>((resolve, reject) => pending.push({ resolve, reject })))
    await sleep(100) // deadline fired: unsynced + pull in flight
    expect(h.indicator()!.s1.synced).toBe(false)

    h.emitRpc("changed", {
      sessionID: "s1",
      reason: "updated",
      active: ["network"],
      temporary: ["network"],
      permanent: [],
      expiresAt: Date.now() + 60_000,
    })
    // The event's deadline armed the new timer; the entry is still unsynced,
    // so the handler also started a recovery pull.
    await h.flush()
    expect(pending.length).toBe(2)

    pending[0]!.reject(new Error("deadline pull failed"))
    await h.flush()
    // The stale failure must not re-mark or re-arm over the fresher state.
    pending[1]!.resolve({ sessionID: "s1", permission: "rwx", active: [], temporary: [], permanent: [] })
    await h.flush()
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: [], synced: true })
    const calls = h.statusCalls.length
    await sleep(150)
    expect(h.statusCalls.length).toBe(calls)
    stop()
  })

  test("a late rejection after session.deleted cannot revive the entry", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    const pending: Array<{ resolve: (r: StatusReply) => void; reject: (e: unknown) => void }> = []
    h.setStatusReply(() => new Promise<StatusReply>((resolve, reject) => pending.push({ resolve, reject })))
    const stop = tuiPlugin.setup(h.context as never)
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    expect(pending.length).toBe(1)

    h.emitData("session.deleted", { type: "session.deleted", data: { sessionID: "s1" } })
    pending[0]!.reject(new Error("session gone"))
    await h.flush()
    expect(h.indicator()!["s1"]).toBeUndefined()
    const calls = h.statusCalls.length
    await sleep(120)
    expect(h.statusCalls.length).toBe(calls)
    stop()
  })
})

describe("past-deadline retry cap", () => {
  test("the badge stays unknown after the retry cap even while the server still reports a past deadline", async () => {
    const h = makeHarness()
    h.sessions.set("s1", { id: "s1", location: HERE })
    // Every reply keeps reporting a deadline already in the past — the
    // server has not swept its lease yet (or the reply is stale).
    h.setStatusReply((id) => ({
      sessionID: id,
      permission: "rwx",
      active: ["ALL"],
      temporary: [],
      permanent: [],
      expiresAt: Date.now() - 1000,
    }))
    const stop = tuiPlugin.setup(h.context as never)
    jest.useFakeTimers()
    // Fake timers also fake setTimeout, so promise continuations are pumped
    // through the microtask queue after each manual advance.
    const tick = async (ms: number) => {
      jest.advanceTimersByTime(ms)
      for (let i = 0; i < 10; i++) await Promise.resolve()
    }
    try {
      jest.setSystemTime(Date.now())
      h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
      await tick(0)
      // First snapshot applied, then the past deadline immediately flagged it.
      expect(h.statusCalls.length).toBe(1)
      expect(h.indicator()!.s1.synced).toBe(false)
      // Bounded spaced retries: 10s each, DEADLINE_MAX_RETRIES = 3.
      for (let i = 0; i < 3; i++) {
        await tick(10_000)
      }
      expect(h.statusCalls.length).toBe(4)
      // The fourth past deadline hits the cap: no more requests, and the
      // badge must remain honest — never a confident stale [YOLO ON].
      await tick(30_000)
      expect(h.statusCalls.length).toBe(4)
      expect(h.indicator()!.s1.synced).toBe(false)

      // A snapshot without expiresAt (lease finally swept) recovers.
      h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
      h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
      await tick(0)
      expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: [], synced: true })
      // A snapshot with a FUTURE deadline also recovers and re-arms cleanly.
      h.setStatusReply((id) => ({
        sessionID: id,
        permission: "rwx",
        active: ["network"],
        temporary: ["network"],
        permanent: [],
        expiresAt: Date.now() + 60_000,
      }))
      h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
      await tick(0)
      expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: ["network"], synced: true })
      // ...and that future deadline does fire exactly once.
      await tick(60_000)
      expect(h.indicator()!.s1.synced).toBe(true)
      expect(h.statusCalls.length).toBe(7)
      expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: ["network"], synced: true })
    } finally {
      jest.useRealTimers()
      stop()
    }
  })
})

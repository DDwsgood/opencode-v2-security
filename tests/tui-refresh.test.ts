import { describe, expect, mock, spyOn, test } from "bun:test"
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
}

type HarnessStore = Record<string, { permission: string; active: string[] }>

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
    expect(h.indicator()!.s1).toEqual({ permission: "r-x", active: ["filesystem"] })

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
    // expired lease silently and must converge via a status pull.
    h.setStatusReply((id) => ({ sessionID: id, permission: "rwx", active: [], temporary: [], permanent: [] }))
    h.emitRpc("changed", { sessionID: "parent", reason: "expired", active: [], temporary: [], permanent: [] })
    await h.flush()
    expect(h.statusCalls.map((c) => c.sessionID)).toEqual(["child"])
    // ...addressed at the child's own location, not the TUI's.
    expect(h.statusCalls[0]!.location).toEqual(childLocation)
    expect(h.indicator()!.child.active).toEqual([])
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
    let resolveStale!: (reply: StatusReply) => void
    h.setStatusReply((id) => new Promise<StatusReply>((resolve) => (resolveStale = resolve)))
    h.emitData("session.compaction.ended", { type: "session.compaction.ended", data: { sessionID: "s1" } })
    // A's pull is in flight. The host hot-reloads: A is disposed, B mounts
    // against the same storage.memory store.
    stopA()
    const stopB = tuiPlugin.setup(h.context as never)
    h.emitRpc("changed", { sessionID: "s1", reason: "armed", active: ["filesystem"], temporary: ["filesystem"], permanent: [] })
    expect(h.indicator()!.s1.active).toEqual(["filesystem"])

    // A's stale snapshot lands late — it must not overwrite B's state.
    resolveStale({ sessionID: "s1", permission: "r-x", active: [], temporary: [], permanent: [] })
    await h.flush()
    expect(h.indicator()!.s1).toEqual({ permission: "rwx", active: ["filesystem"] })
    stopB()
  })
})

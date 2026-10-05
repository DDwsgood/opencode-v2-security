import { afterAll, describe, expect, setSystemTime, test } from "bun:test"
import { mkdtemp } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import type { BypassStatusData } from "../src/bypass-rpc"

// Same minimal host-context harness as tests/bypass-rework.test.ts: the
// plugin's effect(ctx) only needs the ctx slices it actually calls, run
// against a manually-created Scope so forked fibers/finalizers stay alive
// between assertions.

let workdir: string | undefined
const scopes: Scope.Closeable[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "bypass-timeout-"))
  return workdir
}

afterAll(async () => {
  setSystemTime()
  for (const scope of scopes) {
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>

type Harness = {
  executeBefore: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string; description?: string }>
  rpcEvents: Array<{ name: string; data: unknown }>
  /** No-wake notice snapshot: runs the captured session "context" hook the
   *  way the host does while building a model request. */
  notice: (sessionID: string) => Promise<string>
  status: (sessionID: string) => Promise<BypassStatusData>
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

async function startPlugin(
  options: Record<string, unknown> = {},
  events: unknown[] = [],
): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const evalHooks: HookCb[] = []
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  const rpcEvents: Harness["rpcEvents"] = []
  let contextCb:
    | ((ev: { sessionID: string; system: Array<{ type: string; text: string }> }) => Effect.Effect<void>)
    | undefined
  let statusHandler: ((input: { sessionID: string }) => Effect.Effect<unknown, unknown>) | undefined

  const ctx = {
    options,
    tool: {
      hook: (name: string, cb: HookCb) => {
        collected[name] = cb
        return Effect.void
      },
    },
    shell: {
      hook: (name: string, cb: HookCb) => {
        collected[`shell.${name}`] = cb
        return Effect.void
      },
    },
    command: {
      transform: (cb: (draft: { add(d: { name: string; execute: CommandExec }): void }) => void) =>
        Effect.sync(() => cb({ add: (d) => void commands.set(d.name, d.execute) })),
    },
    permission: {
      hook: (name: string, cb: HookCb) => {
        evalHooks.push(cb)
        return Effect.void
      },
    },
    session: {
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      synthetic: (input: { sessionID: string; text: string; description?: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
      hook: (name: string, cb: (ev: { sessionID: string; system: Array<{ type: string; text: string }> }) => Effect.Effect<void>) => {
        if (name === "context") contextCb = cb
        return Effect.void
      },
    },
    rpc: {
      register: (_def: unknown, handlers: Record<string, unknown>) => {
        statusHandler = handlers.status as typeof statusHandler
        return Effect.succeed({
          events: {
            emit: (name: string, data: unknown) =>
              Effect.sync(() => {
                rpcEvents.push({ name, data })
              }),
          },
        })
      },
    },
    event: { subscribe: () => Stream.fromIterable(events) },
  }

  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )

  const status = async (sessionID: string) =>
    (await Effect.runPromise(statusHandler!({ sessionID }))) as BypassStatusData

  const notice = async (sessionID: string) => {
    const event = { sessionID, system: [{ type: "text", text: "base" }] }
    if (contextCb) await Effect.runPromise(contextCb(event as never))
    return event.system.map((p) => p.text).join("\n")
  }

  return {
    executeBefore: collected["execute.before"]!,
    commands,
    synthetic,
    rpcEvents,
    notice,
    status,
  }
}

const invoke = (h: Harness, sessionID: string, text = "") =>
  failureMessage(h.commands.get("bypass")!({ sessionID, prompt: { text } }))

const runBefore = (h: Harness, tool: string, sessionID: string, input: Record<string, unknown>) =>
  failureMessage(
    h.executeBefore({
      tool,
      sessionID,
      agent: "test",
      messageID: "m1",
      id: `call-${Math.random()}`,
      input,
    } as never),
  )

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

describe("/bypass timeout argument", () => {
  test("a trailing number arms with an absolute expiry; activity does not extend it", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const armedAt = Date.now()
      expect(await invoke(h, "s1", "+fs 120")).toBeUndefined()
      const first = await h.status("s1")
      expect(first.expiresAt).toBe(armedAt + 120_000)

      // Executing a shell command (and event-stream activity) must not move
      // the deadline: the lease is a fixed point in time.
      setSystemTime(new Date(armedAt + 60_000))
      expect(await runBefore(h, "shell", "s1", { command: "echo hi" })).toBeUndefined()
      const later = await h.status("s1")
      expect(later.expiresAt).toBe(armedAt + 120_000)
      expect(later.active).toContain("filesystem")

      // 120 seconds after arming the category is gone, renewed activity
      // notwithstanding.
      setSystemTime(new Date(armedAt + 121_000))
      const expired = await h.status("s1")
      expect(expired.active).toEqual([])
      expect(expired.expiresAt).toBeUndefined()
    } finally {
      setSystemTime()
    }
  })

  test("an arm without a timeout uses the configured default (fixed, not idle)", async () => {
    const h = await startPlugin({ bypassLeaseTtlMs: 300_000 })
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const armedAt = Date.now()
      expect(await invoke(h, "s1", "+fs")).toBeUndefined()
      expect((await h.status("s1")).expiresAt).toBe(armedAt + 300_000)
      setSystemTime(new Date(armedAt + 290_000))
      expect(await runBefore(h, "shell", "s1", { command: "echo hi" })).toBeUndefined()
      // 290s later the lease is still live but NOT renewed to 590s.
      expect((await h.status("s1")).expiresAt).toBe(armedAt + 300_000)
      setSystemTime(new Date(armedAt + 301_000))
      expect((await h.status("s1")).active).toEqual([])
    } finally {
      setSystemTime()
    }
  })

  test("timeout <= 0 arms a lease that never expires on its own; /bypass off ends it", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      expect(await invoke(h, "s1", "fs 0")).toBeUndefined()
      const armed = await h.status("s1")
      expect(armed.active).toContain("filesystem")
      expect(armed.expiresAt).toBeNull()

      // Far future: still armed.
      setSystemTime(new Date("2027-09-30T12:00:00Z"))
      const later = await h.status("s1")
      expect(later.active).toContain("filesystem")
      expect(later.expiresAt).toBeNull()

      setSystemTime()
      expect(await invoke(h, "s1", "off")).toBeUndefined()
      expect((await h.status("s1")).active).toEqual([])
      await delay(25) // the emit is fire-and-forget; let it land
      // The cleared event must omit expiresAt — a present-but-undefined value
      // fails the host schema and the event is silently dropped (the TUI badge
      // stayed armed). Presence, not JSON.stringify output, is what matters.
      const cleared = h.rpcEvents.findLast(
        (e) => e.name === "changed" && (e.data as { sessionID?: string }).sessionID === "s1",
      )
      expect((cleared?.data as { reason?: string }).reason).toBe("cleared")
      expect("expiresAt" in (cleared?.data as object)).toBe(false)
    } finally {
      setSystemTime()
    }
  })

  test("negative timeouts never expire, including the ALL kill switch", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      expect(await invoke(h, "negative", "filesystem,network -5")).toBeUndefined()
      expect((await h.status("negative")).expiresAt).toBeNull()
      expect(await invoke(h, "kill", "ALL -1")).toBeUndefined()
      const notice = await h.notice("kill")
      expect(notice).toContain("removed all opencode-v2-security enforcement")
      expect(notice).toContain("zero or negative timeouts have no natural expiry")
      setSystemTime(new Date("2030-09-30T12:00:00Z"))
      expect((await h.status("negative")).active).toEqual(["filesystem", "network"])
      expect((await h.status("kill")).active).toContain("ALL")
      expect(await invoke(h, "negative", "off")).toBeUndefined()
      expect((await h.status("negative")).active).toEqual([])
    } finally {
      setSystemTime()
    }
  })

  test("a timeout on a later arm updates the session lease's overall expiry", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const t0 = Date.now()
      expect(await invoke(h, "s1", "+fs")).toBeUndefined()
      expect(await invoke(h, "s1", "+network 45")).toBeUndefined()
      const status = await h.status("s1")
      expect(status.active).toContain("filesystem")
      expect(status.active).toContain("network")
      expect(status.expiresAt).toBe(t0 + 45_000)

      // A new arm without a timeout resets the same lease to the default.
      expect(await invoke(h, "s1", "+host")).toBeUndefined()
      expect((await h.status("s1")).expiresAt).toBe(Date.now() + 1_200_000)
    } finally {
      setSystemTime()
    }
  })

  test("the kill switch takes the timeout too; expiry restores enforcement", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const t0 = Date.now()
      expect(await invoke(h, "s1", "ALL 30")).toBeUndefined()
      const armed = await h.status("s1")
      expect(armed.active).toContain("ALL")
      expect(armed.expiresAt).toBe(t0 + 30_000)
      expect(await runBefore(h, "shell", "s1", { command: "rm -rf /" })).toBeUndefined()

      setSystemTime(new Date(t0 + 31_000))
      const expired = await h.status("s1")
      expect(expired.active).toEqual([])
      expect(await runBefore(h, "shell", "s1", { command: "rm -rf /" })).toMatch(/Blocked/)
    } finally {
      setSystemTime()
    }
  })

  test("children inherit the parent's lease and its deadline (read-only)", async () => {
    const h = await startPlugin({}, [
      { type: "session.created", data: { sessionID: "child-1", parentID: "s1" } },
    ])
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const t0 = Date.now()
      expect(await invoke(h, "s1", "+fs 240")).toBeUndefined()
      let child: BypassStatusData | undefined
      for (let i = 0; i < 40 && !(child?.active.includes("filesystem")); i++) {
        await delay(25)
        child = await h.status("child-1")
      }
      expect(child?.active).toContain("filesystem")
      expect(child?.expiresAt).toBe(t0 + 240_000)
      // The child never owns a lease: a timeout there is an error, and the
      // parent's deadline is unchanged by child activity.
      expect(await invoke(h, "child-1", "+host 60")).toBeUndefined() // child may still arm its OWN lease
      expect((await h.status("child-1")).expiresAt).toBe(t0 + 60_000)
      expect((await h.status("s1")).expiresAt).toBe(t0 + 240_000)
    } finally {
      setSystemTime()
    }
  })

  test("expiry fires the sweep: agent reminder + expired/empty user event", async () => {
    const h = await startPlugin()
    expect(await invoke(h, "s1", "+fs 1")).toBeUndefined()
    expect((await h.status("s1")).active).toContain("filesystem")
    let expired: unknown
    for (let i = 0; i < 120 && !expired; i++) {
      await delay(50)
      expired = h.rpcEvents.find(
        (e) => e.name === "changed" && (e.data as { reason?: string }).reason === "expired",
      )
    }
    expect(expired).toBeDefined()
    expect((expired as { data: { active: string[] } }).data.active).toEqual([])
    // The expired transition is the dropped-event regression shape: no live
    // lease, so expiresAt must be absent (not undefined) for the host schema.
    expect("expiresAt" in (expired as { data: object }).data).toBe(false)
    // Expired: the notice snapshot clears — the model never sees a stale
    // "allowed" state on its next request.
    expect(await h.notice("expiring")).toBe("base")
  }, 15_000)

  test("kill-switch expiry lifts ALL and re-announces enforcement", async () => {
    const h = await startPlugin()
    expect(await invoke(h, "s1", "ALL 1")).toBeUndefined()
    expect(await h.notice("s1")).toContain("removed all opencode-v2-security enforcement")
    // The lease sweep lifts ALL: the kill-switch notice clears on the next
    // snapshot (the model never sees a stale ALL-OFF state).
    let cleared = false
    for (let i = 0; i < 120 && !cleared; i++) {
      await delay(50)
      cleared = !(await h.notice("s1")).includes("removed all opencode-v2-security enforcement")
    }
    expect(cleared).toBe(true)
    expect((await h.status("s1")).active).toEqual([])
  }, 15_000)

  test("parameter errors reject atomically without changing the lease", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const t0 = Date.now()
      expect(await invoke(h, "s1", "+fs 60")).toBeUndefined()
      const before = await h.status("s1")
      expect(before.expiresAt).toBe(t0 + 60_000)

      // Non-final numbers and non-numeric timeouts are all
      // invalid tokens; none may mutate the lease or its deadline.
      for (const bad of ["+fs 60 bogus", "+fs 30 120", "+fs -5 bogus", "+fs 1e3", "+fs Infinity", "+fs NaN", "+fs 12x", "off 120"]) {
        const err = await invoke(h, "s1", bad)
        expect(err).toMatch(/Unknown bypass categor|Usage: \/bypass/)
      }
      const after = await h.status("s1")
      expect(after.active).toEqual(before.active)
      expect(after.expiresAt).toBe(t0 + 60_000)

      // A bare number alone is not a command — usage error, lease untouched.
      expect(await invoke(h, "s1", "120")).toMatch(/Usage: \/bypass/)
      expect((await h.status("s1")).expiresAt).toBe(t0 + 60_000)

      // A timeout that leaves no lease behind is an explicit error.
      const noLease = await invoke(h, "s2", "off 120")
      expect(noLease).toContain("timeout after off")
      expect((await h.status("s2")).active).toEqual([])
    } finally {
      setSystemTime()
    }
  })

  test("bare 0 stays the `off` alias while a trailing 0 means never-expire", async () => {
    const h = await startPlugin()
    await invoke(h, "s1", "+os")
    expect(await invoke(h, "s1", "0")).toBeUndefined()
    expect((await h.status("s1")).active).toEqual([])
    await invoke(h, "s1", "fs 0")
    expect((await h.status("s1")).expiresAt).toBeNull()
    await invoke(h, "s1", "off")
    expect((await h.status("s1")).active).toEqual([])
  })

  test("children converge on parent expiry for ALL and normal grants alike", async () => {
    const h = await startPlugin({}, [
      { type: "session.created", data: { sessionID: "child-all", parentID: "s1" } },
      { type: "session.created", data: { sessionID: "child-cat", parentID: "s2" } },
    ])
    for (let i = 0; i < 20; i++) await delay(25)
    expect(await invoke(h, "s1", "ALL 1")).toBeUndefined()
    expect(await invoke(h, "s2", "+fs 1")).toBeUndefined()

    // Pull-based status already converges through the inherited chain: both
    // children see the parent's grant while it is live.
    let childAll: BypassStatusData | undefined
    let childCat: BypassStatusData | undefined
    for (let i = 0; i < 40; i++) {
      await delay(25)
      childAll = await h.status("child-all")
      childCat = await h.status("child-cat")
      if (childAll.active.includes("ALL") && childCat.active.includes("filesystem")) break
    }
    expect(childAll?.active).toContain("ALL")
    expect(childCat?.active).toContain("filesystem")

    // After the parent leases lapse, both children converge to empty without
    // any command of their own — the sweep deadline wakes the loop itself.
    // The wait predicate is the pushed `expired` event for BOTH owners, not a
    // status pull: a lazy pull already reports the lease dead the moment its
    // deadline passes, while the sweep's event emit may land later — polling
    // status first and then asserting the events races that emit.
    for (const owner of ["s1", "s2"]) {
      let expired: { name: string; data: unknown } | undefined
      for (let i = 0; i < 140 && !expired; i++) {
        await delay(50)
        expired = h.rpcEvents.find(
          (e) =>
            e.name === "changed" &&
            (e.data as { sessionID?: string }).sessionID === owner &&
            (e.data as { reason?: string }).reason === "expired",
        )
      }
      expect(expired).toBeDefined()
      expect("expiresAt" in (expired?.data as object)).toBe(false)
    }
    // The sweep has run, so both pull-based views have converged too.
    childAll = await h.status("child-all")
    childCat = await h.status("child-cat")
    expect(childAll?.active).toEqual([])
    expect(childCat?.active).toEqual([])
    expect("expiresAt" in (childAll as object)).toBe(false)
    expect("expiresAt" in (childCat as object)).toBe(false)
  }, 15_000)

  test("fractional and large timeouts parse; overflow is clamped to a future deadline", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const t0 = Date.now()
      expect(await invoke(h, "s1", "+fs 1.5")).toBeUndefined()
      expect((await h.status("s1")).expiresAt).toBe(t0 + 1500)
      expect(await invoke(h, "s1", "+fs 999999999999")).toBeUndefined()
      const huge = (await h.status("s1")).expiresAt
      expect(huge).toBeGreaterThan(t0)
      expect(Number.isSafeInteger(huge)).toBe(true)
    } finally {
      setSystemTime()
    }
  })
})

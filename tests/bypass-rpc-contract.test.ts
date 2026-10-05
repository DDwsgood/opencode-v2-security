import { afterAll, describe, expect, setSystemTime, spyOn, test } from "bun:test"
import { mkdtemp } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { BypassRpc, type BypassStatusData } from "../src/bypass-rpc"

// --- strict schema check against the REAL contract object --------------------
// The host validates emitted objects by KEY PRESENCE, not by JSON.stringify
// output: an `expiresAt: undefined` member is present and fails
// `type: ["number","null"]` — that is the regression these tests guard (the
// host dropped `off`/`expired` events as `rpc.invalid_output`, so the TUI
// badge stayed armed). The validator below interprets BypassRpc's actual
// schema fields with those semantics on the original object; nothing is
// stringified first, because JSON.stringify silently drops undefined members
// and would hide exactly this bug.

type JsonSchema = {
  readonly type?: string | readonly string[]
  readonly properties?: Readonly<Record<string, JsonSchema>>
  readonly required?: readonly string[]
  readonly additionalProperties?: boolean
  readonly items?: JsonSchema
}

function typeMatches(type: string, value: unknown): boolean {
  switch (type) {
    case "null":
      return value === null
    case "string":
      return typeof value === "string"
    // The wire is JSON: Infinity/NaN are not representable numbers.
    case "number":
      return typeof value === "number" && Number.isFinite(value)
    case "array":
      return Array.isArray(value)
    case "object":
      return typeof value === "object" && value !== null && !Array.isArray(value)
    default:
      return false
  }
}

function describeValue(value: unknown): string {
  if (value === undefined) return "undefined"
  if (value === null) return "null"
  if (Array.isArray(value)) return "array"
  return typeof value
}

function schemaErrors(schema: JsonSchema, value: unknown, path: string): string[] {
  const errors: string[] = []
  const types = Array.isArray(schema.type) ? schema.type : schema.type ? [schema.type] : []
  if (types.length > 0 && !types.some((type) => typeMatches(type, value))) {
    errors.push(`${path}: expected ${types.join("|")}, got ${describeValue(value)}`)
    return errors
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value) && schema.properties) {
    const obj = value as Record<string, unknown>
    for (const key of Object.keys(obj)) {
      const prop = schema.properties[key]
      if (!prop) {
        if (schema.additionalProperties === false) errors.push(`${path}.${key}: additional property`)
        continue
      }
      // A present key must validate even when its VALUE is `undefined` —
      // presence, not serializability, is what the host checks.
      errors.push(...schemaErrors(prop, obj[key], `${path}.${key}`))
    }
    for (const key of schema.required ?? []) {
      if (!(key in obj)) errors.push(`${path}.${key}: required key missing`)
    }
  }
  if (Array.isArray(value) && schema.items) {
    value.forEach((item, index) =>
      errors.push(...schemaErrors(schema.items as JsonSchema, item, `${path}[${index}]`)),
    )
  }
  return errors
}

const STATUS_SCHEMA = BypassRpc.methods.status.output as JsonSchema
const CHANGED_SCHEMA = BypassRpc.events.changed.schema as JsonSchema

const statusErrors = (data: unknown) => schemaErrors(STATUS_SCHEMA, data, "status")
const changedErrors = (data: unknown) => schemaErrors(CHANGED_SCHEMA, data, "changed")

function expectValidStatus(data: BypassStatusData) {
  expect(statusErrors(data)).toEqual([])
}
function expectValidChanged(data: unknown) {
  expect(changedErrors(data)).toEqual([])
}
const lastChanged = (h: Harness, sessionID: string) =>
  [...h.rpcEvents].reverse().find(
    (e) => e.name === "changed" && (e.data as { sessionID?: string }).sessionID === sessionID,
  )?.data as Record<string, unknown> | undefined

// --- harness (same minimal host-context shape as bypass-timeout.test.ts) -----

let workdir: string | undefined
const scopes: Scope.Closeable[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "bypass-rpc-"))
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
  rpcEvents: Array<{ name: string; data: unknown; probe?: number }>
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
  emitFailure?: Error,
  emitProbe?: () => number,
): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const evalHooks: HookCb[] = []
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  const rpcEvents: Harness["rpcEvents"] = []
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
      // Context hook registrar stub: attachSessionContextHook
      // registers here; state notices are a no-op for these tests.
      hook: () => Effect.void,
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      synthetic: (input: { sessionID: string; text: string; description?: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
    },
    rpc: {
      register: (_def: unknown, handlers: Record<string, unknown>) => {
        statusHandler = handlers.status as typeof statusHandler
        return Effect.succeed({
          events: {
            emit: (name: string, data: unknown) =>
              // A failing host emit still records nothing — the plugin's catch
              // is what must surface it (console.error), never block the flow.
              emitFailure
                ? Effect.fail(emitFailure) as Effect.Effect<void, unknown>
                : Effect.sync(() => {
                    rpcEvents.push(
                      emitProbe ? { name, data, probe: emitProbe() } : { name, data },
                    )
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

  return { executeBefore: collected["execute.before"]!, commands, synthetic, rpcEvents, status }
}

const invoke = (h: Harness, sessionID: string, text = "") =>
  failureMessage(h.commands.get("bypass")!({ sessionID, prompt: { text } }))

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** Wait until `predicate` finds an event, bounded; returns undefined on timeout. */
async function waitForEvent(
  h: Harness,
  predicate: (e: { name: string; data: unknown }) => boolean,
  attempts = 140,
): Promise<{ name: string; data: unknown } | undefined> {
  for (let i = 0; i < attempts; i++) {
    const found = h.rpcEvents.find(predicate)
    if (found) return found
    await delay(50)
  }
  return undefined
}

// --- tests -------------------------------------------------------------------

describe("bypass RPC payload contract", () => {
  test("the test validator enforces presence semantics (present undefined is invalid)", () => {
    const valid = {
      sessionID: "s",
      permission: "rwx",
      active: ["filesystem"],
      temporary: ["filesystem"],
      permanent: [],
      expiresAt: 1234,
    }
    expect(statusErrors(valid)).toEqual([])
    // expiresAt: undefined is a PRESENT key — the exact shape the host
    // rejected. A JSON.stringify round-trip would silently drop it, which is
    // why this validator inspects the original object.
    const bad = { ...valid, expiresAt: undefined }
    expect("expiresAt" in bad).toBe(true)
    expect(statusErrors(bad)).not.toEqual([])
    expect(statusErrors(JSON.parse(JSON.stringify(bad)))).toEqual([])
    // Other schema rules are enforced too: required keys, extra members,
    // wrong scalar types, non-finite numbers.
    const { permanent: _dropped, ...missingRequired } = valid
    expect(statusErrors(missingRequired)).not.toEqual([])
    expect(statusErrors({ ...valid, extra: 1 })).not.toEqual([])
    expect(statusErrors({ ...valid, expiresAt: "soon" })).not.toEqual([])
    expect(statusErrors({ ...valid, expiresAt: Infinity })).not.toEqual([])
    expect(statusErrors({ ...valid, expiresAt: null })).toEqual([])
    const badEvent = { sessionID: "s", reason: "expired", active: [], temporary: [], permanent: [], expiresAt: undefined }
    expect(changedErrors(badEvent)).not.toEqual([])
  })

  test("no grants: status omits expiresAt entirely", async () => {
    const h = await startPlugin()
    const status = await h.status("s1")
    expectValidStatus(status)
    expect(status.active).toEqual([])
    expect("expiresAt" in status).toBe(false)
  })

  test("permanent-only config: status omits expiresAt", async () => {
    const h = await startPlugin({ BypassClassifier: ["filesystem"] })
    const status = await h.status("s1")
    expectValidStatus(status)
    expect(status.active).toEqual(["filesystem"])
    expect(status.temporary).toEqual([])
    expect(status.permanent).toEqual(["filesystem"])
    expect("expiresAt" in status).toBe(false)
  })

  test("timed arm: finite expiresAt on the armed event and status", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      const t0 = Date.now()
      expect(await invoke(h, "s1", "+fs 60")).toBeUndefined()
      await delay(25)
      const event = lastChanged(h, "s1")
      expect(event?.reason).toBe("armed")
      expectValidChanged(event)
      expect(event?.expiresAt).toBe(t0 + 60_000)
      const status = await h.status("s1")
      expectValidStatus(status)
      expect(status.expiresAt).toBe(t0 + 60_000)
    } finally {
      setSystemTime()
    }
  })

  test("never-expire lease: expiresAt is null (present), not absent", async () => {
    const h = await startPlugin()
    expect(await invoke(h, "s1", "fs 0")).toBeUndefined()
    await delay(25)
    const event = lastChanged(h, "s1")
    expectValidChanged(event)
    expect(event?.expiresAt).toBeNull()
    const status = await h.status("s1")
    expectValidStatus(status)
    expect(status.expiresAt).toBeNull()
  })

  test("/bypass off: cleared event omits expiresAt — the dropped-event regression", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      expect(await invoke(h, "s1", "+fs 60")).toBeUndefined()
      await delay(25)
      expect(lastChanged(h, "s1")?.expiresAt).toBe(Date.now() + 60_000)

      expect(await invoke(h, "s1", "off")).toBeUndefined()
      await delay(25)
      const cleared = lastChanged(h, "s1")
      expect(cleared?.reason).toBe("cleared")
      expect(cleared?.active).toEqual([])
      expectValidChanged(cleared)
      // The payload the host used to reject: the key must be absent, not
      // undefined.
      expect("expiresAt" in (cleared ?? {})).toBe(false)
      const status = await h.status("s1")
      expectValidStatus(status)
      expect("expiresAt" in status).toBe(false)
    } finally {
      setSystemTime()
    }
  })

  test("ALL expiry: armed and expired events are both schema-valid", async () => {
    const h = await startPlugin()
    expect(await invoke(h, "s1", "ALL 1")).toBeUndefined()
    await delay(25)
    const armed = lastChanged(h, "s1")
    expectValidChanged(armed)
    expect(armed?.active).toContain("ALL")
    expect(typeof armed?.expiresAt).toBe("number")

    // The sweep fires on its own deadline — no other command or wake needed.
    const expired = await waitForEvent(
      h,
      (e) => e.name === "changed" && (e.data as { reason?: string }).reason === "expired",
    )
    expect(expired).toBeDefined()
    expectValidChanged(expired?.data)
    const data = expired?.data as Record<string, unknown>
    expect(data.active).toEqual([])
    expect("expiresAt" in data).toBe(false)
  }, 15_000)

  test("unbounded parent + finite child: the child's earliest finite deadline wins", async () => {
    const h = await startPlugin({}, [
      { type: "session.created", data: { sessionID: "child-1", parentID: "s1" } },
    ])
    // Give the event-subscription fiber a beat to link the child.
    for (let i = 0; i < 20; i++) await delay(25)
    expect(await invoke(h, "s1", "fs 0")).toBeUndefined() // parent: no expiry
    const t0 = Date.now()
    expect(await invoke(h, "child-1", "+network 60")).toBeUndefined() // child: finite

    const child = await h.status("child-1")
    expectValidStatus(child)
    expect(child.active).toContain("network")
    expect(child.active).toContain("filesystem")
    // The mixed case: the unbounded parent lease must not hide the child's
    // finite deadline — the effective set shrinks when the child lease ends.
    expect(child.expiresAt).toBe(t0 + 60_000)

    const parent = await h.status("s1")
    expectValidStatus(parent)
    expect(parent.expiresAt).toBeNull()
  })

  test("after the finite child lease lapses, the unbounded parent lease remains (null)", async () => {
    const h = await startPlugin({}, [
      { type: "session.created", data: { sessionID: "child-1", parentID: "s1" } },
    ])
    for (let i = 0; i < 20; i++) await delay(25)
    expect(await invoke(h, "s1", "fs 0")).toBeUndefined()
    expect(await invoke(h, "child-1", "+network 1")).toBeUndefined()

    // The child's own arm already emitted reason "updated" (it inherited the
    // parent's armed filesystem), so the post-expiry event is identified by
    // `network` having left the active set — that is the sweep's update.
    const updated = await waitForEvent(
      h,
      (e) =>
        e.name === "changed" &&
        (e.data as { sessionID?: string }).sessionID === "child-1" &&
        (e.data as { reason?: string }).reason === "updated" &&
        !((e.data as { active?: string[] }).active ?? []).includes("network"),
    )
    expect(updated).toBeDefined()
    expectValidChanged(updated?.data)
    // The sweep removes only the child's lease; the child stays armed via the
    // inherited unbounded parent lease, so the follow-up event carries
    // expiresAt: null (armed, no natural expiry) — present null is valid.
    expect((updated?.data as Record<string, unknown>).expiresAt).toBeNull()
    const child = await h.status("child-1")
    expectValidStatus(child)
    expect(child.active).toEqual(["filesystem"])
    expect(child.expiresAt).toBeNull()
  }, 15_000)

  test("status reads the clock once: a deadline crossed mid-snapshot cannot split the payload", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      expect(await invoke(h, "s1", "+fs 60")).toBeUndefined()
      const deadline = Date.now() + 60_000

      // Straddle the lease deadline between successive clock reads: the first
      // read (at handler entry) still sees the lease live while every later
      // read would see it dead. One shared capture must pin the whole payload
      // to the live instant — never `active` armed + `expiresAt` absent, the
      // shape that leaves the TUI badge stale forever.
      let reads = 0
      let clock = spyOn(Date, "now").mockImplementation(() =>
        ++reads === 1 ? deadline - 100 : deadline + 100,
      )
      const live = await h.status("s1")
      clock.mockRestore()
      expect(reads).toBe(1)
      expectValidStatus(live)
      expect(live.temporary).toEqual(["filesystem"])
      expect(live.expiresAt).toBe(deadline)

      // Same rule on the expired side: one capture, a fully dead snapshot.
      reads = 0
      clock = spyOn(Date, "now").mockImplementation(() =>
        ++reads === 1 ? deadline + 100 : deadline - 100,
      )
      const dead = await h.status("s1")
      clock.mockRestore()
      expect(reads).toBe(1)
      expectValidStatus(dead)
      expect(dead.active).toEqual([])
      expect("expiresAt" in dead).toBe(false)
    } finally {
      setSystemTime()
    }
  })

  test("status snapshot stays atomic for the ALL kill switch too", async () => {
    const h = await startPlugin()
    setSystemTime(new Date("2026-09-30T12:00:00Z"))
    try {
      expect(await invoke(h, "s1", "ALL 60")).toBeUndefined()
      const deadline = Date.now() + 60_000
      let reads = 0
      const clock = spyOn(Date, "now").mockImplementation(() =>
        ++reads === 1 ? deadline - 100 : deadline + 100,
      )
      const live = await h.status("s1")
      clock.mockRestore()
      expect(reads).toBe(1)
      expectValidStatus(live)
      expect(live.active).toContain("ALL")
      expect(live.expiresAt).toBe(deadline)
    } finally {
      setSystemTime()
    }
  })

  test("a changed event reads the clock once even when an inherited lease deadline is crossed mid-emit", async () => {
    const childCreated = [
      { type: "session.created", data: { sessionID: "child-1", parentID: "s1" } },
    ]
    const BASE = 1_800_000_000_000

    // Pass 1 (calibration): under a per-call +200ms mock clock, measure the
    // clock value the parent lease arm read and the value captured when the
    // child's `changed` event payload was emitted (the probe records the
    // call index at the emit stub; the emit's single entry read is the last
    // read before it). Pass 2 replays the identical command sequence under
    // the same clock so the parent's deadline lands 100ms past the emit's
    // single capture — a live snapshot that any second read would see dead.
    let readsCal = 0
    const h1 = await startPlugin({}, childCreated, undefined, () => readsCal)
    for (let i = 0; i < 20; i++) await delay(25)
    const calClock = spyOn(Date, "now").mockImplementation(() => BASE + ++readsCal * 200)
    expect(await invoke(h1, "s1", "+fs 60")).toBeUndefined()
    expect(await invoke(h1, "child-1", "off")).toBeUndefined()
    calClock.mockRestore()
    await delay(25)
    const calArmed = h1.rpcEvents.find(
      (e) => e.name === "changed" && (e.data as { sessionID?: string }).sessionID === "s1",
    )
    const calChild = h1.rpcEvents.find(
      (e) => e.name === "changed" && (e.data as { sessionID?: string }).sessionID === "child-1",
    )
    const armNow = ((calArmed?.data as Record<string, unknown>).expiresAt as number) - 60_000
    const emitNow = BASE + (calChild?.probe ?? 0) * 200
    expect(calChild?.probe).toBeGreaterThan(0)

    // Pass 2: identical sequence; the parent's fractional timeout places its
    // deadline just past the emit's clock capture (emitNow + 100).
    let readsRun = 0
    const h2 = await startPlugin({}, childCreated, undefined, () => readsRun)
    for (let i = 0; i < 20; i++) await delay(25)
    const runClock = spyOn(Date, "now").mockImplementation(() => BASE + ++readsRun * 200)
    expect(await invoke(h2, "s1", `+fs ${(emitNow + 100 - armNow) / 1000}`)).toBeUndefined()
    expect(await invoke(h2, "child-1", "off")).toBeUndefined()
    runClock.mockRestore()
    await delay(25)

    const event = h2.rpcEvents.find(
      (e) => e.name === "changed" && (e.data as { sessionID?: string }).sessionID === "child-1",
    )
    const data = event?.data as Record<string, unknown>
    expectValidChanged(data)
    // One capture: the parent lease was live at that instant, so the payload
    // reports it AND carries its deadline — a second read would have seen the
    // deadline pass and emitted `active: [filesystem]` with no `expiresAt`.
    expect(data.temporary).toEqual(["filesystem"])
    expect(data.expiresAt as number).toBeGreaterThan(emitNow)
    expect(Math.abs((data.expiresAt as number) - (emitNow + 100))).toBeLessThan(1)
  }, 15_000)

  test("a failed emit is logged (type + whitelisted code only), never the raw message", async () => {
    const spy = spyOn(console, "error").mockImplementation(() => {})
    try {
      const h = await startPlugin(
        {},
        [],
        new TypeError(
          "rpc.invalid_output: Expected number | null at path .expiresAt — payload SECRET-MARKER-9x7",
        ),
      )
      // The command itself still completes and the state still changes.
      expect(await invoke(h, "s1", "+fs")).toBeUndefined()
      await delay(50)
      const status = await h.status("s1")
      expect(status.active).toContain("filesystem")
      const logged = spy.mock.calls.map((call) => call.join(" ")).join("\n")
      // Logged: the event kind, the error constructor name, and the
      // whitelisted rpc.* code — enough to locate the failing channel.
      expect(logged).toContain("bypass changed event was not delivered")
      expect(logged).toContain("TypeError")
      expect(logged).toContain("rpc.invalid_output")
      // Never logged: the raw message, which can echo payload content back
      // into the log (credentials, paths, config values).
      expect(logged).not.toContain("SECRET-MARKER-9x7")
      expect(logged).not.toContain(".expiresAt")
    } finally {
      spy.mockRestore()
    }
  })
})

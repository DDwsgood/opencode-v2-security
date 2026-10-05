import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"

// `set_permission` is a direct-child-only tightening tool: the sessionID
// argument is mandatory, the target must be a direct child of the calling
// session, and the write is clamped tight-only. The user-side `/perm` command
// and the subagent `permission` spawn argument are unchanged.

let workdir: string | undefined
const harnesses: Array<() => Promise<void>> = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "set-perm-"))
  return workdir
}

/** Controllable wire-event feed (same pattern as the guidance tests). */
function eventFeed() {
  const pending: unknown[] = []
  const waiters: Array<() => void> = []
  let closed = false
  const stream = Stream.fromAsyncIterable(
    (async function* () {
      for (;;) {
        while (pending.length > 0) yield pending.shift()!
        if (closed) return
        await new Promise<void>((resolve) => waiters.push(resolve))
      }
    })(),
    (cause) => new Error(`event feed failed: ${String(cause)}`),
  )
  const push = (event: unknown) => {
    pending.push(event)
    const wake = waiters.shift()
    if (wake) wake()
  }
  const close = () => {
    closed = true
    for (const wake of waiters.splice(0)) wake()
  }
  return { stream, push, close }
}

afterAll(async () => {
  for (const close of harnesses) await close().catch(() => {})
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>

type SetPermissionTool = {
  name: string
  description: string
  input: { required?: string[]; properties?: Record<string, unknown> }
  execute: (input: unknown, context: { sessionID: string }) => Effect.Effect<unknown, unknown>
}

type Harness = {
  setPermission: SetPermissionTool
  commands: Map<string, CommandExec>
  status: (sessionID: string) => Promise<{ active: string[]; permission: string }>
  push: (event: unknown) => void
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

async function startPlugin(parents: Record<string, string> = {}): Promise<Harness> {
  const directory = await ensureWorkdir()
  const feed = eventFeed()
  const collected: Partial<Record<string, HookCb>> = {}
  const commands = new Map<string, CommandExec>()
  const tools = new Map<string, SetPermissionTool>()
  let statusHandler: ((input: { sessionID: string }) => Effect.Effect<unknown, unknown>) | undefined

  const ctx = {
    options: { sandbox: { enabled: false }, logReviewerTrace: false },
    tool: {
      hook: (name: string, cb: HookCb) => {
        collected[name] = cb
        return Effect.void
      },
      transform: (cb: (draft: unknown) => void) =>
        Effect.sync(() =>
          cb({
            add: (tool: SetPermissionTool) => void tools.set(tool.name, tool),
            update: () => {},
          }),
        ),
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
      hook: () => Effect.void,
    },
    session: {
      // Context hook registrar stub: attachSessionContextHook
      // registers here; state notices are a no-op for these tests.
      hook: () => Effect.void,
      get: (input: { sessionID: string }) =>
        Effect.succeed({ location: { directory }, parentID: parents[input.sessionID] }),
      interrupt: () => Effect.void,
      synthetic: () => Effect.void,
    },
    rpc: {
      register: (_def: unknown, handlers: Record<string, unknown>) => {
        statusHandler = handlers.status as typeof statusHandler
        return Effect.succeed({ events: { emit: () => Effect.void } })
      },
    },
    event: { subscribe: () => feed.stream },
  }

  const scope = await Effect.runPromise(Scope.make())
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )

  harnesses.push(async () => {
    feed.close()
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  })

  return {
    setPermission: tools.get("set_permission")!,
    commands,
    status: async (sessionID) =>
      (await Effect.runPromise(statusHandler!({ sessionID }))) as { active: string[]; permission: string },
    push: feed.push,
  }
}

/** Run the tool as `caller`; return the failure message, or undefined with the
 * success result in `out`. */
async function runTool(
  h: Harness,
  caller: string,
  args: Record<string, unknown>,
): Promise<{ message?: string; result?: { content: Array<{ type: string; text: string }>; metadata: Record<string, unknown> } }> {
  const exit = await Effect.runPromise(Effect.exit(h.setPermission.execute(args, { sessionID: caller })))
  if (Exit.isFailure(exit)) {
    const found = Cause.findErrorOption(exit.cause)
    const error = Option.isSome(found) ? found.value : undefined
    return { message: error instanceof Error ? error.message : String(error) }
  }
  return { result: exit.value as never }
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

async function until(condition: () => Promise<boolean>, ms = 5000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if (await condition()) return
    await delay(10)
  }
  throw new Error("condition not met within timeout")
}

/** Push events, then a trailing session.deleted for an armed probe session, and
 * wait until the deletion is observable — the consumer processes the stream in
 * order, so everything pushed before it is guaranteed processed. */
async function flushEventsAfterPush(h: Harness, probe: string, ...events: unknown[]) {
  const invoke = (name: string, sessionID: string, text = "") =>
    failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))
  expect(await invoke("bypass", probe, "host")).toBeUndefined()
  expect((await h.status(probe)).active).toContain("host")
  for (const event of events) h.push(event)
  h.push({ type: "session.deleted", data: { sessionID: probe } })
  await until(async () => (await h.status(probe)).active.length === 0)
}

describe("set_permission registration", () => {
  test("registers with both permission and sessionID required and child-only wording", async () => {
    const h = await startPlugin()
    expect(h.setPermission.name).toBe("set_permission")
    expect([...(h.setPermission.input.required ?? [])].sort()).toEqual(["permission", "sessionID"])
    expect(Object.keys(h.setPermission.input.properties ?? {}).sort()).toEqual(["permission", "sessionID"])
    // Positive child semantics only — no self-session or omission copy.
    expect(h.setPermission.description).toContain("direct subagent session")
    expect(h.setPermission.description).not.toContain("current session")
    expect(h.setPermission.description).not.toContain("omit")
  })
})

describe("set_permission is direct-child-only and tighten-only", () => {
  test("omitted or empty sessionID fails closed (no caller fallback)", async () => {
    const h = await startPlugin()
    for (const args of [{ permission: "ro" }, { permission: "ro", sessionID: "" }, { permission: "ro", sessionID: "  " }]) {
      const { message } = await runTool(h, "parent1", args)
      expect(message).toMatch(/sessionID is required/)
    }
    // Nothing was written to the caller.
    expect((await h.status("parent1")).permission).toBe("rwx")
  })

  test("the caller's own sessionID is rejected", async () => {
    const h = await startPlugin()
    const { message } = await runTool(h, "parent1", { permission: "ro", sessionID: "parent1" })
    expect(message).toMatch(/not a direct child/)
    expect((await h.status("parent1")).permission).toBe("rwx")
  })

  test("a direct child is tightened; success text and metadata use child semantics", async () => {
    const h = await startPlugin()
    // Record child→parent links via the durable session.created event.
    await flushEventsAfterPush(
      h,
      "probe",
      { type: "session.created", data: { sessionID: "ses_child1", parentID: "parent1" } },
      { type: "session.created", data: { sessionID: "ses_grandchild", parentID: "ses_child1" } },
    )

    const { message, result } = await runTool(h, "parent1", { permission: "ro", sessionID: "ses_child1" })
    expect(message).toBeUndefined()
    expect(result?.content[0].text).toBe("Child session ses_child1 permission tightened to r-x.")
    expect(result?.metadata).toEqual({ sessionID: "ses_child1", permission: "r-x" })
    expect((await h.status("ses_child1")).permission).toBe("r-x")
  })

  test("widening a child is rejected (tighten-only preserved)", async () => {
    const h = await startPlugin()
    await flushEventsAfterPush(
      h,
      "probe",
      { type: "session.created", data: { sessionID: "ses_child1", parentID: "parent1" } },
    )
    expect((await runTool(h, "parent1", { permission: "none", sessionID: "ses_child1" })).message).toBeUndefined()
    expect((await h.status("ses_child1")).permission).toBe("--x")

    const { message } = await runTool(h, "parent1", { permission: "rw", sessionID: "ses_child1" })
    expect(message).toMatch(/would widen/)
    expect((await h.status("ses_child1")).permission).toBe("--x")
  })

  test("grandchild and arbitrary sessions are rejected", async () => {
    const h = await startPlugin()
    await flushEventsAfterPush(
      h,
      "probe",
      { type: "session.created", data: { sessionID: "ses_child1", parentID: "parent1" } },
      { type: "session.created", data: { sessionID: "ses_grandchild", parentID: "ses_child1" } },
    )
    // Grandchild of the caller: only child1 is a direct child.
    expect((await runTool(h, "parent1", { permission: "ro", sessionID: "ses_grandchild" })).message).toMatch(
      /not a direct child/,
    )
    // A child is fine from its own parent, but not from a sibling caller.
    expect((await runTool(h, "ses_child1", { permission: "ro", sessionID: "ses_grandchild" })).message).toBeUndefined()
    // Unknown session.
    expect((await runTool(h, "parent1", { permission: "ro", sessionID: "ses_unknown" })).message).toMatch(
      /not a direct child/,
    )
    // The failed calls wrote nothing.
    expect((await h.status("ses_grandchild")).permission).toBe("r-x")
  })

  test("rejects yolo in the mode setter — it is the /bypass kill-switch alias", async () => {
    const h = await startPlugin()
    await flushEventsAfterPush(
      h,
      "probe",
      { type: "session.created", data: { sessionID: "ses_child1", parentID: "parent1" } },
    )
    const { message } = await runTool(h, "parent1", { permission: "yolo", sessionID: "ses_child1" })
    expect(message).toMatch(/permission/i)
  })

  test("a child created before plugin load is verified via the live session lookup", async () => {
    // No session.created event for late-child: only ctx.session.get knows
    // its parentID.
    const h = await startPlugin({ "ses_late_child": "parent1" })
    const { message, result } = await runTool(h, "parent1", { permission: "w", sessionID: "ses_late_child" })
    expect(message).toBeUndefined()
    expect(result?.metadata).toEqual({ sessionID: "ses_late_child", permission: "-wx" })
    expect((await h.status("ses_late_child")).permission).toBe("-wx")
  })
})

describe("/perm stays the user-side control (unchanged)", () => {
  test("/perm still adjusts the caller's own session baseline", async () => {
    const h = await startPlugin()
    const invoke = (name: string, sessionID: string, text = "") =>
      failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))
    expect(await invoke("perm", "parent1", "ro")).toBeUndefined()
    expect((await h.status("parent1")).permission).toBe("r-x")
    // The user may widen back; the tool restriction does not apply to /perm.
    expect(await invoke("perm", "parent1", "rw")).toBeUndefined()
    expect((await h.status("parent1")).permission).toBe("rwx")
  })
})

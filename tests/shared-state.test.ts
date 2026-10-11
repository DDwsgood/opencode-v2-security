// Feature: process-wide shared security state across plugin instances.
//
// OpenCode V2 loads one plugin instance per session location, all inside the
// SAME server process. These tests simulate two instances (the plugin effect
// instantiated twice with fake hosts) sharing one registry and verify:
//
//   - a Bypass armed by instance A is effective for a child served by B;
//   - /perm ro in A caps a child served by B;
//   - the explicit no-Bypass barrier survives cross-instance arming;
//   - lease expiry is observed by both instances;
//   - a session's security notice is delivered exactly once, by whichever
//     instance handles that session's prompt hook;
//   - the approval cache is shared (a write approved via B replays in A) and
//     cleared on snapshot changes regardless of which instance changed;
//   - disposing an instance removes its change listener;
//   - a reloaded instance (location re-boot) sees the existing state.

import { afterAll, describe, expect, mock, setSystemTime, test } from "bun:test"
import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import path from "node:path"
import { Effect, Scope, Stream } from "effect"
import { cleanupTestArtifacts } from "./artifacts"

// Do not read the developer's ignored config.json while exercising startup.
const filesystem = await import("node:fs/promises")
const realReadFile = filesystem.readFile
const localConfig = path.resolve(import.meta.dir, "../config.json")
mock.module("node:fs/promises", () => ({
  ...filesystem,
  readFile: (...args: Parameters<typeof realReadFile>) => {
    if (String(args[0]) === localConfig)
      return Promise.reject(Object.assign(new Error("test config absent"), { code: "ENOENT" }))
    return realReadFile(...args)
  },
}))
const { default: plugin } = await import("../src/index")
const { getSharedSecurityState, resetSharedSecurityStateForTests } = await import("../src/security/shared-state")
const { adjudicateEffectAnswers } = await import("../src/security/effects-reviewer")
import type { EffectReviewRequest } from "../src/security/effects-reviewer"
const frozen = (await import("../src/security/v10-8-pipeexec.json")).default

const root = await mkdtemp("/tmp/opencode/shared-state-")
const workspace = path.join(root, "workspace")
const outside = path.join(root, "outside")
const scratch = path.join(root, "scratch")
await Promise.all([mkdir(workspace), mkdir(outside), mkdir(scratch)])

const scopes: Scope.Closeable[] = []
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})

const report = (deny = false, readonly = false) => {
  const answers: Record<string, unknown> = {}
  for (const [id, q] of Object.entries(frozen.questions)) {
    answers[id] = q.type === "noul" ? { noul: 0 } : { choice: Object.keys((q as { criteria: Record<string, string> }).criteria)[0] }
  }
  answers.floor = { choice: deny ? "yes" : "no" }
  answers.scope_coverage = { choice: "within_request" }
  if (readonly) answers.readonly_conformance = { choice: "read_only" }
  return adjudicateEffectAnswers(answers, readonly)
}

type Hook = (event: any) => Effect.Effect<any, any>

interface Instance {
  readonly scope: Scope.Closeable
  readonly calls: EffectReviewRequest[]
  readonly notifications: any[]
  readonly events: Array<readonly unknown[]>
  command(name: "perm" | "bypass", text: string, sessionID?: string): Promise<unknown>
  run(input: unknown, sessionID?: string): Promise<any>
  status(sessionID?: string): Promise<any>
  prompt(sessionID?: string): Promise<void>
  close(): Promise<void>
}

/** One plugin instance = one effect(ctx) with its own fake host slices. The
 *  durable "server" data (session records, retained user context) is shared
 *  between the instances, exactly like the real host process. */
async function startInstance(
  sessionInfo: Record<string, { parentID?: string; directory?: string }>,
  retained: Array<Record<string, string>>,
  options: { directory?: string; defaultPerm?: string; permanentBypass?: string[]; propagateBypass?: boolean; events?: Iterable<unknown>; mutateScope?: (scope: Scope.Closeable) => void } = {},
): Promise<Instance> {
  const hooks = new Map<string, Hook>()
  const commands = new Map<string, (input: any) => Effect.Effect<unknown, unknown>>()
  const calls: EffectReviewRequest[] = []
  const notifications: any[] = []
  const events: Array<readonly unknown[]> = []
  let serial = 0
  const tools = new Map<string, any>([
    ["write", {
      id: "write", name: "write", options: { codemode: false }, input: { type: "object", properties: {} },
      execute: (input: any, call: any) => Effect.gen(function* () {
        const permission = { sessionID: call.sessionID, action: "edit", resources: [input.path],
          source: { type: "tool", messageID: call.messageID, id: call.id }, effect: "ask" }
        yield* hooks.get("permission.evaluate")!(permission)
        if (permission.effect === "deny") return yield* Effect.fail(new Error(permission.message))
        yield* Effect.promise(() => writeFile(input.path, input.content))
        return { output: {}, content: "written", metadata: {} }
      }),
    }],
  ])
  let status: ((input: { sessionID: string }) => Effect.Effect<any>) | undefined
  const ctx = {
    location: { directory: options.directory ?? workspace },
    options: {
      sandbox: { enabled: false, scratch },
      slowCommands: false,
      logReviewerTrace: false,
      dynamicReview: { jev: { enabled: false } },
      permission: { registerTool: false, ...(options.defaultPerm ? { default: options.defaultPerm } : {}) },
      BypassClassifier: options.permanentBypass ?? [],
      bypassPropagateToSubagents: options.propagateBypass ?? true,
      reviewCommand: async (request: EffectReviewRequest) => {
        calls.push(structuredClone(request))
        return report(false, false)
      },
    },
    tool: {
      hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`tool.${name}`, callback) }),
      transform: (callback: (editor: any) => void) => Effect.sync(() =>
        callback({
          list: () => [...tools.values()],
          get: (id: string) => tools.get(id),
          add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }),
          // The real editor applies the updater to the registered tool; the
          // plugin relies on this to wrap boundary executors. A no-op here
          // would silently unwrap the review path under test.
          update: (id: string, updater: (tool: any) => void) => {
            const tool = tools.get(id)
            if (tool) updater(tool)
          },
        })),
    },
    shell: { hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`shell.${name}`, callback) }) },
    permission: { hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`permission.${name}`, callback) }) },
    command: {
      transform: (callback: (editor: any) => void) =>
        Effect.sync(() => callback({ add: (command: any) => commands.set(command.name, command.execute) })),
    },
    session: {
      get: ({ sessionID }: { sessionID: string }) =>
        Effect.succeed({ ...(sessionInfo[sessionID] ?? {}), location: { directory: sessionInfo[sessionID]?.directory ?? workspace } }),
      hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`session.${name}`, callback) }),
      synthetic: (input: any) => Effect.sync(() => { notifications.push(structuredClone(input)) }),
      context: () => Effect.succeed(retained),
    },
    rpc: {
      register: (_definition: unknown, handlers: any) =>
        Effect.sync(() => {
          status = handlers.status
          return { events: { emit: (...data: unknown[]) => Effect.sync(() => { events.push(data) }) } }
        }),
    },
    event: { subscribe: () => Stream.fromIterable(options.events ?? []) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  options.mutateScope?.(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  return {
    scope,
    calls,
    notifications,
    events,
    command: (name, text, sessionID = "parent") =>
      Effect.runPromise(commands.get(name)!({ sessionID, prompt: { text } })),
    run: (input, sessionID = "child") =>
      Effect.runPromise(tools.get("write")!.execute(input, { sessionID, agent: "build", messageID: "m", id: `call-${++serial}` })),
    status: (sessionID = "parent") => Effect.runPromise(status!({ sessionID })),
    prompt: (sessionID = "parent") =>
      Effect.runPromise(hooks.get("session.prompt")!({ sessionID, delivery: "steer" })),
    close: () => Effect.runPromise(Scope.close(scope, undefined as never)),
  }
}

/** Two plugin instances sharing one registry plus the durable session records
 *  a real server process would share. */
async function twoInstances() {
  resetSharedSecurityStateForTests()
  const sessionInfo: Record<string, { parentID?: string }> = {
    parent: {},
    child: { parentID: "parent" },
  }
  const retained = [{ type: "user", text: "Operate on the named fixtures for this shared-state test." }]
  const start = () => startInstance(sessionInfo, retained)
  return { start, a: await start(), b: await start() }
}

describe("shared security state across plugin instances", () => {
  test("loads under a host scope that keeps its first finalizer in single-entry form", async () => {
    resetSharedSecurityStateForTests()
    const instance = await startInstance(
      { parent: { directory: workspace } },
      [{ type: "user", text: "work on the fixtures" }],
      {
        mutateScope: (scope) => {
          // Older effect builds store a scope's first finalizer as
          // {finalizerKey, finalizer} and only promote to a `finalizers`
          // Map on the second add; this build dereferences `.finalizers`
          // unconditionally, so the plugin must normalize the ambient scope
          // before registering its own finalizers.
          ;(scope as { state: unknown }).state = {
            _tag: "Open", finalizerKey: {}, finalizer: () => Effect.void,
          }
        },
      },
    )
    // The single-finalizer entry is promoted to the Map shape; loading must
    // not die inside scopeAddFinalizerUnsafe.
    expect((instance.scope.state as { finalizers?: unknown }).finalizers).toBeInstanceOf(Map)
    await instance.close()
  })

  test("different location policies derive identical session snapshots without oscillating epochs", async () => {
    resetSharedSecurityStateForTests()
    const records = { parent: { directory: workspace }, child: { parentID: "parent", directory: outside } }
    const retained = [{ type: "user", text: "Inspect synthetic fixtures." }]
    const a = await startInstance(records, retained, { permanentBypass: ["network"] })
    const b = await startInstance(records, retained, { directory: outside, defaultPerm: "ro", propagateBypass: false })
    await a.command("bypass", "all", "parent")
    expect((await a.status("child")).mode).toBe("readonly")
    const epoch = getSharedSecurityState().securityEpochs.get("child")
    for (const instance of [b, a, b, a]) {
      const status = await instance.status("child")
      expect(status.permission).toBe("r-x")
      expect(status.active).toEqual([])
      expect(getSharedSecurityState().securityEpochs.get("child")).toBe(epoch)
    }
  })

  test("same-location policy conflicts retain the restrictive basis and warn once", async () => {
    resetSharedSecurityStateForTests()
    const records = { parent: { directory: workspace } }
    const retained = [{ type: "user", text: "Inspect synthetic fixtures." }]
    const warnings: string[] = []
    const originalWarn = console.warn
    console.warn = (message) => { warnings.push(String(message)) }
    try {
      const a = await startInstance(records, retained, { permanentBypass: ["network", "secret"] })
      const b = await startInstance(records, retained, { defaultPerm: "ro", permanentBypass: ["network"], propagateBypass: false })
      await startInstance(records, retained)
      for (const instance of [a, b, a, b]) {
        const status = await instance.status("parent")
        expect(status.permission).toBe("r-x")
        expect(status.permanent).toEqual([])
      }
      expect(warnings.filter((message) => message.includes("conflicting security policies"))).toHaveLength(1)
    } finally {
      console.warn = originalWarn
    }
  })

  test("a missing home instance tightens until its replacement registers", async () => {
    resetSharedSecurityStateForTests()
    const records = { parent: { directory: workspace }, child: { parentID: "parent", directory: outside } }
    const retained = [{ type: "user", text: "Inspect synthetic fixtures." }]
    const a = await startInstance(records, retained)
    const b = await startInstance(records, retained, { directory: outside })
    expect((await a.status("child")).mode).toBe("auto")
    await b.close()
    expect((await a.status("child")).mode).toBe("readonly")
    await startInstance(records, retained, { directory: outside })
    expect((await a.status("child")).mode).toBe("auto")
  })

  test("session.deleted clears shared L3 grants and repetitions", async () => {
    resetSharedSecurityStateForTests()
    const shared = getSharedSecurityState()
    shared.l3.grants.set("child", [{ root: outside, grantedAt: Date.now(), userMessageDigest: "fixture", securitySnapshot: "fixture" }])
    shared.l3.repetitions.set("fixture", { events: [], lastSeenAt: Date.now(), scope: { sessionID: "child", canWrite: true,
      userMessageDigest: "fixture", securitySnapshot: "fixture" }, pending: false })
    let processed!: () => void
    const deleted = new Promise<void>((resolve) => { processed = resolve })
    const events = { *[Symbol.iterator]() {
      yield { type: "session.deleted", data: { sessionID: "child" } }
      processed()
    } }
    await startInstance({}, [{ type: "user", text: "fixture" }], { events })
    await deleted
    expect(shared.l3.grants.has("child")).toBe(false)
    expect(shared.l3.repetitions.size).toBe(0)
  })

  test("a Bypass armed in instance A is effective for a child served by instance B", async () => {
    const { a, b } = await twoInstances()
    await a.command("bypass", "all", "parent")
    // The child is served by the OTHER instance: its status walk must see
    // the parent's lease through the shared map.
    const status = await b.status("child")
    expect(status.mode).toBe("bypass")
    expect(status.active).toContain("ALL")
  })

  test("/perm ro in instance A caps the child served by instance B", async () => {
    const { a, b } = await twoInstances()
    await a.command("perm", "ro", "parent")
    const status = await b.status("child")
    expect(status.mode).toBe("readonly")
    expect(status.permission).toBe("r-x")
    const parent = await b.status("parent")
    expect(parent.permission).toBe("r-x")
  })

  test("an explicit no-Bypass barrier set in one instance blocks a later arm in the other", async () => {
    const { a, b } = await twoInstances()
    // The user asserts the child's own mode through B: an inheritance
    // barrier lands on the child.
    await b.command("perm", "auto child", "parent")
    // Later, the parent arms full Bypass through A.
    await a.command("bypass", "all", "parent")
    const child = await b.status("child")
    expect(child.mode).toBe("auto")
    expect(child.active).toEqual([])
    const parent = await b.status("parent")
    expect(parent.mode).toBe("bypass")
  })

  test("lease expiry is observed by both instances", async () => {
    const { a, b } = await twoInstances()
    setSystemTime(new Date("2026-10-11T12:00:00Z"))
    try {
      await a.command("bypass", "all 60", "parent")
      const armed = await b.status("child")
      expect(armed.mode).toBe("bypass")
      setSystemTime(new Date("2026-10-11T12:01:01Z"))
      const fromA = await a.status("parent")
      const fromB = await b.status("child")
      expect(fromA.mode).toBe("auto")
      expect(fromA.active).toEqual([])
      expect(fromB.mode).toBe("auto")
      expect(fromB.active).toEqual([])
    } finally {
      setSystemTime()
    }
  })

  test("a session's notice is delivered exactly once, by whichever instance handles its prompt hook", async () => {
    const { a, b } = await twoInstances()
    await a.command("perm", "ro child", "parent")
    // The change itself admits nothing on either instance.
    expect(a.notifications).toHaveLength(0)
    expect(b.notifications).toHaveLength(0)
    // B serves the child's prompt hook: it delivers the recorded notice.
    await b.prompt("child")
    expect(b.notifications).toHaveLength(1)
    expect(b.notifications[0].text).toContain("[Read only]")
    // A broadcast prompt hook firing on the OTHER instance for the same
    // session must not deliver a second copy.
    await a.prompt("child")
    expect(a.notifications).toHaveLength(0)
    expect(b.notifications).toHaveLength(1)
  })

  test("the approval cache is shared across instances and cleared on any instance's snapshot change", async () => {
    const { a, b } = await twoInstances()
    const target = path.join(outside, "shared-cache.txt")
    // Pre-existing file: both writes see the same object identity, so the
    // replay must come from the L1 core-digest entry, not the L2 object
    // grant (a create-then-rewrite pair legitimately lands on L2).
    await writeFile(target, "seed")
    // B serves the first write: one review, cached under the child's
    // security snapshot in the shared cache.
    await b.run({ path: target, content: "one" })
    expect(b.calls).toHaveLength(1)
    // A serves the same crossing for the same session: the shared cache
    // replays B's approval without another review on either instance.
    const replay = await a.run({ path: target, content: "two" })
    expect(replay.metadata.boundary.source).toBe("cache:L1")
    expect(a.calls).toHaveLength(0)
    expect(b.calls).toHaveLength(1)
    // A changes the session's security state (down, then back up): the
    // shared basis/epoch move and the shared cache is cleared, so B's next
    // identical write is reviewed again.
    await a.command("perm", "ro child", "parent")
    await a.command("perm", "auto child", "parent")
    await b.run({ path: target, content: "three" })
    expect(b.calls).toHaveLength(2)
  })

  test("disposing an instance removes its change listener", async () => {
    const { a, b } = await twoInstances()
    await a.command("bypass", "all", "parent")
    await a.close()
    const before = a.events.length
    // B's transition must reach no listener of the disposed instance.
    await b.command("perm", "auto", "parent")
    expect(a.events.length).toBe(before)
    // The surviving instance still works normally.
    const status = await b.status("parent")
    expect(status.mode).toBe("auto")
  })

  test("a reloaded instance sees the existing state (location re-boot)", async () => {
    const { a, b, start } = await twoInstances()
    await a.command("bypass", "all", "parent")
    await a.close()
    // Same process, same registry: the replacement instance for that
    // location must reload into the armed lease instead of dropping it.
    const replacement = await start()
    const status = await replacement.status("parent")
    expect(status.mode).toBe("bypass")
    const child = await replacement.status("child")
    expect(child.mode).toBe("bypass")
    // The other instance observes the same state.
    expect((await b.status("parent")).mode).toBe("bypass")
  })
})

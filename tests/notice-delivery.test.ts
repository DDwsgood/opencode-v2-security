// Mid-run notices are separate user messages, not tool output or inbox work.

import { afterAll, describe, expect, mock, test } from "bun:test"
import { mkdtemp, mkdir } from "node:fs/promises"
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
const { resetSharedSecurityStateForTests } = await import("../src/security/shared-state")
const { createNoticeStore, createSessionStateNotices } = await import("../src/session-notifications")

const root = await mkdtemp("/tmp/opencode/notice-delivery-")
const workspace = path.join(root, "workspace")
await mkdir(workspace)
const scopes: Scope.Closeable[] = []
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})

type Hook = (event: any) => Effect.Effect<void, unknown>
type Lookup = "ok" | "missing" | "fail"

async function harness(failPolicy: "fail_open" | "fail_close" = "fail_open") {
  // Security state is shared process-wide between plugin instances; each
  // simulated instance here must start from a clean registry.
  resetSharedSecurityStateForTests()
  const hooks = new Map<string, Hook>()
  const commands = new Map<string, (input: any) => Effect.Effect<unknown, unknown>>()
  const notifications: any[] = []
  const lookups = new Map<string, Lookup>()
  let status: ((input: { sessionID: string }) => Effect.Effect<any>) | undefined
  const tools = new Map<string, any>([
    ["read", { id: "read", name: "read", options: {}, input: { type: "object", properties: {} },
      execute: () => Effect.succeed({ output: "file body", content: "file body", metadata: {} }) }],
  ])
  const ctx = {
    options: { sandbox: { enabled: false }, slowCommands: false, failPolicy },
    tool: {
      hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`tool.${name}`, callback) }),
      transform: (callback: (editor: any) => void) =>
        Effect.sync(() => callback({
          list: () => [...tools.values()],
          get: (id: string) => tools.get(id),
          add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }),
          update: () => {},
        })),
    },
    shell: { hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`shell.${name}`, callback) }) },
    permission: { hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`permission.${name}`, callback) }) },
    command: {
      transform: (callback: (editor: any) => void) =>
        Effect.sync(() => callback({ add: (command: any) => commands.set(command.name, command.execute) })),
    },
    session: {
      get: ({ sessionID }: { sessionID: string }) => {
        const mode = lookups.get(sessionID) ?? "ok"
        if (mode === "missing") return Effect.fail({ _tag: "Session.NotFoundError", sessionID })
        if (mode === "fail") return Effect.fail(new Error("transient store failure"))
        return Effect.succeed({ id: sessionID, location: { directory: workspace } })
      },
      hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`session.${name}`, callback) }),
      synthetic: (input: unknown) => Effect.sync(() => { notifications.push(structuredClone(input)) }),
    },
    rpc: {
      register: (_definition: unknown, handlers: any) =>
        Effect.sync(() => {
          status = handlers.status
          return { events: { emit: () => Effect.void } }
        }),
    },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  return {
    notifications,
    lookups,
    command: (text: string, sessionID = "s1") =>
      Effect.runPromise(commands.get("perm")!({ sessionID, prompt: { text } })),
    status: (sessionID = "s1") => Effect.runPromise(status!({ sessionID })),
    prompt: (sessionID = "s1") =>
      Effect.runPromise(hooks.get("session.prompt")!({ sessionID, messageID: "m", prompt: { text: "next" }, delivery: "steer" })),
    context: async (sessionID = "s1") => {
      const event = { sessionID, messages: [{ role: "tool", content: [{ type: "text", text: "fixture" }] }] }
      await Effect.runPromise(hooks.get("session.context")!(event))
      return event
    },
    after: async (result: Record<string, unknown> | undefined, status: "completed" | "error" = "completed", sessionID = "s1") => {
      const event: any = { tool: "read", sessionID, agent: "build", messageID: "m", id: "c1", input: {}, status,
        ...(result ? { result } : {}) }
      await Effect.runPromise(hooks.get("tool.execute.after")!(event))
      return event
    },
  }
}

describe("mid-run notice delivery", () => {
  test("RO prompt → Auto model context → RO again delivers the repeated mode", async () => {
    const host = await harness()
    await host.command("ro")
    await host.prompt()
    expect(host.notifications).toHaveLength(1)
    await host.command("auto")
    const auto = await host.context()
    expect(auto.messages.at(-1)?.role).toBe("user")
    expect(auto.messages.at(-1)?.content[0].text).toContain("[Auto mode]")
    await host.command("ro")
    const readonly = await host.context()
    expect(readonly.messages.at(-1)?.content[0].text).toContain("[Read only]")
  })

  test("shared claims serialize different snapshots and release on success and failure", async () => {
    const store = createNoticeStore()
    let entered!: () => void
    let release!: () => void
    const started = new Promise<void>((resolve) => { entered = resolve })
    const gate = new Promise<void>((resolve) => { release = resolve })
    const published: string[] = []
    const first = createSessionStateNotices(async (notice) => {
      entered()
      await gate
      published.push(notice.text)
    }, store)
    const second = createSessionStateNotices(async (notice) => { published.push(notice.text) }, store)
    first.setPerm("fixture", "ReadOnly")
    const earlier = first.deliverWithPrompt("fixture", "steer")
    await started
    second.setPerm("fixture", "Auto")
    const later = second.deliverWithPrompt("fixture", "steer")
    expect(second.forModelContext("fixture")).toBeUndefined()
    expect(published).toEqual([])
    release()
    await Promise.all([earlier, later])
    expect(published).toEqual(["[opencode-v2-security] ReadOnly", "[opencode-v2-security] Auto"])
    expect(store.claims.size).toBe(0)
    const failed = createSessionStateNotices(async () => { throw new Error("synthetic admission failure") }, store)
    failed.setPerm("fixture", "ReadOnly")
    await failed.deliverWithPrompt("fixture", "steer")
    expect(store.claims.size).toBe(0)
    expect(second.forModelContext("fixture")).toContain("ReadOnly")
  })

  test("a mid-run change leaves tool results intact and reaches the next existing model request", async () => {
    const host = await harness()
    await host.command("ro")
    const first = await host.after({ output: "file body", content: "file body" })
    expect(first.result.content).toBe("file body")
    const second = await host.after({ output: "again", content: "again" })
    expect(second.result.content).toBe("again")
    expect(host.notifications).toHaveLength(0)
    const context = await host.context()
    expect(context.messages[0]).toEqual({ role: "tool", content: [{ type: "text", text: "fixture" }] })
    expect(context.messages[1].role).toBe("user")
    expect(context.messages[1].content[0].text).toContain("[Read only]")
    expect((await host.context()).messages[1]).toEqual(context.messages[1])
    await host.prompt()
    expect(host.notifications).toHaveLength(1)
    expect((await host.context()).messages).toHaveLength(1)
  })

  test("an absent content keeps the host's output fallback unchanged", async () => {
    const host = await harness()
    await host.command("ro")
    const event = await host.after({ output: { lines: 2 } })
    expect(event.result).toEqual({ output: { lines: 2 } })
  })

  test("a failed tool call does not consume the notice; the next prompt carries it", async () => {
    const host = await harness()
    await host.command("ro")
    await host.after(undefined, "error")
    await host.prompt()
    expect(host.notifications).toHaveLength(1)
    expect(host.notifications[0].text).toContain("[Read only]")
  })
})

describe("ancestry verification at the prompt", () => {
  test("a status pull before the session exists does not mark it unverified", async () => {
    const host = await harness()
    host.lookups.set("s1", "missing")
    const early = await host.status()
    expect(early.permission).toBe("rwx")
    host.lookups.set("s1", "ok")
    await host.prompt()
    expect(host.notifications.map((item) => item.text).join("\n")).not.toContain("could not be verified")
  })

  test("a transient lookup failure is re-verified before the prompt's notice", async () => {
    const host = await harness("fail_close")
    host.lookups.set("s1", "fail")
    const early = await host.status()
    expect(early.permission).toBe("r-x")
    host.lookups.set("s1", "ok")
    await host.prompt()
    expect(host.notifications.map((item) => item.text).join("\n")).not.toContain("could not be verified")
    expect((await host.status()).permission).toBe("rwx")
  })
  test("fail_open does not manufacture a read-only ceiling from a lookup failure", async () => {
    const host = await harness("fail_open")
    host.lookups.set("s1", "fail")
    expect((await host.status()).permission).toBe("rwx")
    host.lookups.set("s1", "ok")
    await host.prompt()
    expect((await host.status()).permission).toBe("rwx")
  })
})

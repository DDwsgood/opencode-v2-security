// Delivery channels of the security-mode notice: a change during a run rides
// the next completed tool result; an idle change waits for the next user
// prompt. Ancestry lookups that failed earlier are re-verified at the prompt.

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

async function harness() {
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
    options: { sandbox: { enabled: false }, slowCommands: false },
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
    after: async (result: Record<string, unknown> | undefined, status: "completed" | "error" = "completed", sessionID = "s1") => {
      const event: any = { tool: "read", sessionID, agent: "build", messageID: "m", id: "c1", input: {}, status,
        ...(result ? { result } : {}) }
      await Effect.runPromise(hooks.get("tool.execute.after")!(event))
      return event
    },
  }
}

describe("mid-run notice delivery", () => {
  test("a change during a run is prepended to the next completed tool result, once", async () => {
    const host = await harness()
    await host.command("ro")
    const first = await host.after({ output: "file body", content: "file body" })
    expect(first.result.content[0].text).toContain("[Read only]")
    expect(first.result.content[1]).toEqual({ type: "text", text: "file body" })
    const second = await host.after({ output: "again", content: "again" })
    expect(second.result.content).toBe("again")
    // Already seen by the model: the next prompt does not repeat it, and
    // nothing was admitted to the inbox (no extra model request).
    expect(host.notifications).toHaveLength(0)
    await host.prompt()
    expect(host.notifications).toHaveLength(0)
  })

  test("an absent content keeps the host's output fallback after the notice", async () => {
    const host = await harness()
    await host.command("ro")
    const event = await host.after({ output: { lines: 2 } })
    expect(event.result.content).toEqual([
      { type: "text", text: expect.stringContaining("[Read only]") },
      { type: "text", text: JSON.stringify({ lines: 2 }) },
    ])
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
    const host = await harness()
    host.lookups.set("s1", "fail")
    const early = await host.status()
    expect(early.permission).toBe("r-x")
    host.lookups.set("s1", "ok")
    await host.prompt()
    expect(host.notifications.map((item) => item.text).join("\n")).not.toContain("could not be verified")
    expect((await host.status()).permission).toBe("rwx")
  })
})

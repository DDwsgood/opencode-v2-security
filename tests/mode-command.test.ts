// Mode-command coverage for the three user-facing security modes:
// [Read only] / [Auto mode] / [Bypass mode]. Exercises /perm mode tokens,
// the /bypass kill-switch aliases (all/*/ALL/yolo/bypass), lease expiry with
// baseline restore, and the ancestor read-only clamp — all through the real
// registered commands, never the model path.

import { afterAll, describe, expect, mock, test } from "bun:test"
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
const { resetSharedSecurityStateForTests } = await import("../src/security/shared-state")

const root = await mkdtemp("/tmp/opencode/mode-command-")
const workspace = path.join(root, "workspace")
await mkdir(workspace)
const scopes: Scope.Closeable[] = []
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})

type Hook = (event: any) => Effect.Effect<void, unknown>

async function harness(options: { bypassLeaseTtlMs?: number } = {}) {
  // Security state is shared process-wide between plugin instances; each
  // simulated instance here must start from a clean registry.
  resetSharedSecurityStateForTests()
  const hooks = new Map<string, Hook>()
  const commands = new Map<string, (input: any) => Effect.Effect<unknown, unknown>>()
  const events: Array<readonly unknown[]> = []
  const notifications: any[] = []
  const tools = new Map<string, { id: string; name: string; options: Record<string, unknown>; input?: unknown; execute: (input: any, call: any) => Effect.Effect<any, unknown> }>()
  const executed: Array<{ name: string; input: any }> = []
  let status: ((input: { sessionID: string }) => Effect.Effect<any>) | undefined
  // parent → child → grandchild chain plus an orphan session for the
  // descendant check.
  const sessionInfo: Record<string, { parentID?: string }> = {
    parent: {},
    child: { parentID: "parent" },
    grandchild: { parentID: "child" },
    orphan: {},
  }
  // A minimal subagent tool makes the plugin treat this host as having the
  // direct-subagent feature, so execute.before runs the permission
  // bookkeeping (stash/declared ceilings) — the tool itself is never run.
  tools.set("subagent", {
    id: "subagent",
    name: "subagent",
    options: { codemode: false },
    input: { type: "object", properties: {} },
    execute: () => Effect.succeed({ output: {}, content: "spawned", metadata: {} }),
  })
  for (const name of ["shell", "write", "read"]) {
    tools.set(name, {
      id: name,
      name,
      options: { codemode: false },
      input: { type: "object", properties: {} },
      execute: (input, call) =>
        Effect.gen(function* () {
          const action = name === "write" ? "edit" : name
          const target = typeof input?.path === "string" ? input.path : typeof input?.filePath === "string" ? input.filePath : "*"
          const event = {
            sessionID: call.sessionID,
            action,
            resources: [target],
            source: { type: "tool", messageID: call.messageID, id: call.id },
            effect: "ask",
          }
          if (hooks.has("permission.evaluate")) yield* hooks.get("permission.evaluate")!(event)
          if (event.effect === "deny") return yield* Effect.fail(new Error((event as any).message))
          if (name === "shell" && hooks.has("shell.create.before")) {
            const spawn = { command: input.command, cwd: input.workdir ?? workspace, shell: "/bin/bash", timeout: 1000, env: {} }
            yield* hooks.get("shell.create.before")!(spawn)
            input = { ...input, spawn }
          }
          executed.push({ name, input })
          return { output: { output: "mock", exit: 0, truncated: false }, content: "ok", metadata: {} }
        }),
    })
  }
  const ctx = {
    options: {
      sandbox: { enabled: false },
      slowCommands: false,
      bypassLeaseTtlMs: options.bypassLeaseTtlMs ?? 60_000,
    },
    tool: {
      hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`tool.${name}`, callback) }),
      transform: (callback: (editor: any) => void) =>
        Effect.sync(() =>
          callback({
            list: () => [...tools.values()],
            get: (id: string) => tools.get(id),
            add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }),
            update: (id: string, update: (tool: any) => void) => {
              const current = tools.get(id)
              if (!current) return
              const next = { ...current, options: { ...current.options } }
              update(next)
              tools.set(id, next)
            },
          }),
        ),
    },
    shell: { hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`shell.${name}`, callback) }) },
    permission: { hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`permission.${name}`, callback) }) },
    command: {
      transform: (callback: (editor: any) => void) =>
        Effect.sync(() => callback({ add: (command: any) => commands.set(command.name, command.execute) })),
    },
    session: {
      get: ({ sessionID }: { sessionID: string }) =>
        Effect.succeed({ location: { directory: workspace }, ...(sessionInfo[sessionID] ?? {}) }),
      hook: (name: string, callback: Hook) => Effect.sync(() => { hooks.set(`session.${name}`, callback) }),
      synthetic: (input: unknown) => Effect.sync(() => { notifications.push(structuredClone(input)) }),
    },
    rpc: {
      register: (_definition: unknown, handlers: any) =>
        Effect.sync(() => {
          status = handlers.status
          return { events: { emit: (...data: unknown[]) => Effect.sync(() => { events.push(data) }) } }
        }),
    },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  return {
    events,
    executed,
    notifications,
    hooks,
    command: (name: string, text: string, sessionID = "parent") =>
      Effect.runPromise(commands.get(name)!({ sessionID, prompt: { text } })),
    commandError: async (name: string, text: string, sessionID = "parent") => {
      try {
        await Effect.runPromise(commands.get(name)!({ sessionID, prompt: { text } }))
        return undefined
      } catch (error) {
        return error instanceof Error ? error.message : String(error)
      }
    },
    run: (name: string, input: unknown, sessionID = "parent", callId = "call-1") =>
      Effect.runPromise(tools.get(name)!.execute(input, { sessionID, agent: "build", messageID: "m", id: callId })),
    runError: async (name: string, input: unknown, sessionID = "parent", callId = "call-1") => {
      try {
        await Effect.runPromise(tools.get(name)!.execute(input, { sessionID, agent: "build", messageID: "m", id: callId }))
        return undefined
      } catch (error) {
        return error instanceof Error ? error.message : String(error)
      }
    },
    setPermission: (permission: string, target: string, caller = "parent") =>
      Effect.runPromise(tools.get("set_permission")!.execute({ permission, sessionID: target }, { sessionID: caller })),
    setPermissionError: async (permission: string, target: string, caller = "parent") => {
      try {
        await Effect.runPromise(tools.get("set_permission")!.execute({ permission, sessionID: target }, { sessionID: caller }))
        return undefined
      } catch (error) {
        return error instanceof Error ? error.message : String(error)
      }
    },
    execBefore: (ev: unknown) => Effect.runPromise(hooks.get("tool.execute.before")!(ev)),
    execAfter: (ev: unknown) => Effect.runPromise(hooks.get("tool.execute.after")!(ev)),
    status: (sessionID = "parent") => Effect.runPromise(status!({ sessionID })),
    prompt: (sessionID = "parent", delivery = "steer") =>
      Effect.runPromise(hooks.get("session.prompt")!({ sessionID, messageID: "m", prompt: { text: "next" }, delivery })),
    notice: async (sessionID = "parent") => {
      await Effect.runPromise(status!({ sessionID }))
      await Effect.runPromise(hooks.get("session.prompt")!({ sessionID, messageID: "m", prompt: { text: "next" }, delivery: "steer" }))
      return notifications.filter((item) => item.sessionID === sessionID).at(-1)?.text ?? ""
    },
  }
}

describe("security mode commands", () => {
  test("mode transitions append user notices with the next user prompt, never register a context hook", async () => {
    const host = await harness()
    await host.command("perm", "ro")
    // The change itself admits nothing: an inbox item here would start a
    // model request on its own.
    expect(host.notifications).toHaveLength(0)
    await host.prompt()
    const first = structuredClone(host.notifications)
    expect(first).toHaveLength(1)
    expect(first[0].text).toContain("[Read only]")
    expect(first[0].resume).toBe(false)
    expect(first[0].delivery).toBe("steer")
    await host.command("perm", "auto")
    expect(host.notifications).toHaveLength(1)
    // A queued prompt does not carry it (it would be promoted alone).
    await host.prompt("parent", "queue")
    expect(host.notifications).toHaveLength(1)
    await host.prompt()
    expect(host.notifications).toHaveLength(2)
    expect(host.notifications[0]).toEqual(first[0])
    expect(host.notifications[1].text).toContain("[Auto mode]")
    await host.command("perm", "auto")
    await host.prompt()
    expect(host.notifications).toHaveLength(2)
    expect(host.hooks.has("session.context")).toBe(false)
  })
  test("default session reports Auto mode", async () => {
    const host = await harness()
    const status = await host.status()
    expect(status.mode).toBe("auto")
    expect(status.permission).toBe("rwx")
  })

  test("/perm readonly aliases clamp to ReadOnly; auto spellings restore", async () => {
    const host = await harness()
    for (const alias of ["ro", "readonly", "r", "read-only", "4"]) {
      await host.command("perm", alias)
      const status = await host.status()
      expect(status.mode).toBe("readonly")
      expect(status.permission).toBe("r-x")
    }
    for (const alias of ["rw", "auto", "w", "readwrite", "6"]) {
      await host.command("perm", alias)
      const status = await host.status()
      expect(status.mode).toBe("auto")
      expect(status.permission).toBe("rwx")
    }
  })

  test("/perm bypass and every /bypass kill-switch spelling arm Bypass mode", async () => {
    for (const [command, text] of [
      ["perm", "bypass"],
      ["perm", "all"],
      ["perm", "yolo"],
      ["perm", "*"],
      ["bypass", "all"],
      ["bypass", "*"],
      ["bypass", "ALL"],
      ["bypass", "yolo"],
      ["bypass", "bypass"],
    ] as const) {
      const host = await harness()
      await host.command(command, text)
      const status = await host.status()
      expect(status.mode).toBe("bypass")
      expect(status.active).toContain("ALL")
      expect(status.permission).toBe("rwx")
      expect(host.events.some((entry) => entry[0] === "changed" && (entry[1] as any).mode === "bypass")).toBe(true)
      expect(host.events.some((entry) => entry[0] === "permission" && (entry[1] as any).mode === "bypass")).toBe(true)
    }
  })

  test("/bypass off restores the pre-Bypass baseline instead of leaving it widened", async () => {
    const host = await harness()
    await host.command("perm", "ro")
    expect((await host.status()).mode).toBe("readonly")
    // Bypass lifts the OWN baseline; the mode is real while the lease lives.
    await host.command("bypass", "ALL")
    expect((await host.status()).mode).toBe("bypass")
    // Ending the lease restores the stashed read-only baseline — the RO cap
    // must not have been permanently widened by the expired/ended mode.
    await host.command("bypass", "off")
    const status = await host.status()
    expect(status.mode).toBe("readonly")
    expect(status.permission).toBe("r-x")
    expect(status.active).toEqual([])
  })

  test("a lapsed Bypass lease restores the stashed read-only baseline lazily", async () => {
    const host = await harness()
    await host.command("perm", "ro")
    await host.command("bypass", "ALL 1")
    expect((await host.status()).mode).toBe("bypass")
    const now = Date.now
    Date.now = () => now() + 5_000
    try {
      // No sweep fired: the status read itself prunes the expired lease.
      const status = await host.status()
      expect(status.mode).toBe("readonly")
      expect(status.permission).toBe("r-x")
    } finally {
      Date.now = now
    }
  })

  test("an inherited read-only ceiling clamps Bypass mode to ReadOnly", async () => {
    const host = await harness()
    await host.command("perm", "ro")
    // Bypass on the child lifts only ITS baseline; the parent RO baseline
    // still caps the effective set.
    await host.command("perm", "bypass child")
    const status = await host.status("child")
    expect(status.mode).toBe("readonly")
    expect(status.permission).toBe("r-x")
    expect(status.active).toContain("ALL")
    // The child notice says the ceiling is still read-only — never claims
    // enforcement is fully off.
    expect(await host.notice("child")).toContain("read-only")
    // And a grandchild inherits the clamp the same way.
    const grandchild = await host.status("grandchild")
    expect(grandchild.mode).toBe("readonly")
  })

  test("/perm auto disarms a local Bypass lease but keeps armed categories", async () => {
    const host = await harness()
    await host.command("bypass", "fs")
    await host.command("bypass", "ALL")
    expect((await host.status()).mode).toBe("bypass")
    await host.command("perm", "auto")
    const status = await host.status()
    expect(status.mode).toBe("auto")
    expect(status.permission).toBe("rwx")
    expect(status.active).toContain("filesystem")
    expect(status.active).not.toContain("ALL")
  })

  test("/perm readonly disarms a local Bypass lease too", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    await host.command("perm", "readonly")
    const status = await host.status()
    expect(status.mode).toBe("readonly")
    expect(status.active).not.toContain("ALL")
  })

  test("category arms without the kill switch keep the ceiling visible", async () => {
    const host = await harness()
    await host.command("perm", "ro")
    await host.command("bypass", "fs")
    const status = await host.status()
    // Categories are armed but the RO ceiling still reports ReadOnly —
    // arming categories never claims Bypass.
    expect(status.mode).toBe("readonly")
    expect(status.active).toContain("filesystem")
    expect(status.active).not.toContain("ALL")
  })

  test("mode tokens and permission bits cannot be mixed", async () => {
    const host = await harness()
    expect(await host.commandError("perm", "bypass ro")).toContain("Usage:")
    expect(await host.commandError("perm", "bypass +w")).toContain("Usage:")
    expect((await host.status()).mode).toBe("auto")
  })

  test("/perm with a descendant id applies the mode there; non-descendants fail", async () => {
    const host = await harness()
    await host.command("perm", "ro child")
    expect((await host.status("child")).mode).toBe("readonly")
    expect(await host.commandError("perm", "ro orphan")).toContain("not a descendant")
    // With the parent itself read-only, a child's own baseline change cannot
    // escape the inherited ceiling.
    await host.command("perm", "ro")
    await host.command("perm", "auto child")
    expect((await host.status("child")).mode).toBe("readonly") // parent RO caps it
  })

  test("a never-expiring Bypass lease reports expiresAt null", async () => {
    const host = await harness()
    await host.command("bypass", "ALL -1")
    const status = await host.status()
    expect(status.mode).toBe("bypass")
    expect(status.expiresAt).toBeNull()
  })

  test("an agent-declared 'auto' child does not inherit the parent's Bypass mode", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    // The agent asserts an Auto ceiling on the child — same r/w bits, but
    // review must stay enabled: the child may not ride the parent's kill
    // switch. An undeclared sibling still inherits it.
    await host.setPermission("rw", "child")
    const child = await host.status("child")
    expect(child.mode).toBe("auto")
    expect(child.permission).toBe("rwx")
    // The barrier is per-level: the grandchild cannot read THROUGH the
    // declared Auto parent to the armed grandparent lease either.
    expect((await host.status("grandchild")).mode).toBe("auto")
    // The user's own Bypass on the child overrides the declared mask.
    await host.command("perm", "bypass child")
    expect((await host.status("child")).mode).toBe("bypass")
    await host.run("shell", { command: `rm -- '${path.join(workspace, "child-write.txt")}'` }, "child")
    expect(host.executed).toHaveLength(1)
  })

  test("an agent-declared 'ro' child under Bypass stays read-only checked", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    await host.setPermission("ro", "child")
    const child = await host.status("child")
    expect(child.mode).toBe("readonly")
    // The parent's kill switch must not let the RO child skip its checks.
    const target = path.join(workspace, "ro-write.txt")
    const error = await host.runError("write", { path: target, content: "x" }, "child")
    expect(error).toBeDefined()
    expect(host.executed).toHaveLength(0)
    // Reads still pass under the clamped Bypass lease.
    await host.run("read", { path: target }, "child")
    expect(host.executed).toHaveLength(1)
  })

  test("a pending declared spawn barriers the child before the authoritative bind", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    // The agent declares a ReadOnly ceiling on the not-yet-spawned child.
    await host.execBefore({
      tool: "subagent",
      sessionID: "parent",
      id: "spawn-1",
      input: { permission: "readonly" },
    })
    // Before execute.after binds the childID, the pending declaration is
    // already an inheritance barrier: the child must not observe the
    // parent's armed Bypass mode, and the declared cap tightens its
    // effective ceiling conservatively.
    expect((await host.status("child")).mode).toBe("readonly")
    // The authoritative bind keeps the same state — with a real RPC
    // notification so the UI never shows the child as Bypass.
    await host.execAfter({
      tool: "subagent",
      id: "spawn-1",
      status: "completed",
      result: { metadata: { sessionID: "child" } },
    })
    expect((await host.status("child")).mode).toBe("readonly")
    expect(host.events.some((entry) => entry[0] === "permission" && (entry[1] as any).sessionID === "child")).toBe(true)
  })

  test("a failed spawn consumes the declared stash instead of leaking it to siblings", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    await host.execBefore({
      tool: "subagent",
      sessionID: "parent",
      id: "spawn-2",
      input: { permission: "readonly" },
    })
    // The spawn call fails WITHOUT a child id: the stash must be consumed
    // here, not left tightening (or barrier-ing) a later child of the same
    // parent.
    await host.execAfter({ tool: "subagent", id: "spawn-2", status: "failed" })
    // Inheritance is unblocked again — the child rides the parent's lease.
    expect((await host.status("child")).mode).toBe("bypass")
  })

  test("a declared child's own Bypass lease expiry falls back to the declared mode, not the parent's", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    await host.setPermission("ro", "child")
    // The user's own arm on the child wins over the barrier — and when it
    // expires the barrier returns the child to its DECLARED mode, never to
    // the parent's inherited Bypass.
    await host.command("perm", "bypass child")
    expect((await host.status("child")).mode).toBe("bypass")
    const now = Date.now
    Date.now = () => now() + 61_000 // past the default 60s lease TTL
    try {
      const status = await host.status("child")
      expect(status.mode).toBe("readonly")
      expect(status.permission).toBe("r-x")
    } finally {
      Date.now = now
    }
  })

  test("the user's own Auto selection on a child also barriers the parent's Bypass", async () => {
    const host = await harness()
    await host.command("bypass", "ALL")
    expect((await host.status("child")).mode).toBe("bypass")
    await host.command("perm", "auto child")
    // An explicit user mode selection is an inheritance barrier too — the
    // child must not silently re-inherit the parent's armed kill switch.
    expect((await host.status("child")).mode).toBe("auto")
  })

  test("set_permission rejects non-mode values without echoing the raw input", async () => {
    const host = await harness()
    for (const bad of ["bypass", "all", "yolo", "none", "0", "s3cr3t-v4lue"]) {
      const error = await host.setPermissionError(bad, "child")
      expect(error).toContain("Permission change rejected")
      expect(error).toContain('"readonly" or "auto"')
      expect(error).not.toContain(bad)
    }
  })
})

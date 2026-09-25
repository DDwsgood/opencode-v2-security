import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { BYPASS_CATEGORIES, resolvePluginConfig, resolveSandbox } from "../src/config"
import { buildSandboxSpawn, type SandboxSelection } from "../src/sandbox"

// The test session's workspace: a real directory so ctx.session.get can
// report it as the session's location.
let workdir: string | undefined
const scopes: Scope.Closeable[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "bypass-rework-"))
  return workdir
}

afterAll(async () => {
  for (const scope of scopes) {
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

// --- minimal host-context harness ------------------------------------------
// The plugin's `effect(ctx)` only needs the ctx slices it actually calls:
// hook registrars (callbacks captured), command.transform (command defs
// captured), permission.hook, session.get/synthetic, rpc.register, and
// event.subscribe. The whole effect is run against a manually-created Scope
// so forked fibers/finalizers stay alive between assertions.

type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>

type Harness = {
  executeBefore: HookCb
  executeAfter: HookCb
  createBefore: HookCb
  evalHook: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string; description?: string }>
  rpcEvents: Array<{ name: string; data: unknown }>
  status: (sessionID: string) => Promise<{ active: string[]; temporary: string[]; permanent: string[]; permission: string }>
}

/** Run an effect and return the failure error's message, or undefined on
 * success. Effect.runPromise wraps failures in FiberFailure; Exit+Cause
 * recovers the original error object. */
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
    (await Effect.runPromise(statusHandler!({ sessionID }))) as Awaited<ReturnType<Harness["status"]>>

  return {
    executeBefore: collected["execute.before"]!,
    executeAfter: collected["execute.after"]!,
    createBefore: collected["shell.create.before"]!,
    evalHook: evalHooks[0]!,
    commands,
    synthetic,
    rpcEvents,
    status,
  }
}

/** /bypass (or /perm) invocation; returns the error message on failure. */
const invoke = (h: Harness, name: string, sessionID: string, text = "") =>
  failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))

/** execute.before driver; returns the block message, or undefined on allow. */
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

describe("config: BYPASS_CATEGORIES + BypassClassifier validation", () => {
  test("BYPASS_CATEGORIES is the canonical 10-entry list", () => {
    expect([...BYPASS_CATEGORIES]).toEqual([
      "filesystem", "host", "privilege", "secret", "network", "remote", "indirection", "dynamic", "sandbox", "slow",
    ])
  })

  test('"all"/"ALL" and "*" are rejected as permanent config entries', () => {
    expect(() => resolvePluginConfig({ BypassClassifier: ["all"] as never })).toThrow(/session-only/)
    expect(() => resolvePluginConfig({ BypassClassifier: ["ALL"] as never })).toThrow(/session-only/)
    expect(() => resolvePluginConfig({ BypassClassifier: ["*"] as never })).toThrow(/session-only/)
  })

  test("new categories are accepted as permanent config entries", () => {
    const resolved = resolvePluginConfig({ BypassClassifier: ["sandbox", "slow"] })
    expect(resolved.bypassClassifier.has("sandbox")).toBe(true)
    expect(resolved.bypassClassifier.has("slow")).toBe(true)
  })
})

describe("/bypass command parse + kill switch", () => {
  test("registers as `bypass`; * arms all 10 categories; unknown args fail with usage", async () => {
    const h = await startPlugin()
    expect(h.commands.has("bypass")).toBe(true)
    expect(await invoke(h, "bypass", "s1", "*")).toBeUndefined()
    expect((await h.status("s1")).active).toEqual([
      "dynamic", "filesystem", "host", "indirection", "network", "privilege", "remote", "sandbox", "secret", "slow",
    ])
    const usage = await invoke(h, "bypass", "s1", "bogus")
    expect(usage).toMatch(/Usage: \/bypass </)
    expect(usage).toContain("sandbox")
    expect(usage).toContain("slow")
  })

  test("ALL (case-sensitive) arms the kill switch, notifies loudly; `off` clears everything", async () => {
    const h = await startPlugin()
    // lowercase `all` arms all categories, NOT the kill switch.
    expect(await invoke(h, "bypass", "s1", "all")).toBeUndefined()
    let status = await h.status("s1")
    expect(status.active).toHaveLength(10)
    expect(status.active).not.toContain("ALL")
    expect(await invoke(h, "bypass", "s1", "off")).toBeUndefined()

    expect(await invoke(h, "bypass", "s1", "ALL")).toBeUndefined()
    status = await h.status("s1")
    expect(status.active).toContain("ALL")
    expect(status.temporary).toContain("ALL")
    const allReminder = h.synthetic.find((s) => s.sessionID === "s1" && s.text.includes("/bypass ALL"))
    expect(allReminder?.text).toContain("removed all opencode-v2-security enforcement")
    // Synthetic reminders carry the plugin prefix and no internal event tokens.
    expect(allReminder?.text.startsWith("opencode-v2-security:")).toBe(true)
    expect(allReminder?.text).not.toMatch(/token=/)

    // Category arms don't lift the kill switch — and stay silent while armed.
    const silentCount = h.synthetic.length
    expect(await invoke(h, "bypass", "s1", "+os")).toBeUndefined()
    status = await h.status("s1")
    expect(status.active).toContain("ALL")
    expect(status.active).toContain("host")
    expect(status.active).toContain("indirection")
    expect(h.synthetic.length).toBe(silentCount)

    expect(await invoke(h, "bypass", "s1", "off")).toBeUndefined()
    status = await h.status("s1")
    expect(status.active).toEqual([])
    expect(h.synthetic.some((s) => s.sessionID === "s1" && s.text.includes("Enforcement restored"))).toBe(true)
  })

  test("+ALL/-ALL are explicit arm/disarm; bare ALL toggles", async () => {
    const h = await startPlugin()
    expect(await invoke(h, "bypass", "s1", "+ALL")).toBeUndefined()
    expect((await h.status("s1")).active).toContain("ALL")
    expect(await invoke(h, "bypass", "s1", "-ALL")).toBeUndefined()
    expect((await h.status("s1")).active).not.toContain("ALL")
    // bare ALL toggles against the pre-command snapshot
    expect(await invoke(h, "bypass", "s1", "ALL")).toBeUndefined()
    expect((await h.status("s1")).active).toContain("ALL")
    expect(await invoke(h, "bypass", "s1", "ALL")).toBeUndefined()
    expect((await h.status("s1")).active).not.toContain("ALL")
  })

  test("bare tokens toggle per category against the pre-command snapshot", async () => {
    const h = await startPlugin()
    // fs alias arm, then bare toggle off.
    expect(await invoke(h, "bypass", "s1", "fs")).toBeUndefined()
    expect((await h.status("s1")).active).toContain("filesystem")
    expect(await invoke(h, "bypass", "s1", "fs")).toBeUndefined()
    expect((await h.status("s1")).active).not.toContain("filesystem")
    // Mixed snapshot toggle: legacy os expansion armed, fs not -> result {fs}.
    await invoke(h, "bypass", "s1", "+os")
    await invoke(h, "bypass", "s1", "os,fs")
    const active = (await h.status("s1")).active
    expect(active).toContain("filesystem")
    expect(active).not.toContain("host")
    expect(active).not.toContain("indirection")
    // `*` twice: arm-all then disarm-all.
    await invoke(h, "bypass", "s1", "off")
    await invoke(h, "bypass", "s1", "*")
    expect((await h.status("s1")).active).toHaveLength(10)
    await invoke(h, "bypass", "s1", "*")
    expect((await h.status("s1")).active).toEqual([])
    // 0 == off.
    await invoke(h, "bypass", "s1", "+os")
    await invoke(h, "bypass", "s1", "0")
    expect((await h.status("s1")).active).toEqual([])
  })

  test("ALL disarm emits restore notice + re-announces armed categories", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "+os", )
    await invoke(h, "bypass", "s1", "ALL")
    const armedCount = h.synthetic.length
    // Silent while armed.
    await invoke(h, "bypass", "s1", "+fs")
    expect(h.synthetic.length).toBe(armedCount)
    await invoke(h, "bypass", "s1", "-ALL")
    const texts = h.synthetic.map((s) => s.text).join("\n")
    expect(texts).toContain("Enforcement restored")
    expect(texts).toContain("The user temporarily allowed some sensitive commands")
    expect(texts).toContain("host")
    expect(texts).toContain("indirection")
    expect(texts).toContain("filesystem")
    expect(texts).not.toMatch(/token=/)
    // Every bypass reminder is prefixed with the plugin name.
    for (const s of h.synthetic) expect(s.text.startsWith("opencode-v2-security:")).toBe(true)
  })

  test("kill switch propagates to subagent sessions via session.created", async () => {
    const h = await startPlugin({}, [
      { type: "session.created", data: { sessionID: "child-1", parentID: "s1" } },
    ])
    await invoke(h, "bypass", "s1", "ALL")
    // The event consumer is a forked fiber; poll briefly for the parent link.
    let childActive: string[] = []
    for (let i = 0; i < 40 && !childActive.includes("ALL"); i++) {
      await delay(25)
      childActive = (await h.status("child-1")).active
    }
    expect(childActive).toContain("ALL")
    // The child session gets the all-enforcement-removed reminder at link time.
    expect(h.synthetic.some((s) => s.sessionID === "child-1" && s.text.includes("/bypass ALL"))).toBe(
      true,
    )
  })

  test("slow arm/disarm sends NO agent reminder; sandbox and all do notify", async () => {
    const h = await startPlugin()
    const count = () => h.synthetic.length

    await invoke(h, "bypass", "s1", "slow")
    expect(count()).toBe(0)
    expect((await h.status("s1")).active).toEqual(["slow"])
    // The user still sees it via the RPC event.
    expect(h.rpcEvents.some((e) => e.name === "changed")).toBe(true)

    await invoke(h, "bypass", "s1", "off")
    expect(count()).toBe(0)

    await invoke(h, "bypass", "s1", "sandbox")
    expect(
      h.synthetic.some((s) => s.text.includes("temporarily allowed") && s.text.includes("sandbox")),
    ).toBe(true)

    h.synthetic.length = 0
    await invoke(h, "bypass", "s1", "ALL")
    expect(h.synthetic.some((s) => s.text.includes("/bypass ALL"))).toBe(true)

    // Re-arming slow on top of other categories still adds no reminder.
    await invoke(h, "bypass", "s2", "sandbox")
    h.synthetic.length = 0
    await invoke(h, "bypass", "s2", "slow")
    expect(count()).toBe(0)
  })

  test("`off *` rearms cleanly and bare `/bypass` reports status", async () => {
    const h = await startPlugin()
    expect(await invoke(h, "bypass", "s1")).toBeUndefined()
    expect((await h.status("s1")).active).toEqual([])
    expect(await invoke(h, "bypass", "s1", "off *")).toBeUndefined()
    expect((await h.status("s1")).active).toHaveLength(10)
    expect(await invoke(h, "bypass", "s1", "off")).toBeUndefined()
    expect((await h.status("s1")).active).toEqual([])
  })

  test("disarming emits an ENDED reminder naming the ended categories", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "+os")
    const active = h.synthetic.find((s) => s.text.includes("temporarily allowed"))
    expect(active).toBeDefined()
    await invoke(h, "bypass", "s1", "-os")
    const ended = h.synthetic.find((s) => s.text.includes("temporary security allowance ended"))
    expect(ended?.text).toContain("host")
    expect(ended?.text).toContain("indirection")
    expect(ended?.text).toContain("Normal checks are active again")
    expect(ended?.text).not.toMatch(/token=|closed event/)
  })

  test("ACTIVE reminder carries the per-category layer notes", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "+os", )
    await invoke(h, "bypass", "s1", "+sandbox")
    await invoke(h, "bypass", "s1", "+privilege")
    const last = [...h.synthetic].reverse().find((s) => s.text.includes("temporarily allowed"))
    expect(last?.text).toContain("processes, services, and other running-system state")
    expect(last?.text).toContain("operating-system sandbox is removed")
    // The privilege note states the host-direct contract honestly.
    expect(last?.text).toContain("runs host-direct without the OS sandbox")
    expect(last?.text).toContain("refused loudly")
  })
})

describe("/perm bit syntax", () => {
  const invokePerm = (h: Harness, sessionID: string, text = "") =>
    failureMessage(h.commands.get("perm")!({ sessionID, prompt: { text } }))

  test("+/- bit ops mutate the session baseline; label shows x always set", async () => {
    const h = await startPlugin()
    expect((await h.status("s1")).permission).toBe("rwx")
    expect(await invokePerm(h, "s1", "-w")).toBeUndefined()
    expect((await h.status("s1")).permission).toBe("r-x")
    expect(await invokePerm(h, "s1", "+w")).toBeUndefined()
    expect((await h.status("s1")).permission).toBe("rwx")
    // Multi-token applied left-to-right: +r -w -> r-x.
    expect(await invokePerm(h, "s1", "+r -w")).toBeUndefined()
    expect((await h.status("s1")).permission).toBe("r-x")
    // Absolute forms still work.
    expect(await invokePerm(h, "s1", "rw")).toBeUndefined()
    expect((await h.status("s1")).permission).toBe("rwx")
    expect(await invokePerm(h, "s1", "ro")).toBeUndefined()
    expect((await h.status("s1")).permission).toBe("r-x")
    expect(await invokePerm(h, "s1", "none")).toBeUndefined()
    expect((await h.status("s1")).permission).toBe("--x")
  })

  test("+x/-x are rejected with the x-cannot-be-set copy", async () => {
    const h = await startPlugin()
    for (const arg of ["+x", "-x", "x"]) {
      const err = await invokePerm(h, "s1", arg)
      expect(err).toBeDefined()
      expect(err).toContain("x cannot be set; it is always on and only shown in the label")
    }
    expect((await h.status("s1")).permission).toBe("rwx")
  })

  test("/perm emits no reminder while the ALL kill switch is armed", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "ALL")
    const count = h.synthetic.length
    await invokePerm(h, "s1", "ro")
    expect(h.synthetic.length).toBe(count)
    // Restore re-announces the (now non-default) perm ceiling.
    await invoke(h, "bypass", "s1", "-ALL")
    expect(h.synthetic.some((s) => s.text.includes("r-x"))).toBe(true)
  })

  test("the permission reminder describes the concrete label and never claims a user change", async () => {
    const h = await startPlugin()
    await invokePerm(h, "s1", "ro")
    const ro = h.synthetic.find((s) => s.text.includes("permission ceiling"))
    expect(ro?.text).toContain("This session's permission ceiling changed")
    expect(ro?.text).not.toContain("user changed")
    expect(ro?.text).toContain("r=read actions, w=write/edit/delete actions")
    expect(ro?.text).toContain("x cannot be set; it is always on and only shown in the label")
    // RO keeps read actions and a read-only shell.
    expect(ro?.text).toContain("read actions are available but write actions are denied")

    await invokePerm(h, "s1", "none")
    const none = [...h.synthetic].reverse().find((s) => s.text.includes("--x"))
    expect(none?.text).toContain("all tool actions that require r or w are denied")
    // Under --x there is no read exemption to promise.
    expect(none?.text).not.toContain("read actions are available")
    expect(none?.text).not.toContain("read-only shell remains")
  })

  test("bit ops respect the ancestor cap like absolute forms", async () => {
    const h = await startPlugin({}, [
      { type: "session.created", data: { sessionID: "child-1", parentID: "s1" } },
    ])
    await delay(50)
    await invokePerm(h, "s1", "ro")
    // Child inherits the ro cap: +w on the child still reads r-x effective.
    await invokePerm(h, "s1", "+w child-1")
    const status = await h.status("child-1")
    expect(status.permission).toBe("r-x")
  })
})

describe("kill switch short-circuits", () => {
  test("runBefore leaves ev untouched (except the full marker) and never classifies", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "ALL")

    const input = { command: "rm -rf /" }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    // The command carries a "full" marker so create.before skips the wrap.
    expect(String(input.command)).toMatch(/^: opencode-sandbox [0-9a-f]{32}\n/)
    const dir = await ensureWorkdir()
    const createEv = {
      command: String(input.command),
      cwd: dir,
      shell: "/bin/bash",
      timeout: 60000,
      env: {} as Record<string, string | undefined>,
    }
    await Effect.runPromise(h.createBefore(createEv as never))
    expect(createEv.command).toBe("rm -rf /")
    expect(createEv.shell).toBe("/bin/bash")
    expect(createEv.env.OPENCODE_SANDBOX_MODE).toBeUndefined()

    // Re-enabling restores static enforcement.
    await invoke(h, "bypass", "s1", "off")
    expect(await runBefore(h, "shell", "s1", { command: "rm -rf /" })).toMatch(/Blocked/)
  })

  test("slow-command classifier skipped while all is armed", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "ALL")
    expect(await runBefore(h, "shell", "s1", { command: "sleep 200" })).toBeUndefined()
  })

  test("permission evaluate gate allows everything while all is armed", async () => {
    const h = await startPlugin({ permission: { default: "ro" } })
    const ev = { sessionID: "s1", action: "edit", resources: [], effect: "allow" as const, message: undefined }
    await Effect.runPromise(h.evalHook(ev as never))
    expect(ev.effect).toBe("deny")

    await invoke(h, "bypass", "s1", "ALL")
    const ev2 = { sessionID: "s1", action: "edit", resources: [], effect: "allow" as const, message: undefined }
    await Effect.runPromise(h.evalHook(ev2 as never))
    expect(ev2.effect).toBe("allow")

    await invoke(h, "bypass", "s1", "off")
    const ev3 = { sessionID: "s1", action: "edit", resources: [], effect: "allow" as const, message: undefined }
    await Effect.runPromise(h.evalHook(ev3 as never))
    expect(ev3.effect).toBe("deny")
  })

  test("non-shell tools are untouched; the subagent `permission` arg is stripped", async () => {
    const h = await startPlugin()
    await invoke(h, "bypass", "s1", "ALL")
    const input: Record<string, unknown> = { prompt: "x", permission: "ro" }
    expect(await runBefore(h, "subagent", "s1", input)).toBeUndefined()
    expect(input.permission).toBeUndefined()
    // execute.after records nothing under the kill switch.
    const afterResult = await failureMessage(
      h.executeAfter({
        tool: "shell",
        sessionID: "s1",
        agent: "test",
        messageID: "m1",
        id: "c1",
        input: { command: "false" },
        status: "completed",
        result: { metadata: { exit: 1 }, output: { output: "x" } },
      } as never),
    )
    expect(afterResult).toBeUndefined()
  })
})

describe("`slow` and `sandbox` categories", () => {
  test("`slow` bypasses the slow-command classifier only", async () => {
    const h = await startPlugin()
    // Baseline: sleep 200 soft-blocks (no BLOCK_SUFFIX — it's the soft form).
    const blocked = await runBefore(h, "shell", "s1", { command: "sleep 200" })
    expect(blocked).toBeTruthy()
    expect(blocked).not.toMatch(/^Blocked by static classifier/)

    await invoke(h, "bypass", "s1", "slow")
    expect(await runBefore(h, "shell", "s1", { command: "sleep 200" })).toBeUndefined()
    // Other enforcement still applies: static deny stays denied.
    expect(await runBefore(h, "shell", "s1", { command: "rm -rf /" })).toMatch(/Blocked/)
  })

  test("`sandbox` resolves full: tool calls carry a full marker; !cmd stays bare", async () => {
    const h = await startPlugin()
    const dir = await ensureWorkdir()

    // Marker-less spawns (user `!cmd`, host-internal) are never sandboxed —
    // the nonce marker is the sole wrap authority, before and after the arm.
    const bang = { command: "ls", cwd: dir, shell: "/bin/bash", timeout: 60000, env: {} as Record<string, string | undefined> }
    await Effect.runPromise(h.createBefore(bang as never))
    expect(bang.shell).toBe("/bin/bash")
    expect(bang.env.OPENCODE_SANDBOX_MODE).toBeUndefined()
    expect(bang.command).toBe("ls")

    await invoke(h, "bypass", "s1", "sandbox")

    const bang2 = { command: "ls", cwd: dir, shell: "/bin/bash", timeout: 60000, env: {} as Record<string, string | undefined> }
    await Effect.runPromise(h.createBefore(bang2 as never))
    expect(bang2.shell).toBe("/bin/bash")
    expect(bang2.command).toBe("ls")

    // The model-issued shell path resolves full: a "full" marker is
    // inserted and create.before leaves the spawn untouched.
    const input = { command: "echo hi" }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    expect(String(input.command)).toMatch(/^: opencode-sandbox [0-9a-f]{32}\n/)
    const createEv = {
      command: String(input.command),
      cwd: dir,
      shell: "/bin/bash",
      timeout: 60000,
      env: {} as Record<string, string | undefined>,
    }
    await Effect.runPromise(h.createBefore(createEv as never))
    expect(createEv.command).toBe("echo hi")
    expect(createEv.shell).toBe("/bin/bash")
  })
})

describe("sandbox config keys (schema + env plumbing)", () => {
  test("new keys have the documented defaults", () => {
    const s = resolveSandbox(undefined)
    expect(s.denyWrite).toEqual([])
    expect(s.denyRead).toEqual([])
    expect(s.rwNetwork).toBe("on")
    expect(s.allowSudo).toBe(false)
    expect(s.extraArgs).toEqual([])
  })

  test("valid forms resolve and normalize", () => {
    const s = resolveSandbox({
      denyWrite: ["/etc//shadow", "/var/lib"],
      denyRead: ["/home/user/.aws", "/etc/shadow"],
      rwNetwork: "off",
      allowSudo: true,
      extraArgs: ["--tmpfs", "/run/x", "--setenv", "K", "v"],
    })
    expect(s.denyWrite).toEqual(["/etc/shadow", "/var/lib"])
    expect(s.denyRead).toEqual(["/home/user/.aws", "/etc/shadow"])
    expect(s.rwNetwork).toBe("off")
    expect(s.allowSudo).toBe(true)
    expect(s.extraArgs).toEqual(["--tmpfs", "/run/x", "--setenv", "K", "v"])
    // The same path in both lists is allowed by contract.
    expect(() => resolveSandbox({ denyWrite: ["/x"], denyRead: ["/x"] })).not.toThrow()
  })

  test("invalid entries are rejected", () => {
    const invalid: Array<Record<string, unknown>> = [
      { denyWrite: "not-array" },
      { denyWrite: ["relative/path"] },
      { denyWrite: [""] },
      { denyWrite: ["/has:colon"] },
      { denyWrite: ["/"] },
      { denyWrite: ["/tmp"] }, // default scratch
      { denyWrite: ["/a/../b"] },
      { denyRead: ["relative"] },
      { denyRead: ["/tmp/"] }, // normalizes to scratch
      { denyRead: ["/"] },
      { denyRead: ["/x/../y"] },
      { rwNetwork: "maybe" },
      { rwNetwork: true },
      { allowSudo: "yes" },
      { extraArgs: "not-array" },
      { extraArgs: [""] },
      { extraArgs: ["--bind\n--tmpfs /etc"] }, // newline breaks the env encoding
      { extraArgs: [42] },
    ]
    for (const sandbox of invalid) {
      expect(() => resolveSandbox(sandbox)).toThrow()
    }
    // Custom scratch relocates the reserved path.
    const s = resolveSandbox({ scratch: "/var/tmp/scratch", denyWrite: ["/tmp/opencode"] })
    expect(s.denyWrite).toEqual(["/tmp/opencode"])
    expect(() => resolveSandbox({ scratch: "/var/tmp/scratch", denyRead: ["/var/tmp/scratch"] })).toThrow()
  })

  test("buildSandboxSpawn emits the env contract verbatim (both profiles)", () => {
    const sel = (overrides: Partial<SandboxSelection> = {}): SandboxSelection => ({
      enabled: true,
      mode: "auto",
      bwrapPath: "/usr/bin/bwrap",
      helperPath: "/pkg/bin/opencode-sandbox",
      scratch: "/tmp/opencode",
      roNetwork: "off",
      rwNetwork: "on",
      denyWrite: [],
      denyRead: [],
      allowSudo: false,
      extraArgs: [],
      maskWslInterop: true,
      maskPrivilegedSockets: [],
      roAfUnixBlock: true,
      onUnavailable: "fail_close",
      ...overrides,
    })

    for (const profile of ["ro", "rw"] as const) {
      const spec = buildSandboxSpawn(profile, sel(), () => false)
      expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("")
      expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("")
      expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("1")
      expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
      expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("")
    }

    const spec = buildSandboxSpawn(
      "rw",
      sel({
        denyWrite: ["/a", "/b/c"],
        denyRead: ["/d"],
        rwNetwork: "off",
        allowSudo: true,
        extraArgs: ["--setenv", "K", "yes", "--tmpfs", "/t"],
      }),
      () => false,
    )
    expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("/a:/b/c")
    expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("/d")
    expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("0")
    expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
    // One argv element per line; joined verbatim (no re-quoting).
    expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("--setenv\nK\nyes\n--tmpfs\n/t")
  })
})

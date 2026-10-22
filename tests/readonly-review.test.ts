import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test"
import { lstat, mkdir, mkdtemp } from "node:fs/promises"
import { connect } from "node:net"
import path from "node:path"
import * as os from "node:os"
import { Effect, Scope, Stream } from "effect"
import plugin from "../src/index"
import frozen from "../src/security/v11-gold-prompt.json"
import { resetSharedSecurityStateForTests } from "../src/security/shared-state"
import {
  adjudicateEffectAnswers,
  buildEffectReviewBody,
  EFFECTS_POLICY_VERSION,
  EFFECTS_POLICY_VERSION_READONLY,
  parseEffectAnswers,
  reviewEffects,
  type EffectReviewRequest,
} from "../src/security/effects-reviewer"
import { boundaryCoreDigest, createApprovalCache } from "../src/security/approval-cache"
import { classifyShellCommand } from "../src/security/classifier"
import { isFloorRule } from "../src/security/bypass"
import type { RuntimeBoundaryEvent } from "../src/runtime-boundary"
import { cleanupTestArtifacts } from "./artifacts"

const request: EffectReviewRequest = {
  command: "printf hello",
  cwd: "/workspace",
  environment: "Linux",
  user_request: "Inspect",
  session_context: [],
  input_facts: [],
  files: [],
  sandbox: { trigger: "none", resolved_writes: [], domain: null, error: null },
  bypass: { categories: [], custom: null },
}

function answers(conformance?: "read_only" | "writes" | "unclear", overrides: Record<string, unknown> = {}) {
  const values: Record<string, any> = Object.fromEntries(Object.entries(frozen.questions).map(([name, question]) => [
    name,
    question.type === "noul"
      ? { noul: 0 }
      : { choice: Object.keys((question as { criteria: Record<string, string> }).criteria)[0] },
  ]))
  values.floor = { choice: "no" }
  values.scope_coverage = { choice: "within_request" }
  values.gap_reach = { choice: "no_blocking_gap" }
  if (conformance) values.readonly_conformance = { choice: conformance }
  return { ...values, ...overrides }
}

describe("frozen write-mode body and read-only variant", () => {
  test("write mode has ten questions and compact trusted-answer authorization", () => {
    const facts = '{"bypass":{"categories":[],"custom":null},"command":"printf hello","cwd":"/workspace","environment":"Linux","files":[],"input_facts":[],"sandbox":{"domain":null,"error":null,"resolved_writes":[],"trigger":"none"},"session_context":[],"user_request":"Inspect"}'
    const body = buildEffectReviewBody(request)
    expect(body.questions).toEqual(frozen.questions)
    expect(Object.keys(body.questions)).toHaveLength(10)
    expect(body.state).toContain("User response via trusted question tool")
    expect(body.state).toEndWith(`<review_input>\n${facts}\n</review_input>\n`)
    expect(buildEffectReviewBody(request, false)).toEqual(body)
  })

  test("RO keeps all frozen questions and appends the paragraph and one choice", () => {
    const body = buildEffectReviewBody(request, true)
    const { readonly_conformance, ...originalQuestions } = body.questions
    expect(originalQuestions).toEqual(frozen.questions)
    expect(Object.keys(body.questions)).toHaveLength(11)
    expect(body.state.startsWith(`${frozen.header}\n\n`)).toBe(true)
    expect(body.state).toContain("READ-ONLY SESSION [Read only]")
    expect(body.state).toContain("[Read only]")
    expect(body.state).toContain("denyWrite, protected/credential paths or floors")
    expect(body.state).toContain("No outside-root cache/history exemption")
    expect(body.state.slice(body.state.indexOf("<review_input>"))).toBe(
      buildEffectReviewBody(request).state.slice(buildEffectReviewBody(request).state.indexOf("<review_input>")),
    )
    expect(readonly_conformance).toMatchObject({ type: "choice" })
    expect(Object.keys((readonly_conformance as any).criteria)).toEqual(["read_only", "writes", "unclear"])
  })

  test("the floor wins first, then writes and unclear deny as readonly", () => {
    for (const conformance of ["writes", "unclear"] as const) {
      for (const floor of ["no", "yes", "unclear"]) {
        expect(adjudicateEffectAnswers(answers(conformance, { floor: { choice: floor } }), true)).toMatchObject({
          decision: "deny", source: floor === "yes" ? "floor" : "readonly", policyVersion: EFFECTS_POLICY_VERSION_READONLY,
        })
      }
    }
  })

  test("read_only applies the normal adjudication, including deny and evidence", () => {
    for (const overrides of [
      {},
      { floor: { choice: "yes" } },
      { floor: { choice: "unclear" } },
      { filesystem_severity: { noul: 1 }, scope_coverage: { choice: "uncovered" } },
    ]) {
      const normal = adjudicateEffectAnswers(answers(undefined, overrides))
      const readonly = adjudicateEffectAnswers(answers("read_only", overrides), true)
      expect(readonly.decision).toBe(normal.decision)
      expect(readonly.source).toBe(normal.source)
    }
  })

  test("missing, extra and cross-variant answers are protocol errors", () => {
    const missingFrozen = answers("read_only")
    delete missingFrozen.floor
    for (const bad of [answers(), missingFrozen, answers("read_only", { extra: { choice: "read_only" } }),
      answers("read_only", { readonly_conformance: { choice: "unknown" } })]) {
      expect(() => parseEffectAnswers(bad, true)).toThrow()
      try {
        parseEffectAnswers(bad, true)
      } catch (error) {
        expect(error).toMatchObject({ kind: "protocol" })
      }
    }
    expect(() => parseEffectAnswers(answers("read_only"))).toThrow()
  })

  test("policy versions and cache core digests cannot mix", () => {
    const network = { family: "AF_INET", target: "127.0.0.1:443" }
    const writableDigest = boundaryCoreDigest({
      kind: "network", operation: "connect", targets: [], network, policyVersion: EFFECTS_POLICY_VERSION,
    })
    const readonlyDigest = boundaryCoreDigest({
      kind: "network", operation: "connect", targets: [], network, policyVersion: EFFECTS_POLICY_VERSION_READONLY,
    })
    expect(readonlyDigest).not.toBe(writableDigest)
    expect(EFFECTS_POLICY_VERSION_READONLY).not.toBe(EFFECTS_POLICY_VERSION)
    const cache = createApprovalCache()
    const scope = { sessionID: "fixture", securitySnapshot: "same", userAuthorizationDigest: "same" }
    const facts = { coreDigest: writableDigest, kind: "network" as const, operation: "connect", targets: [],
      networkEndpoint: { family: "AF_INET" as const, host: "127.0.0.1", port: 443 } }
    cache.store(scope, facts, adjudicateEffectAnswers(answers()))
    expect(cache.lookup(scope, facts)?.decision).toBe("allow")
    expect(cache.lookup(scope, { ...facts, coreDigest: readonlyDigest })).toBeUndefined()
  })

  test("RO transport sends and parses the variant without contacting a network", async () => {
    let body: any
    const fetchFixture = (async (_url: unknown, init: RequestInit) => {
      body = JSON.parse(init.body as string)
      return Response.json({ answers: answers("read_only") })
    }) as unknown as typeof fetch
    const result = await reviewEffects(request, {
      endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", readonly: true, fetch: fetchFixture,
    })
    expect(body.questions.readonly_conformance.type).toBe("choice")
    expect(result).toMatchObject({ decision: "allow", policyVersion: EFFECTS_POLICY_VERSION_READONLY })
  })
})

let root: string
let workspace: string
let scratch: string
let home: string
const oldHome = process.env.HOME
const systemHome = os.homedir()
let homeSpy: { mockRestore(): void }
const scopes: Scope.Closeable[] = []
beforeAll(async () => {
  root = await mkdtemp("/var/tmp/opencode-readonly-review-")
  workspace = path.join(root, "workspace")
  scratch = path.join(root, "scratch")
  home = path.join(root, "home")
  await Promise.all([mkdir(workspace), mkdir(scratch), mkdir(home)])
  process.env.HOME = home
  homeSpy = spyOn(os, "homedir").mockImplementation(() => process.env.HOME ?? systemHome)
})
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
  homeSpy.mockRestore()
  if (oldHome === undefined) delete process.env.HOME
  else process.env.HOME = oldHome
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})

type HostOptions = {
  mode?: "ro" | "auto"
  conformance?: "read_only" | "writes" | "unclear" | "missing"
  failPolicy?: "fail_open" | "fail_close"
  denyWrite?: string[]
  allowWrite?: string[]
  rootReview?: (request: import("../src/security/root-widening").RootWideningInput) => Promise<unknown>
  workspaceNetwork?: "on" | "off"
  securityEnabled?: boolean
  directory?: string
}

// The real plugin wrappers and broker are used, but no sample shell command
// executes. The synthetic host sends authenticated observer events instead.
async function harness(options: HostOptions = {}) {
  // Security state is shared process-wide between plugin instances; each
  // simulated instance here must start from a clean registry.
  resetSharedSecurityStateForTests()
  const hooks = new Map<string, (event: any) => Effect.Effect<any, any>>()
  const tools = new Map<string, any>()
  const commands = new Map<string, any>()
  const calls: EffectReviewRequest[] = []
  const retained = [{ type: "user", text: "Inspect the synthetic fixtures." }]
  let serial = 0
  let executed = 0
  tools.set("shell", {
    id: "shell", name: "shell", options: { codemode: false }, input: { type: "object", properties: {} },
    execute: (input: any, call: any) => Effect.gen(function* () {
      executed++
      const spawn = { command: input.command, cwd: input.workdir ?? workspace, shell: "/bin/bash", env: { ...process.env } }
      yield* hooks.get("shell.create.before")!(spawn)
      const socketPath = /'--broker' '([^']+)'/.exec(spawn.command)?.[1]
      const token = /'--token' '([^']+)'/.exec(spawn.command)?.[1]
      if (!socketPath || !token) throw new Error("Expected an observer-wrapped shell")
      let response: any
      if (input.event) {
        response = yield* Effect.promise(async () => {
          const targets = await Promise.all((input.event.paths ?? []).map(async (target: string) => {
            const object = await lstat(target, { bigint: true }).catch(() => undefined)
            const parent = await lstat(path.dirname(target), { bigint: true }).catch(() => undefined)
            return { path: target, domain: "linux", exists: object !== undefined,
              ...(object ? { dev: String(object.dev), ino: String(object.ino), mode: String(object.mode & 0o7777n) } : {}),
              ...(parent ? { parentDev: String(parent.dev), parentIno: String(parent.ino) } : {}) }
          }))
          const socket = connect(socketPath)
          try {
            await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject) })
            const reply = new Promise<any>((resolve, reject) => {
              socket.once("data", (data) => {
                try { resolve(JSON.parse(data.toString())) } catch (error) { reject(error) }
              })
              socket.once("error", reject)
            })
            socket.write(JSON.stringify({
              version: 1, type: "boundary", token, eventID: 1, pid: process.pid,
              syscall: input.event.syscall ?? "fixture", operation: "open", targets,
              kind: input.event.kind,
               details: { atExit: false, requiresFullApproval: input.event.full === true },
             }) + "\n")
            const response = await reply
            const disconnected = new Promise<void>((resolve) => { socket.once("close", resolve) })
            if (response.action === "deny") {
              // A refusal must survive an observer disconnect without an exit frame.
              socket.destroy()
            } else {
              // Successful synthetic runs follow the real observer's terminal protocol.
              socket.end(JSON.stringify({ version: 1, type: "exit", token, exit: 0 }) + "\n")
            }
            await disconnected
            return response
          } finally {
            socket.destroy()
          }
        })
      }
      return { output: { exit: response?.action === "deny" ? 126 : 0, response, spawn }, content: "fixture", metadata: {} }
    }),
  })
  for (const name of ["write", "edit", "patch"]) tools.set(name, {
    id: name, name, options: { codemode: false }, input: { type: "object", properties: {} },
    execute: () => Effect.sync(() => { executed++; return { output: {}, content: "fixture", metadata: {} } }),
  })
  const ctx: any = {
    options: {
      securityEnabled: options.securityEnabled ?? true,
      failPolicy: options.failPolicy ?? "fail_open",
      sandbox: { enabled: true, mode: "auto", scratch, denyWrite: options.denyWrite ?? [], allowWrite: options.allowWrite ?? [], workspaceNetwork: options.workspaceNetwork ?? "on" },
      slowCommands: false, logReviewerTrace: false, dynamicReview: { jev: { enabled: false } }, permission: { registerTool: false },
      reviewCommand: Object.assign(async (payload: EffectReviewRequest) => {
        calls.push(structuredClone(payload))
        const readonly = payload.input_facts.includes("Session security mode: [Read only]")
        const conformance = options.conformance === "missing" ? undefined : options.conformance ?? "read_only"
        return { answers: answers(readonly ? conformance : undefined) }
      }, { rootWidening: options.rootReview }),
    },
    tool: {
      hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`tool.${name}`, callback) }),
      transform: (callback: any) => Effect.sync(() => callback({
        list: () => [...tools.values()], get: (id: string) => tools.get(id),
        update: (id: string, update: any) => { const next = { ...tools.get(id) }; update(next); tools.set(id, next) },
        add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }),
      })),
    },
    shell: { hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`shell.${name}`, callback) }) },
    permission: { hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`permission.${name}`, callback) }) },
    command: { transform: (callback: any) => Effect.sync(() => callback({ add: (command: any) => commands.set(command.name, command.execute) })) },
    session: {
      get: () => Effect.succeed({ location: { directory: options.directory ?? workspace } }),
      context: () => Effect.succeed(retained),
      synthetic: () => Effect.void,
    },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  const mode = (text: string) => Effect.runPromise(commands.get("perm")({ sessionID: "readonly-fixture", prompt: { text } }))
  if (options.mode !== "auto") await mode("ro")
  return {
    calls, mode, get executed() { return executed },
    newUserMessage: (text: string) => { retained.push({ type: "user", text }) },
    run: (command: string, event?: { kind: RuntimeBoundaryEvent["kind"]; full?: boolean; paths?: string[]; syscall?: string }, workdir?: string) =>
      Effect.runPromise(tools.get("shell").execute({ command, event, workdir }, { sessionID: "readonly-fixture", messageID: "m", id: `call-${++serial}`, agent: "build" })) as Promise<any>,
    file: (name: string, input: unknown) => Effect.runPromise(tools.get(name).execute(input, {
      sessionID: "readonly-fixture", messageID: "m", id: `call-${++serial}`, agent: "build",
    })),
  }
}

const classify = (script: string) => classifyShellCommand({
  script, cwd: workspace, worktree: workspace, shell: "/bin/bash", strictness: "LOOSE",
  permScope: { r: true, w: false, x: true }, roWritableRoots: [scratch], sandboxDenyWrite: [workspace],
})

describe("RO launch gate", () => {
  test("a credential read is admitted to the observer and then reviewed", async () => {
    const classified = await classify("cat /etc/shadow")
    expect(classified.rules).toContain("credentials.sensitive-access")
    expect(classified.rules).not.toContain("permission.write")
    expect(classified.rules.some(isFloorRule)).toBe(false)
    const host = await harness()
    const result = await host.run("cat /etc/shadow", { kind: "read" })
    expect(host.executed).toBe(1)
    expect(host.calls).toHaveLength(1)
    expect(result.output.response.action).toBe("continue")
  })

  test("sqlite and Python imports are unproven, not refused at launch", async () => {
    const host = await harness()
    for (const command of ["sqlite3 db 'select 1'", "python3 -c 'import json'"]) {
      const result = await classify(command)
      expect(result.verdict).toBe("ASK")
      expect(result.rules).toContain("permission.exec-unproven")
      await host.run(command)
    }
    expect(host.executed).toBe(2)
    expect(host.calls).toHaveLength(0)
  })

  test("proven writes, process changes and remote mutations never call the reviewer", async () => {
    const host = await harness()
    for (const command of [
      "echo x > ordinary.txt", "rm ordinary.txt", "mv a b", "cp a b", "sed -i 's/a/b/' ordinary.txt",
      "git commit -m fixture", "git push origin", "npm install fixture", "kill 1234", "pkill fixture",
      "curl -X POST https://fixture.invalid/", "curl --data=x https://fixture.invalid/",
      "curl -dx https://fixture.invalid/", "curl -G -F x=y https://fixture.invalid/",
    ]) {
      const result = await classify(command)
      expect(result.verdict).toBe("DENY")
      expect(result.rules).toContain("permission.write")
      await expect(host.run(command)).rejects.toThrow()
    }
    expect(host.executed).toBe(0)
    expect(host.calls).toHaveLength(0)
  })

  test("floor rules remain a launch refusal", async () => {
    const command = ":(){ :|:& };:"
    const decision = await classify(command)
    expect(decision.verdict).toBe("DENY")
    expect(decision.rules.some(isFloorRule)).toBe(true)
    const host = await harness()
    await expect(host.run(command)).rejects.toThrow()
    expect(host.executed).toBe(0)
    expect(host.calls).toHaveLength(0)
  })

  test("curl GET data conversion is independent of flag order", async () => {
    for (const command of ["curl -G -d x=y https://fixture.invalid/", "curl -d x=y -G https://fixture.invalid/"]) {
      expect((await classify(command)).verdict).not.toBe("DENY")
    }
    expect((await classify("curl --request-target /resource https://fixture.invalid/")).verdict).not.toBe("DENY")
  })

  test("native writes allow temp-only targets but refuse workspace and mixed patches", async () => {
    const host = await harness()
    await host.file("write", { path: path.join(scratch, "file"), content: "x" })
    await host.file("edit", { path: path.join(scratch, "file"), oldString: "x", newString: "y" })
    await host.file("patch", { patchText: `*** Begin Patch\n*** Add File: ${scratch}/file\n+x\n*** End Patch` })
    await expect(host.file("write", { path: path.join(workspace, "file"), content: "x" })).rejects.toThrow("[Read only]")
    await expect(host.file("patch", { patchText: `*** Begin Patch\n*** Add File: ${scratch}/file\n+x\n*** Add File: ${workspace}/file\n+x\n*** End Patch` })).rejects.toThrow("[Read only]")
    expect(host.executed).toBe(3)
    expect(host.calls).toHaveLength(0)
  })

  test("plugin development is scoped to its workspace and keeps the observer protected", async () => {
    const packageRoot = path.resolve(import.meta.dir, "..")
    const target = path.join(packageRoot, "README.md")
    const unrelated = await harness({ mode: "auto" })
    await expect(unrelated.file("write", { path: target, content: "fixture" })).rejects.toThrow("protected")
    const developer = await harness({ mode: "auto", directory: packageRoot })
    // Synthetic executors never change the real source or observer image.
    await developer.file("write", { path: target, content: "fixture" })
    await expect(developer.file("write", { path: path.join(packageRoot, "bin/opencode-boundary-watch"), content: "fixture" })).rejects.toThrow("protected")
    const result = await developer.run("true")
    expect(result.output.spawn.command).not.toContain(`'--protect' '${packageRoot}'`)
    expect(developer.calls).toHaveLength(0)
  })

  test("writes under /tmp continue in Auto mode, including destructive writes", async () => {
    const host = await harness({ mode: "auto" })
    const paths = ["/tmp/opencode"]
    const mkdir = await host.run("true", { kind: "write", syscall: "mkdirat", paths })
    expect(mkdir.output.response.action).toBe("continue")
    const rmdir = await host.run("true", { kind: "write", syscall: "rmdir", paths })
    expect(rmdir.output.response.action).toBe("continue")
    expect(host.calls).toHaveLength(0)
  })

  test("launch proof uses the shell workdir rather than the session workspace", async () => {
    const host = await harness()
    await host.run("touch workdir-fixture", undefined, scratch)
    expect(host.executed).toBe(1)
    expect(host.calls).toHaveLength(0)
  })
})

describe("RO observer routing through the plugin", () => {
  test("allowWrite becomes an observer root and exempts safe writes in Auto and Read only", async () => {
    const allowed = path.join(home, "configured-logs")
    await mkdir(allowed)
    for (const mode of ["auto", "ro"] as const) {
      const host = await harness({ mode, allowWrite: [allowed] })
      const result = await host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/plain.log`] })
      expect(result.output.spawn.command).toContain(`'--root' '${allowed}'`)
      expect(result.output.response.action).toBe("continue")
      expect(host.calls).toHaveLength(0)
      const sensitive = host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/private.key`] })
      if (mode === "ro") {
        await expect(sensitive).rejects.toMatchObject({
          _tag: "Tool.Error", message: expect.stringContaining("Read-only limit:"),
        })
      } else {
        expect((await sensitive).output.response.action).toBe("allow")
        const request = host.calls[0]
        const observed = JSON.parse(request.input_facts.find((fact) => fact.startsWith("Observed boundary facts"))!.split(": ").slice(1).join(": "))
        expect(observed.targets[0]).toMatchObject({ path: `${allowed}/private.key`, exists: false })
        for (const field of ["dev", "ino", "parentDev", "parentIno", "mtimeNs", "ctimeNs"]) {
          expect(observed.targets[0]).not.toHaveProperty(field)
        }
        expect(observed.details).not.toHaveProperty("argvDigest")
        expect(request.input_facts.join("\n")).not.toContain("Executing image identity")
        expect(request.input_facts.join("\n")).not.toContain("Current boundary object metadata")
        expect(request.files).toEqual([])
        expect(request.session_context).not.toContain("user: Inspect the synthetic fixtures.")
      }
      expect(host.calls).toHaveLength(mode === "ro" ? 0 : 1)
    }
  })

  test("three allowed crossings (including L2) start a background grant used by new calls and the broker", async () => {
    const allowed = path.join(home, "l3-logs")
    await mkdir(allowed)
    const requests: import("../src/security/root-widening").RootWideningInput[] = []
    let requested!: () => void
    const started = new Promise<void>((resolve) => { requested = resolve })
    let granted!: () => void
    const completed = new Promise<void>((resolve) => { granted = resolve })
    const rootReview = Object.assign(async (input: import("../src/security/root-widening").RootWideningInput) => {
      requests.push(input)
      requested()
      return { answers: { widen_root: { choice: "root_1" } } }
    }, { trace: (entry: import("../src/security/root-widening").L3Trace) => { if (entry.kind === "l3_root_granted") granted() } })
    const host = await harness({ mode: "auto", rootReview })
    for (let index = 0; index < 3; index++) {
      const result = await host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/plain.log`] })
      expect(result.output.response.action).not.toBe("deny")
    }
    await started
    expect(host.calls).toHaveLength(1)
    expect(requests).toHaveLength(1)
    expect(requests[0].repeated_directory).toBe(allowed)
    await completed
    const result = await host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/new.log`] })
    expect(result.output.spawn.command).toContain(`'--root' '${allowed}'`)
    expect(result.output.response.action).toBe("continue")
    expect(host.calls).toHaveLength(1)
    host.newUserMessage("A different inspection task.")
    const expired = await host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/after-message.log`] })
    expect(expired.output.spawn.command).not.toContain(`'--root' '${allowed}'`)
    expect(host.calls).toHaveLength(2)
  })

  test("L3 failure leaves allowed commands runnable and Read only never invokes L3", async () => {
    const allowed = path.join(home, "l3-errors")
    await mkdir(allowed)
    let calls = 0
    let requested!: () => void
    const started = new Promise<void>((resolve) => { requested = resolve })
    const host = await harness({ mode: "auto", rootReview: async () => { calls++; requested(); throw new Error("fake provider failure") } })
    for (let index = 0; index < 3; index++) {
      const result = await host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/file-${index}.log`] })
      expect(result.output.response.action).toBe("allow")
    }
    await started
    expect(calls).toBe(1)
    await host.mode("ro")
    await expect(host.run("python3 -c 'import json'", { kind: "write", paths: [`${allowed}/readonly.log`] })).rejects.toMatchObject({
      _tag: "Tool.Error", message: expect.stringContaining("Read-only limit:"),
    })
    expect(calls).toBe(1)
  })

  test("non-exempt writes and privilege events refuse without review", async () => {
    for (const kind of ["write", "privilege"] as const) {
      const host = await harness()
      await expect(host.run("python3 -c 'import json'", { kind, full: kind === "privilege" })).rejects.toMatchObject({
        _tag: "Tool.Error", message: expect.stringContaining("Read-only limit:"),
      })
      expect(host.calls).toHaveLength(0)
    }
  })

  test("read/network continue; interop/opaque full approvals detach", async () => {
    for (const kind of ["read", "network", "interop", "opaque"] as const) {
      const host = await harness({ workspaceNetwork: "on" })
      const full = kind === "interop" || kind === "opaque"
      const result = await host.run("python3 -c 'import json'", { kind, full })
      expect(host.calls).toHaveLength(1)
      expect(host.calls[0].input_facts).toContain("Session security mode: [Read only]")
      expect(result.output.response.action).toBe(full ? "allow" : "continue")
    }
  })

  test("only an RO whole-command ALLOW can statically continue a read/network", async () => {
    const host = await harness()
    for (const kind of ["read", "network"] as const) {
      const result = await host.run("printf hello", { kind })
      expect(result.output.response.action).toBe("continue")
    }
    expect(host.calls).toHaveLength(0)
  })

  test("writes, unclear and missing conformance answers fail closed in the host", async () => {
    for (const conformance of ["writes", "unclear", "missing"] as const) {
      const host = await harness({ conformance, failPolicy: "fail_close" })
      await expect(host.run("python3 -c 'import json'", { kind: "network" })).rejects.toMatchObject({
        _tag: "Tool.Error",
        message: expect.stringContaining(conformance === "missing" ? "Check unavailable (review_protocol)" : "Command review — read-only"),
      })
      expect(host.calls).toHaveLength(1)
    }
  })
  test("fail_open passes a missing RO answer, not an adjudicated RO denial", async () => {
    const host = await harness({ conformance: "missing", failPolicy: "fail_open" })
    const result = await host.run("python3 -c 'import json'", { kind: "network" })
    expect(result.output.response.action).toBe("allow")
    expect(result.output.response.reason).toBeUndefined()
    expect(result.content).not.toMatch(/blocked|cannot|could not/i)
    expect(result.metadata.boundary.runtimeBlocked).toBeUndefined()
  })

  test("mode changes cannot reuse the write-mode approval for RO", async () => {
    const host = await harness({ mode: "auto" })
    await host.run("python3 -c 'import json'", { kind: "read" })
    await host.mode("ro")
    await host.run("python3 -c 'import json'", { kind: "read" })
    expect(host.calls).toHaveLength(2)
    expect(host.calls[0].input_facts).not.toContain("Session security mode: [Read only]")
    expect(host.calls[1].input_facts).toContain("Session security mode: [Read only]")
  })

  test("disabled review layers do not waive RO conformance before detaching", async () => {
    const host = await harness({ securityEnabled: false, conformance: "writes" })
    await expect(host.run("python3 -c 'import json'", { kind: "opaque", full: true })).rejects.toMatchObject({
      _tag: "Tool.Error", message: expect.stringContaining("Command review — read-only limit:"),
    })
    expect(host.calls).toHaveLength(1)
  })

  test("incidental components and history roots skip review in both modes", async () => {
    for (const mode of ["auto", "ro"] as const) {
      const host = await harness({ mode })
      // Name-matched components are exempted by the broker.
      for (const target of [
        path.join(root, "incidental/__pycache__/module.pyc"), path.join(root, "incidental/.pytest_cache/state"),
      ]) {
        const result = await host.run("python3 -c 'import json'", { kind: "write", paths: [target] })
        expect(result.output.response.action).toBe("continue")
      }
      expect(host.calls).toHaveLength(0)
      // Cache/history files are observer write roots (incidentalWriteRoots,
      // covered in incidental-writes.test.ts), so no event is raised for
      // them. This fixture overrides HOME, which the sensitivity filter
      // reads, so the real-home roots are not asserted here.
    }
  })

  test("denyWrite, control-plane protect and credentials override incidental exemptions", async () => {
    for (const mode of ["auto", "ro"] as const) {
      const deniedRoot = path.join(root, "denied")
      // Missing synthetic parent directories are intentional evidence gaps;
      // keep the review strict here to distinguish them from exemptions.
      const host = await harness({ mode, denyWrite: [deniedRoot], failPolicy: "fail_close" })
      for (const target of [
        path.join(deniedRoot, ".pytest_cache/state"),
        path.resolve(import.meta.dir, "../.pytest_cache/state"),
        path.join(home, ".aws/.pytest_cache/state"),
        path.join(home, ".cache/private.key"),
      ]) {
        const before = host.calls.length
        const result = host.run("python3 -c 'import json'", { kind: "write", paths: [target] })
        // Configured/protected roots and the isolated HOME's actual credential
        // stores are hard refusals; sensitive cache leaves still need review.
        const configuredOrProtected = target.startsWith(`${deniedRoot}/`) || target.startsWith(`${home}/.aws/`) ||
          target === path.resolve(import.meta.dir, "../.pytest_cache/state")
        if (mode === "ro" || configuredOrProtected) {
          await expect(result).rejects.toMatchObject({
            _tag: "Tool.Error", message: expect.stringContaining(mode === "ro" ? "Read-only limit:" : "Write protection:"),
          })
          expect(host.calls.length).toBe(before)
        } else {
          expect((await result).output.response.action).toBe("allow")
          expect(host.calls.length).toBe(before + 1)
        }
      }
    }
  })
})

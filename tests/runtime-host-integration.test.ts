import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test"
import { execFile, spawn as spawnProcess } from "node:child_process"
import { chmod, mkdtemp, mkdir, readFile, readdir, rename, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import * as os from "node:os"
import * as filesystem from "node:fs/promises"
import * as classifier from "../src/security/classifier"
import * as cache from "../src/security/approval-cache"
import { DEFAULT_BOUNDARY_WATCH_HELPER } from "../src/sandbox"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import frozen from "../src/security/v11-gold-prompt.json"
import { adjudicateEffectAnswers, EffectsReviewError, type EffectReviewRequest } from "../src/security/effects-reviewer"
import { resetSharedSecurityStateForTests } from "../src/security/shared-state"
import * as writeRootPolicy from "../src/security/write-root-policy"
import { createRuntimeBoundaryBroker } from "../src/runtime-boundary"
import { NO_REROUTE } from "../src/agent-messages"
import { cleanupTestArtifacts } from "./artifacts"

let root: string, workspace: string, outside: string, scratch: string, probe: string
const oldHome = process.env.HOME
const systemHome = os.homedir()
let homeSpy: { mockRestore(): void }
let brokerBaseSpy: { mockRestore(): void }
const scopes: Scope.Closeable[] = []
beforeAll(async () => {
  // Keep non-temp permission fixtures outside the unconditional /tmp grant.
  root = await mkdtemp("/var/tmp/opencode-runtime-host-")
  workspace = path.join(root, "workspace")
  outside = path.join(root, "outside")
  scratch = path.join(root, "scratch")
  const home = path.join(root, "home")
  await Promise.all([mkdir(workspace), mkdir(outside), mkdir(scratch), mkdir(home)])
  // Keep the root-external fixtures outside adopted temp roots: a root that
  // covers this isolated HOME is intentionally never an automatic grant.
  process.env.HOME = home
  homeSpy = spyOn(os, "homedir").mockImplementation(() => process.env.HOME ?? systemHome)
  brokerBaseSpy = spyOn(writeRootPolicy, "runtimeBrokerBase").mockReturnValue(path.join(home, ".opencode", "run"))
  probe = path.join(root, "probe-fixture")
  await writeFile(probe, "#!/bin/sh\nprintf 'bwrap: /usr/bin/bwrap\\nuserns: yes\\nlandlock_abi: 7\\nsandbox_path: full\\n'\n", { mode: 0o700 })
})
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
  homeSpy.mockRestore()
  brokerBaseSpy.mockRestore()
  if (oldHome === undefined) delete process.env.HOME
  else process.env.HOME = oldHome
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})
const quote = (text: string) => `'${text.replaceAll("'", "'\\''")}'`
const python = (code: string) => `python3 -c ${quote(code)}`
/** Host-deadline simulation: the observer's payload calls setpgid(0, 0), so a
 *  single `kill(-shellPid)` leaves it running. Walk /proc and SIGKILL every
 *  descendant (groups first, then the root) like a host process-tree kill. */
async function killProcessTree(rootPid: number): Promise<void> {
  const processes = new Map<number, { ppid: number; pgrp: number }>()
  for (const entry of await readdir("/proc").catch(() => [] as string[])) {
    if (!/^\d+$/.test(entry)) continue
    const stat = await readFile(`/proc/${entry}/stat`, "utf8").catch(() => "")
    const close = stat.lastIndexOf(")")
    if (close < 0) continue
    const fields = stat.slice(close + 2).trim().split(/\s+/)
    const ppid = Number(fields[1]), pgrp = Number(fields[2])
    if (Number.isSafeInteger(ppid) && Number.isSafeInteger(pgrp)) processes.set(Number(entry), { ppid, pgrp })
  }
  const targets: number[] = []
  const collect = (pid: number) => {
    for (const [child, info] of processes) {
      if (info.ppid !== pid || targets.includes(child)) continue
      targets.push(child)
      collect(child)
    }
  }
  collect(rootPid)
  const signal = (pid: number) => {
    const group = processes.get(pid)?.pgrp === pid
    try { if (group) process.kill(-pid, "SIGKILL") } catch { /* already gone */ }
    try { process.kill(pid, "SIGKILL") } catch { /* already gone */ }
  }
  for (const pid of targets.reverse()) signal(pid)
  signal(rootPid)
}
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

async function harness(deny = false, options: {
  failPolicy?: "fail_open" | "fail_close"
  review?: (request: EffectReviewRequest) => Promise<any>
  sessionFailure?: boolean
  contextFailure?: boolean
  missingContext?: boolean
  directory?: string
  denyWrite?: string[]
  allowWrite?: string[]
  onSpawn?: () => void
  failContextRead?: number
  slowCommands?: boolean
  logReviewerTrace?: boolean
  trustedCommands?: string[]
  onOutput?: (stdout: string, stderr: string) => void
  /** Simulate the host command deadline: kill the detached process tree and
   *  return the documented result shape (`output.timeout` + `metadata.timeout`)
   *  instead of failing the tool call. */
  hostTimeoutMs?: number
} = {}) {
  // Security state is shared process-wide between plugin instances; each
  // simulated instance here must start from a clean registry.
  resetSharedSecurityStateForTests()
  const hooks = new Map<string, (event: any) => Effect.Effect<any, any>>()
  const commands = new Map<string, any>()
  const calls: EffectReviewRequest[] = []
  const notifications: any[] = []
  const processOutputs: Array<{ stdout: string; stderr: string }> = []
  const retained = [{ type: "user", text: "Operate on the named fixture files and directories for this acceptance test." }]
  const tools = new Map<string, any>()
  let executed = 0, serial = 0, contextReads = 0
  for (const name of ["shell", "write"]) tools.set(name, {
    id: name, name, options: { codemode: false }, input: { type: "object", properties: {} },
    execute: (input: any, call: any) => Effect.gen(function* () {
      const permission = { sessionID: call.sessionID, action: name === "write" ? "edit" : "shell", resources: [name === "write" ? input.path : "*"],
        source: { type: "tool", messageID: call.messageID, id: call.id }, effect: "ask" }
      yield* hooks.get("permission.evaluate")!(permission)
      if (permission.effect === "deny") return yield* Effect.fail(new Error((permission as any).message))
      executed++
      if (name === "write") {
        yield* Effect.promise(() => writeFile(input.path, input.content))
        return { output: {}, content: "written", metadata: {} }
      }
      const spawn = { command: input.command, cwd: input.workdir ?? workspace, shell: "/bin/bash", env: { ...process.env, ...input.env } }
      yield* hooks.get("shell.create.before")!(spawn)
      const hostTimeoutMs = options.hostTimeoutMs
      if (!input.background && hostTimeoutMs !== undefined) {
        const child = spawnProcess(spawn.shell, ["-c", spawn.command], {
          cwd: spawn.cwd, env: spawn.env, detached: true, stdio: ["ignore", "pipe", "pipe"],
        })
        let stdout = "", stderr = "", timedOut = false
        child.stdout?.on("data", (chunk: Buffer) => { stdout += chunk.toString() })
        child.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString() })
        let timer: ReturnType<typeof setTimeout> | undefined
        child.once("spawn", () => {
          options.onSpawn?.()
          timer = setTimeout(() => {
            timedOut = true
            // The host kills the whole shell tree at its deadline. The
            // observer's payload runs in its own process group, so walk the
            // live tree; its socket closes without a terminal exit frame.
            if (child.pid !== undefined) void killProcessTree(child.pid)
            else child.kill("SIGKILL")
          }, hostTimeoutMs)
        })
        const output = yield* Effect.promise(() => new Promise<{ output: string; exit: number; timeout?: boolean }>((resolve) => {
          let settled = false
          const finish = (code: number | null) => {
            if (settled) return
            settled = true
            if (timer !== undefined) clearTimeout(timer)
            processOutputs.push({ stdout, stderr })
            options.onOutput?.(stdout, stderr)
            const result = { output: stdout + stderr, exit: timedOut ? 124 : code ?? 1, ...(timedOut ? { timeout: true } : {}) }
            // Let the broker observe the killed observer's socket close before
            // the host reports its timeout result.
            setTimeout(() => resolve(result), timedOut ? 200 : 0)
          }
          child.once("close", finish)
          child.once("error", () => finish(1))
        }))
        return { output, content: output.output, metadata: timedOut ? { timeout: true, exit: output.exit } : {} }
      }
      const output = yield* Effect.promise((signal) => new Promise<{ output: string; exit: number; status?: string }>((resolve) => {
        if (input.background) {
          // Host shape: background=true returns status:"running" at once and
          // keeps the process alive; the exit frame arrives over the broker.
          execFile(spawn.shell === "/bin/sh" ? "/bin/sh" : "/bin/bash",
            ["-c", spawn.command],
            { cwd: spawn.cwd, env: spawn.env, timeout: 15_000 },
            (_error, stdout, stderr) => {
              processOutputs.push({ stdout, stderr })
              options.onOutput?.(stdout, stderr)
            })
          resolve({ output: "", exit: 0, status: "running" })
          return
        }
        // Honor spawn.shell: the host resolves the shell before the hook
        // and spawns invocation.shell — the watcher wrap may switch it.
        const child = execFile(spawn.shell, ["-c", spawn.command], { cwd: spawn.cwd, env: spawn.env, signal, timeout: 15_000, maxBuffer: 1024 * 1024 },
          (error, stdout, stderr) => {
            processOutputs.push({ stdout, stderr })
            options.onOutput?.(stdout, stderr)
            resolve({ output: stdout + stderr, exit: typeof error?.code === "number" ? error.code : error ? 1 : 0 })
          })
        child.once("spawn", () => options.onSpawn?.())
      }))
      return { output, content: output.output, metadata: {} }
    }),
  })
  const ctx: any = {
    options: { sandbox: { enabled: true, mode: "auto", scratch, helperPath: probe }, slowCommands: options.slowCommands ?? false, logReviewerTrace: options.logReviewerTrace ?? false,
      failPolicy: options.failPolicy ?? "fail_open",
      trustedCommands: options.trustedCommands ?? [],
      dynamicReview: { jev: { enabled: false } }, permission: { registerTool: false },
      reviewCommand: async (request: EffectReviewRequest) => {
        calls.push(structuredClone(request))
        if (options.review) return options.review(request)
        return report(deny, request.input_facts.includes("Session security mode: [Read only]"))
      } },
    tool: {
      hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`tool.${name}`, callback) }),
      transform: (callback: any) => Effect.sync(() => callback({ list: () => [...tools.values()], get: (id: string) => tools.get(id),
        update: (id: string, update: any) => { const current = tools.get(id); if (!current) return; const next = { ...current }; update(next); tools.set(id, next) },
        add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }) })),
    },
    shell: { hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`shell.${name}`, callback) }) },
    permission: { hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`permission.${name}`, callback) }) },
    command: { transform: (callback: any) => Effect.sync(() => callback({ add: (command: any) => commands.set(command.name, command.execute) })) },
    session: { get: () => Effect.succeed({ location: { directory: workspace } }), context: () => Effect.succeed(retained),
      hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`session.${name}`, callback) }),
      synthetic: (input: any) => Effect.sync(() => { notifications.push(structuredClone(input)) }) },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  if (options.denyWrite) ctx.options.sandbox.denyWrite = options.denyWrite
  if (options.allowWrite) ctx.options.sandbox.allowWrite = options.allowWrite
  if (options.sessionFailure) ctx.session.get = () => Effect.fail(new Error("synthetic session lookup failure"))
  else if (options.directory) ctx.session.get = () => Effect.succeed({ location: { directory: options.directory } })
  if (options.contextFailure) ctx.session.context = () => Effect.fail(new Error("synthetic context lookup failure"))
  else if (options.failContextRead) ctx.session.context = () => Effect.sync(() => {
    contextReads++
    if (contextReads === options.failContextRead) throw new Error("synthetic late context failure")
    return retained
  })
  if (options.missingContext) delete ctx.session.context
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  return {
    calls, notifications, processOutputs, get executed() { return executed },
    run: (name: string, input: unknown) => Effect.runPromise(tools.get(name).execute(input, { sessionID: "acceptance", messageID: "m", id: `call-${++serial}`, agent: "build" })) as Promise<any>,
    failure: async (name: string, input: unknown) => {
      const effect = tools.get(name).execute(input, { sessionID: "acceptance", messageID: "m", id: `call-${++serial}`, agent: "build" })
      const exit = await Effect.runPromise(Effect.exit(effect))
      if (!Exit.isFailure(exit)) throw new Error("Expected a tool refusal")
      const found = Cause.findErrorOption(exit.cause)
      return Option.isSome(found) ? found.value as any : undefined
    },
    command: (text: string) => Effect.runPromise(commands.get("perm")({ sessionID: "acceptance", prompt: { text } })),
    newUserMessage: (text: string) => { retained.push({ type: "user", text }) },
    modelContext: async () => {
      const event = { sessionID: "acceptance", messages: [] as any[] }
      await Effect.runPromise(hooks.get("session.context")!(event))
      return event.messages
    },
    after: async (result: Record<string, unknown>) => {
      const event = { tool: "read", sessionID: "acceptance", agent: "build", messageID: "m", id: `after-${++serial}`,
        input: {}, status: "completed", result }
      await Effect.runPromise(hooks.get("tool.execute.after")!(event))
      return event.result
    },
  }
}

describe("real observer → broker → frozen reviewer → original process", () => {
  test("trustedCommands runtime bypass covers only trusted-only launches and keeps permission floors", async () => {
    const toolsDirectory = path.join(workspace, "trusted-bin")
    await mkdir(toolsDirectory)
    const fixture = [
      "#!/usr/bin/python3",
      "import ctypes, os, socket, subprocess, sys",
      "print('trusted-start', flush=True)",
      "open(os.environ['TRUSTED_TEST_TARGET'], 'w').write('trusted')",
      "subprocess.check_call([sys.executable, '-c', \"import os; open(os.environ['TRUSTED_TEST_CHILD'], 'w').write('child')\"])",
      "try:",
      "    socket.create_connection(('127.0.0.1', 9), 1).close()",
      "except OSError:",
      "    pass",
      "if os.environ.get('TRUSTED_TEST_FULL') == '1':",
      "    ctypes.CDLL(None).syscall(426, -1, 0, 0, 0, 0) # io_uring_enter: invalid fd, no effect",
      "print('trusted-done')",
      "",
    ].join("\n")
    for (const name of ["opencode", "ask-gemini", "agent-browser", "google-chrome"]) {
      await writeFile(path.join(toolsDirectory, name), fixture, { mode: 0o700 })
    }
    const trustedCommands = ["opencode", "ask-gemini", "agent-browser open *", "google-chrome --headless *"]
    const environment = (name: string) => ({
      PATH: `${toolsDirectory}:${process.env.PATH}`,
      // The host's BASH_ENV can reset PATH and launch the real installed CLI
      // instead of these fixtures. Keep this acceptance test self-contained.
      BASH_ENV: "",
      ENV: "",
      TRUSTED_TEST_TARGET: path.join(outside, `trusted-${name}.log`),
      TRUSTED_TEST_CHILD: path.join(outside, `trusted-${name}-child.log`),
    })
    // Context lookup would fail if this path accidentally entered review.
    const trusted = await harness(true, { trustedCommands, contextFailure: true })
    for (const [name, command] of [
      ["opencode", 'opencode run --session ses_fixture "prompt" 2>&1'],
      ["gemini", 'ask-gemini "prompt; this is data"'],
      ["browser", "agent-browser open https://example.invalid"],
      ["chrome", "google-chrome --headless"],
    ]) {
      const env = environment(name!)
      const result = await trusted.run("shell", { command, env }).catch((error) => {
        throw new Error(`Trusted CLI ${name} failed; captured output: ${JSON.stringify(trusted.processOutputs.at(-1))}`, { cause: error })
      })
      expect(result.output.exit).toBe(0)
      expect(result.content).toContain("trusted-done")
      expect(result.metadata.boundary.source).toBe("runtime_trusted_command")
      expect(await readFile(env.TRUSTED_TEST_TARGET, "utf8")).toBe("trusted")
      expect(await readFile(env.TRUSTED_TEST_CHILD, "utf8")).toBe("child")
    }
    const full = await trusted.run("shell", {
      command: "google-chrome --headless about:blank",
      env: { ...environment("full"), TRUSTED_TEST_FULL: "1" },
    })
    expect(full.output.exit).toBe(0)
    expect(full.content).toContain("trusted-done")
    expect(trusted.calls).toHaveLength(0)

    const redirect = path.join(outside, "trusted-shell-redirect.log")
    const additionalWrite = python(`open(${JSON.stringify(path.join(outside, "trusted-sibling.log"))}, 'w').write('other')`)
    const untrustedCommands = [
      `opencode api get /api/info > ${quote(redirect)}`,
      `ask-gemini prompt; ${additionalWrite}`,
      "agent-browser close session",
      "./trusted-bin/opencode run prompt",
      `opencode "$(printf prompt)"`,
      `opencode "$(opencode prompt)"`,
      `PATH=${quote(toolsDirectory)}; opencode run prompt`,
    ]
    for (const [index, command] of untrustedCommands.entries()) {
      const host = await harness(true, { trustedCommands })
      await host.failure("shell", { command, env: environment(`untrusted-${index}`) })
      expect(host.calls).toHaveLength(1)
    }
    await expect(readFile(redirect)).rejects.toMatchObject({ code: "ENOENT" })

    const readonly = await harness(true, { trustedCommands })
    await readonly.command("ro")
    const readonlyEnv = environment("readonly")
    expect((await readonly.failure("shell", { command: "opencode run prompt", env: readonlyEnv })).message).toContain("Read-only limit")
    expect(readonly.calls).toHaveLength(0)
    await expect(readFile(readonlyEnv.TRUSTED_TEST_TARGET)).rejects.toMatchObject({ code: "ENOENT" })

    const deniedEnv = environment("denied")
    const denied = await harness(true, { trustedCommands, denyWrite: [deniedEnv.TRUSTED_TEST_TARGET] })
    expect((await denied.failure("shell", { command: "opencode run prompt", env: deniedEnv })).message).toContain("Write protection")
    expect(denied.calls).toHaveLength(0)
    await expect(readFile(deniedEnv.TRUSTED_TEST_TARGET)).rejects.toMatchObject({ code: "ENOENT" })
  }, 30_000)

  test("first review inlines executable bodies, protects sensitive aliases and redacts expanded argv", async () => {
    const literalToken = "fixture-literal-token-123456"
    for (const kind of ["ordinary", "sensitive-alias", "build-wrapper"] as const) {
      const host = await harness()
      const scriptName = kind === "build-wrapper" ? "gradlew" : `${kind}.py`
      const script = path.join(workspace, scriptName)
      const source = kind === "sensitive-alias" ? path.join(workspace, ".env.payload") : script
      const target = path.join(outside, `preinline-${kind}.txt`)
      const marker = `payload-body-${kind}`
      await writeFile(source, `# ${marker}\nopen(${JSON.stringify(target)}, 'w').write('fixture')\n`)
      if (source !== script) await symlink(source, script)
      const result = await host.run("shell", {
        command: `python3 ${quote(script)} --token "$BOUNDARY_TEST_TOKEN"`,
        env: { BOUNDARY_TEST_TOKEN: literalToken },
      })
      expect(result.output.exit).toBe(0)
      expect(host.calls).toHaveLength(1)
      const request = host.calls[0]
      const facts = request.input_facts.join("\n")
      expect(facts).not.toContain(literalToken)
      const observed = JSON.parse(request.input_facts.find((fact) => fact.startsWith("Observed boundary facts"))!.split(": ").slice(1).join(": "))
      expect(observed.details.argv).toContain("[redacted]")
      expect(observed.details).not.toHaveProperty("argvDigest")
      expect(observed.targets[0]).not.toHaveProperty("dev")
      expect(observed.targets[0]).not.toHaveProperty("ino")
      expect(observed.targets[0]).not.toHaveProperty("parentDev")
      expect(observed.targets[0]).not.toHaveProperty("parentIno")
      expect(observed.targets[0]).not.toHaveProperty("mtimeNs")
      expect(observed.targets[0]).not.toHaveProperty("ctimeNs")
      expect(observed.targets[0]).toHaveProperty("exists")
      expect(request.input_facts.join("\n")).not.toContain("Executing image identity")
      expect(request.files.some((file) => file.kind === "observed_boundary_target")).toBe(false)
      if (kind === "ordinary") {
        expect(facts).toContain(marker)
        expect(request.files.some((file) => file.kind === "local_executable_payload" && file.path === script)).toBe(true)
      } else {
        expect(facts).not.toContain(marker)
        expect(request.files.some((file) => file.kind === "local_executable_payload")).toBe(false)
      }
    }
  })

  test("expanded argv redacts every secret value and entire URL userinfo", async () => {
    const host = await harness()
    const script = path.join(scratch, "literal-argv-redaction.py")
    const target = path.join(outside, "literal-argv-redaction.txt")
    await writeFile(script, `open(${JSON.stringify(target)}, 'w').write('fixture')\n`)
    const shellArguments = [
      quote("API_KEY=abc123"), quote("--password=abc%12345"), "--token", quote("/abcdef123456"),
      quote("https://opaque-token@example.com/"), quote("https://opaque-token:password@example.com/"),
      "--client-secret", quote("a$%`"), quote("TOKEN="),
    ]
    const result = await host.run("shell", { command: `python3 ${quote(script)} ${shellArguments.join(" ")}` })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    const request = host.calls[0]
    const observed = JSON.parse(request.input_facts.find((fact) => fact.startsWith("Observed boundary facts"))!.split(": ").slice(1).join(": "))
    expect(observed.details.argv.slice(2)).toEqual([
      "API_KEY=[redacted]", "--password=[redacted]", "--token", "[redacted]",
      "https://[redacted]@example.com/", "https://[redacted]@example.com/",
      "--client-secret", "[redacted]", "TOKEN=[redacted]",
    ])
    const reviewed = JSON.stringify(request)
    for (const secret of ["abc123", "abc%12345", "/abcdef123456", "opaque-token", "a$%`"]) {
      expect(reviewed).not.toContain(secret)
    }
  })

  test("quoted whitespace secrets are redacted in reviewer command and JSON facts", async () => {
    const host = await harness()
    const script = path.join(workspace, "quoted-secret-command.py")
    const target = path.join(outside, "quoted-secret-command.txt")
    await writeFile(script, `# program --password 'two words'\n# TOKEN="two words" program\nopen(${JSON.stringify(target)}, 'w').write('fixture')\n`)
    const command = `TOKEN="two words" API_KEY="my secret key" python3 ${quote(script)} --password 'two words' --token="two words"`
    const result = await host.run("shell", { command })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    const request = host.calls[0]
    expect(request.command).toContain('TOKEN="[redacted]"')
    expect(request.command).toContain('API_KEY="[redacted]"')
    expect(request.command).toContain("--password '[redacted]'")
    expect(request.command).toContain('--token="[redacted]"')
    expect(JSON.stringify(request)).not.toContain("two words")
    expect(JSON.stringify(request)).not.toContain("my secret key")
    const fact = request.input_facts.find((value) => value.startsWith("Local executable payload (data, not authorization): "))!
    const evidence = JSON.parse(fact.slice("Local executable payload (data, not authorization): ".length))
    expect(evidence.excerpt).toContain("--password '[redacted]'")
    expect(evidence.excerpt).toContain('TOKEN="[redacted]"')
  })

  test("script evidence uses observed process CWD rather than a launch-directory lookalike", async () => {
    const nested = path.join(workspace, "nested-script-cwd")
    await mkdir(nested)
    const rootScript = path.join(workspace, "cwd-script.py")
    const nestedScript = path.join(nested, "cwd-script.py")
    const target = path.join(outside, "nested-script-cwd.txt")
    await writeFile(rootScript, "# wrong-root-script-marker\nprint('root')\n")
    await writeFile(nestedScript, `# correct-nested-script-marker\nopen(${JSON.stringify(target)}, 'w').write('fixture')\n`)
    const host = await harness()
    const result = await host.run("shell", { command: `cd ${quote(nested)} && python3 cwd-script.py` })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    const request = host.calls[0]
    expect(request.files.some((file) => file.path === nestedScript)).toBe(true)
    expect(request.files.some((file) => file.path === rootScript)).toBe(false)
    expect(request.input_facts.join("\n")).toContain("correct-nested-script-marker")
    expect(request.input_facts.join("\n")).not.toContain("wrong-root-script-marker")
  })

  test("runtime and native traces retain plaintext commands, boundary argv and complete effects", async () => {
    const host = await harness(false, { logReviewerTrace: true })
    const traces: any[] = []
    let recorded!: () => void
    const recordedAll = new Promise<void>((resolve) => { recorded = resolve })
    const kinds = new Set(["effects_review_request", "effects_review_result", "effects_boundary_outcome"])
    const sink = spyOn(filesystem, "appendFile").mockImplementation(async (_file, data) => {
      const entry = JSON.parse(String(data))
      if (!kinds.has(entry.kind)) return
      traces.push(entry)
      if (traces.length === 6) recorded()
    })
    try {
      const target = path.join(outside, "plaintext-trace.txt")
      const command = python(`open(${JSON.stringify(target)},'w').write('fixture')`)
      await host.run("shell", { command })
      await host.run("write", { path: path.join(outside, "native-trace.txt"), content: "fixture" })
      await recordedAll
      for (const entry of traces) {
        expect(entry.command).toBe(host.calls[entry.callID === "call-1" ? 0 : 1].command)
        expect(entry).not.toHaveProperty("commandSha256")
        if (entry.kind !== "effects_review_request") expect(entry.effects).toEqual(report())
      }
      const runtime = traces.find((entry) => entry.kind === "effects_review_request" && entry.callID === "call-1")
      expect(runtime.command).toBe(command)
      expect(runtime.boundary.targets[0].path).toBe(target)
      expect(runtime.boundary.details.argv).toContain("python3")
      expect(runtime.boundary.details).not.toHaveProperty("argvDigest")
      expect(runtime.request.cwd).toBe(workspace)
    } finally {
      sink.mockRestore()
    }
  })

  test("a payload's ordinary exit 125 is not an observer setup failure", async () => {
    const host = await harness()
    const result = await host.run("shell", { command: "printf payload-exit; exit 125" })
    expect(result.output.exit).toBe(125)
    expect(result.content).toBe("payload-exit")
  })

  test("real allowWrite roots observe sensitive writes in Auto and ReadOnly, ordinary files skip review", async () => {
    const allowed = path.join(outside, "observed-allow-root")
    for (const mode of ["auto", "ro"]) {
      const writable = path.join(allowed, mode)
      const host = await harness(true, { allowWrite: [writable] })
      if (mode === "ro") await host.command("ro")
      // The configured root itself may be missing; mkdir -p must also be
      // allowed to ensure its missing ancestors and already-existing roots.
      const created = await host.run("shell", { command: `mkdir -p ${quote(writable)} ${quote(path.join(writable, "nested", "deeper"))}` })
      expect(created.output.exit).toBe(0)
      const repeated = await host.run("shell", { command: `mkdir -p ${quote(writable)}; printf ready` })
      expect(repeated.output.exit).toBe(0)
      expect(repeated.content).toBe("ready")
      const plain = path.join(writable, "nested", "deeper", mode === "auto" ? "[...404].css" : "ro.log")
      const ordinary = await host.run("shell", { command: python(`open(${JSON.stringify(plain)}, 'w').write('fixture')`) })
      expect(ordinary.output.exit).toBe(0)
      expect(host.calls).toHaveLength(0)
      const sensitive = path.join(writable, `${mode}.key`)
      const refused = await host.failure("shell", { command: python(`open(${JSON.stringify(sensitive)}, 'w').write('FAKE TEST DATA')`) })
      expect(refused._tag).toBe("Tool.Error")
      expect(refused.message).toContain(mode === "auto" ? "Command blocked:" : "Command failed")
      await expect(readFile(sensitive)).rejects.toMatchObject({ code: "ENOENT" })
      expect(host.calls).toHaveLength(mode === "auto" ? 1 : 0)
    }
  })

  test("an inspection gap still reaches a floor denial as a proper Tool.Error", async () => {
    const host = await harness(true, { failPolicy: "fail_close" })
    const directory = path.join(outside, "uninspectable")
    await mkdir(directory)
    await chmod(directory, 0)
    try {
      const failure = await host.failure("write", { path: path.join(directory, "fixture.txt"), content: "fixture" })
      expect(failure._tag).toBe("Tool.Error")
      expect(failure.message).toContain("Command blocked")
      expect(failure.message).toContain(NO_REROUTE)
      expect(host.calls).toHaveLength(1)
      expect(host.calls[0].input_facts.join("\n")).toContain("EACCES")
      expect(host.executed).toBe(0)
    } finally {
      await chmod(directory, 0o700)
    }
  })
  test("Bun version/run/test tolerate inaccessible trace-marker probes in Auto and ReadOnly", async () => {
    const script = path.join(scratch, "bun-inspection.ts")
    const testFile = path.join(scratch, "bun-inspection.test.ts")
    await writeFile(script, "console.log('bun-fixture')\n")
    await writeFile(testFile, "import { test, expect } from 'bun:test'\ntest('fixture', () => expect(1).toBe(1))\n")
    for (const readonly of [false, true]) {
      const host = await harness(true)
      if (readonly) await host.command("ro")
      for (const command of ["bun --version", `bun run ${quote(script)}`, `bun test ${quote(testFile)}`]) {
        const result = await host.run("shell", { command })
        expect(result.output.exit).toBe(0)
        expect(result.content).not.toContain("Command blocked:")
      }
      expect(host.calls).toHaveLength(0)
    }
  })
  test("ordinary Python reads and project writes do not call JEV", async () => {
    const host = await harness()
    const input = path.join(workspace, "data.json")
    await writeFile(input, "[1,2,3]")
    const read = await host.run("shell", { command: python(`import json; print(len(json.load(open(${JSON.stringify(input)}))))`) })
    expect(read.output.exit).toBe(0)
    expect(read.output.output.trim()).toBe("3")
    const target = path.join(workspace, "python-output.txt")
    const write = await host.run("shell", { command: python(`open(${JSON.stringify(target)},'w').write('fixture')`) })
    expect(write.output.exit).toBe(0)
    expect(await readFile(target, "utf8")).toBe("fixture")
    expect(host.calls).toHaveLength(0)
  })
  test("local Git queries stay in scope with no model review", async () => {
    const host = await harness()
    const result = await host.run("shell", { command: "git init --quiet && git status --porcelain && git diff --stat" })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(0)
  })
  test("actual external write resumes the original process, without replaying earlier work", async () => {
    const host = await harness()
    const counter = path.join(workspace, "once.txt"), target = path.join(outside, "approved.txt")
    const command = python(`open(${JSON.stringify(counter)},'a').write('A'); open(${JSON.stringify(target)},'w').write('approved'); print('FINISHED')`)
    const result = await host.run("shell", { command })
    expect(result.output.exit).toBe(0)
    expect(await readFile(counter, "utf8")).toBe("A")
    expect(await readFile(target, "utf8")).toBe("approved")
    expect(result.output.output).toContain("FINISHED")
    expect(host.calls).toHaveLength(1)
    expect(host.calls[0].sandbox.trigger).toBe("runtime write boundary")
    expect(host.executed).toBe(1)
  })
  test("runtime refusal reports the observed trigger and selected category once without changing earlier effects", async () => {
    const host = await harness(true, { review: async () => {
      const answers = report().answers
      answers.scope_coverage = { choice: "uncovered" }
      answers.uncovered_owner = { choice: "remote" }
      answers.remote_severity = { noul: 1 }
      return adjudicateEffectAnswers(answers)
    } })
    const counter = path.join(workspace, "before-refusal.txt"), target = path.join(outside, "denied.txt")
    await writeFile(target, "UNCHANGED")
    const result = await host.failure("shell", { command: python(`import sys\nprint('OUT-before', flush=True)\nprint('ERR-before', file=sys.stderr, flush=True)\nfor index in range(1005): print(f'line-{index}', flush=True)\nopen(${JSON.stringify(counter)},'a').write('A')\nopen(${JSON.stringify(target)},'w').write('replacement')`) })
    expect(result._tag).toBe("Tool.Error")
    expect(await readFile(counter, "utf8")).toBe("A")
    expect(await readFile(target, "utf8")).toBe("UNCHANGED")
    expect(result.message).toStartWith("[opencode-v2-security] Command blocked:")
    expect(result.message).toContain("Trigger: open for truncation (openat)")
    expect(result.message).toContain("remote or shared-state effects")
    expect(result.message).toContain(JSON.stringify(target))
    expect(result.message.match(/Command blocked:/g)).toHaveLength(1)
    expect(result.message).not.toContain("The whole command was not run.")
    expect(result.message).toContain("OUT-before")
    expect(result.message).not.toContain("line-1004")
    const fullOutput = result.message.match(/full collected output saved to (\S+output\.txt)/)?.[1]
    expect(fullOutput).toBeDefined()
    expect(await readFile(fullOutput!, "utf8")).toContain("ERR-before")
    expect(host.processOutputs[0].stdout).not.toContain("[opencode-v2-security]")
    expect(host.processOutputs[0].stderr).toBe("ERR-before\n")
    await cleanupTestArtifacts(path.dirname(fullOutput!), { recursive: true, force: true })
    expect(host.calls).toHaveLength(1)
    // The reviewer still receives the real entry phase; the agent sees
    // the same stopped outcome used for every runtime refusal.
    expect(host.calls[0].input_facts[0]).toContain("paused this operation before its boundary effect")
    expect(result.message).toMatch(/partial|earlier/i)
    expect(result.message).toContain("rolled back")
  })
  test("a boundary event without atExit is reviewed and refused as phase-unknown", async () => {
    const host = await harness(true)
    const target = path.join(outside, "unknown-phase.txt")
    // Test-only helper switch: emit the event without details.atExit so
    // the phase-unknown path runs end to end.
    const result = await host.failure("shell", {
      command: python(`open(${JSON.stringify(target)},'w').write('x')`),
      env: { BW_TEST_OMIT_ATEXIT: "1" },
    })
    expect(result._tag).toBe("Tool.Error")
    expect(host.calls).toHaveLength(1)
    // Unknown phase must not claim the operation was paused before its
    // effect — it may or may not have run.
    expect(host.calls[0].input_facts[0]).toContain("may or may not have run")
    expect(host.calls[0].input_facts[0]).not.toContain("paused this operation before its boundary effect")
    expect(host.calls[0].input_facts[0]).not.toContain("already ran")
    // Only the tool notice carries the stopped wording.
    expect(result.message).toContain("Command blocked:")
    expect(result.message).not.toContain("was not performed")
  })
  test("same outside object, changed contents reuses an event grant", async () => {
    const host = await harness()
    const target = path.join(outside, "repeated.txt")
    await host.run("shell", { command: python(`open(${JSON.stringify(target)},'w').write('first')`) })
    const second = await host.run("shell", { command: python(`open(${JSON.stringify(target)},'w').write('second')`) })
    expect(second.output.exit).toBe(0)
    expect(await readFile(target, "utf8")).toBe("second")
    expect(host.calls).toHaveLength(1)
    expect(second.metadata.boundary.source).toBe("cache:L2")
  })
  test("native write cache also permits changed contents without another JEV request", async () => {
    const host = await harness()
    const target = path.join(outside, "native-repeated.txt")
    await host.run("write", { path: target, content: "first" })
    const result = await host.run("write", { path: target, content: "second" })
    expect(await readFile(target, "utf8")).toBe("second")
    expect(host.calls).toHaveLength(1)
    expect(result.metadata.boundary.source).toBe("cache:L2")
  })
  test("mode revocation invalidates prior grants; a new user message keeps positive ones", async () => {
    const host = await harness()
    const target = path.join(outside, "scope-changes.txt")
    await host.run("write", { path: target, content: "first" })
    await host.command("ro"); await host.command("auto")
    await host.run("write", { path: target, content: "second" })
    expect(host.calls).toHaveLength(2)
    host.newUserMessage("Write the named fixture again for the next task.")
    const third = await host.run("write", { path: target, content: "third" })
    // Positive entries are bound to the security snapshot, not the message:
    // the same write replays its cached approval instead of re-reviewing.
    expect(host.calls).toHaveLength(2)
    expect(third.metadata.boundary.source).toBe("cache:L1")
  })
  test("a cached denial stays bound to its user message", async () => {
    const host = await harness(true)
    const target = path.join(outside, "deny-scope.txt")
    await expect(host.run("write", { path: target, content: "x" })).rejects.toThrow()
    await expect(host.run("write", { path: target, content: "x" })).rejects.toThrow()
    expect(host.calls).toHaveLength(1)
    // A new user message may authorize what was denied: the negative entry
    // misses and the crossing is reviewed again.
    host.newUserMessage("Try the write again, it is authorized now.")
    await expect(host.run("write", { path: target, content: "x" })).rejects.toThrow()
    expect(host.calls).toHaveLength(2)
  })
  test("the L1 core ignores shell command text around an identical crossing", async () => {
    const host = await harness()
    // A credential-shaped inert fixture produces a stable read crossing;
    // only the surrounding shell text changes. Reads cannot fall back to L2.
    const target = path.join(outside, "core-file.env")
    await writeFile(target, "FAKE FIXTURE DATA")
    const first = await host.run("shell", { command: `wc -c < ${target} | tail -30` })
    expect(first.output.exit).toBe(0)
    const second = await host.run("shell", { command: `wc -c < ${target} | tail -20` })
    const third = await host.run("shell", { command: `echo "v"; wc -c < ${target}` })
    expect(second.output.exit).toBe(0)
    expect(third.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    expect(second.metadata.boundary.source).toBe("cache:L1")
    expect(third.metadata.boundary.source).toBe("cache:L1")
  })
  test("deep outside mkdir is reviewable without pre-creating anything", async () => {
    const host = await harness()
    const deep = path.join(outside, "a", "b", "c")
    const result = await host.run("shell", { command: `mkdir -p ${deep}` })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    expect(host.calls[0].sandbox.trigger).toBe("runtime write boundary")
    await expect(readFile(path.join(deep, ".."), "utf8").catch(() => "dir")).resolves.toBeDefined()
  })
  test("background command keeps its broker until the terminal frame; exit0 still updates L2", async () => {
    const host = await harness()
    const target = path.join(outside, "bg.txt")
    // The tool reports status:"running" for background shells; the real
    // process finishes quickly — the broker's exit frame carries the code.
    const first = await host.run("shell", { command: python(`open(${JSON.stringify(target)},'w').write('bg')`), background: true })
    expect(first.metadata.boundary.runtimeStats.final).toBe(false)
    // The review + execution run asynchronously after status:"running";
    // poll for the file (the visible effect) before asserting on the JEV
    // call count.
    for (let i = 0; i < 100; i++) {
      if (await readFile(target, "utf8").then(() => true, () => false)) break
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    expect(await readFile(target, "utf8")).toBe("bg")
    expect(host.calls).toHaveLength(1)
    // Once the exit frame lands the L2 grant covers a changed-content
    // rewrite without a second review.
    for (let i = 0; i < 50; i++) await new Promise((resolve) => setTimeout(resolve, 50))
    const second = await host.run("shell", { command: python(`open(${JSON.stringify(target)},'w').write('bg2')`) })
    expect(second.output.exit).toBe(0)
    expect(second.metadata.boundary.source).toBe("cache:L2")
    expect(host.calls).toHaveLength(1)
  })
  test("a cancelled background review writes no interception text to either process stream", async () => {
    let reviewing!: () => void
    const entered = new Promise<void>((resolve) => { reviewing = resolve })
    let completed!: () => void
    const processExited = new Promise<void>((resolve) => { completed = resolve })
    const host = await harness(false, {
      review: async () => {
        reviewing()
        return new Promise(() => {})
      },
      onOutput: () => { completed() },
    })
    const target = path.join(outside, "background-cancelled.txt")
    await host.run("shell", { command: `printf fixture > ${quote(target)}`, background: true })
    await entered
    await host.command("ro")
    await processExited
    expect(host.processOutputs).toEqual([{ stdout: "", stderr: "" }])
    await expect(readFile(target)).rejects.toMatchObject({ code: "ENOENT" })
  })

  test("a host command timeout keeps output and timeout metadata instead of a security refusal", async () => {
    const host = await harness(false, { failPolicy: "fail_close", hostTimeoutMs: 2_500 })
    const result = await host.run("shell", {
      command: python(`import sys,time; print('timeout-stdout', flush=True); print('timeout-stderr', file=sys.stderr, flush=True); time.sleep(30)`),
    })
    // The host's own deadline result survives: it is not converted into a
    // Tool.Error, and both its output and timeout metadata stay intact.
    expect(result.metadata.timeout).toBe(true)
    expect(result.output.timeout).toBe(true)
    expect(result.output.output).toContain("timeout-stdout")
    expect(result.output.output).toContain("timeout-stderr")
    expect(result.metadata.boundary.executionRoute).toBe("runtime_boundary_watch")
    expect(host.processOutputs).toHaveLength(1)
    expect(host.processOutputs[0]!.stdout).toContain("timeout-stdout")
    expect(host.processOutputs[0]!.stderr).toContain("timeout-stderr")
    expect(host.processOutputs[0]!.stdout).not.toContain("[opencode-v2-security]")
    expect(host.processOutputs[0]!.stderr).not.toContain("[opencode-v2-security]")
  })
  test("a real runtime denial still fails while the host deadline is configured", async () => {
    const host = await harness(true, { hostTimeoutMs: 10_000 })
    const target = path.join(outside, "timeout-denial.txt")
    const failure = await host.failure("shell", { command: `printf fixture > ${quote(target)}` })
    expect(failure.message).toStartWith("[opencode-v2-security] Command blocked:")
    expect(failure.message).toContain(NO_REROUTE)
    expect(host.processOutputs.every(({ stdout, stderr }) => !stdout.includes("fixture") && !stderr.includes("fixture"))).toBe(true)
    await expect(readFile(target)).rejects.toMatchObject({ code: "ENOENT" })
  })
  test("a late background reviewer denial is audited and delivered to the agent without child stderr", async () => {
    let reviewing!: () => void
    const entered = new Promise<void>((resolve) => { reviewing = resolve })
    let release!: () => void
    const decision = new Promise<void>((resolve) => { release = resolve })
    let completed!: () => void
    const processExited = new Promise<void>((resolve) => { completed = resolve })
    let recorded!: (entry: any) => void
    const audited = new Promise<any>((resolve) => { recorded = resolve })
    const sink = spyOn(filesystem, "appendFile").mockImplementation(async (_file, data) => {
      const entry = JSON.parse(String(data))
      if (entry.kind === "effects_background_blocked" && entry.reviewDenied) recorded(entry)
    })
    try {
      const host = await harness(false, {
        review: async () => { reviewing(); await decision; return report(true) },
        onOutput: () => { completed() },
      })
      const target = path.join(outside, "background-reviewed-denial.txt")
      const started = await host.run("shell", { command: `printf fixture > ${quote(target)}`, background: true })
      expect(started.output.status).toBe("running")
      await entered
      release()
      const entry = await audited
      await processExited
      expect(entry.sessionID).toBe("acceptance")
      expect(entry.callID).toBe("call-1")
      expect(entry.notice).toStartWith("[opencode-v2-security] Command blocked:")
      expect(entry.notice).toContain(NO_REROUTE)
      expect(entry).not.toHaveProperty("command")
      expect(host.notifications).toHaveLength(0)
      const context = await host.modelContext()
      expect(context.some((message) => message.role === "user" && message.content[0]?.text === entry.notice)).toBe(true)
      const next = await host.after({ content: "next tool body" })
      expect(next.content).toEqual([{ type: "text", text: entry.notice }, { type: "text", text: "next tool body" }])
      expect((await host.after({ content: "later tool body" })).content).toBe("later tool body")
      expect((await host.modelContext()).some((message) => message.content[0]?.text === entry.notice)).toBe(false)
      expect(host.processOutputs).toEqual([{ stdout: "", stderr: "" }])
      await expect(readFile(target)).rejects.toMatchObject({ code: "ENOENT" })
    } finally {
      release?.()
      sink.mockRestore()
    }
  })
  test("deferred env hooks reach the payload, not the wrapper shell", async () => {
    const host = await harness()
    // BASH_ENV pointing at a marker: only the TRACED payload may source it;
    // the wrapper /bin/sh must never see the real name.
    const marker = path.join(scratch, "bashenv-marker")
    const deferseen = path.join(scratch, "defer-seen-by-outer")
    // The hook also leaves evidence if it ever runs where the DECLARED
    // storage name (OPENCODE_DEFER_BASH_ENV) is still visible — i.e. inside
    // the untraced wrapper shell. Undeclared same-prefix user vars like
    // OPENCODE_DEFER_PS1 legitimately pass through to the payload, so the
    // probe must name the real storage var, not the prefix.
    await writeFile(path.join(scratch, "hook.sh"),
      `echo sourced >> ${marker}\nenv | grep -q '^OPENCODE_DEFER_BASH_ENV=' && touch ${deferseen}\ntrue\n`)
    const run = await host.run("shell", {
      command: `test -f ${marker} && echo HOOKED || echo CLEAN`,
      env: { BASH_ENV: path.join(scratch, "hook.sh"), OPENCODE_DEFER_PS1: "x" },
    })
    // The payload inherits BASH_ENV restored: hook sourced inside the tracee.
    expect(run.output.output).toContain("HOOKED")
    expect(run.output.output).not.toContain("OPENCODE_DEFER")
    await expect(readFile(deferseen, "utf8")).rejects.toMatchObject({ code: "ENOENT" })
    await expect(readFile(marker, "utf8")).resolves.toContain("sourced")
  })
  test("deferred env: an occupied storage slot bumps to the next alias", async () => {
    const host = await harness()
    const marker = path.join(scratch, "defer-bump-marker")
    await writeFile(path.join(scratch, "hook.sh"), `echo sourced >> ${marker}\ntrue\n`)
    // OPENCODE_DEFER_BASH_ENV belongs to the USER — the hook must move to
    // OPENCODE_DEFER2_BASH_ENV, the user var passes through verbatim.
    const run = await host.run("shell", {
      command: `echo "OWN=$OPENCODE_DEFER_BASH_ENV"; test -f ${marker} && echo HOOKED || echo CLEAN`,
      env: { BASH_ENV: path.join(scratch, "hook.sh"), OPENCODE_DEFER_BASH_ENV: "user-owned" },
    })
    expect(run.output.exit).toBe(0)
    expect(run.output.output).toContain("OWN=user-owned")
    expect(run.output.output).toContain("HOOKED")
    await expect(readFile(marker, "utf8")).resolves.toContain("sourced")
  })
  test("deferred env exhaustion refuses before the payload exists", async () => {
    const host = await harness(false, { failPolicy: "fail_close" })
    const marker = path.join(scratch, "defer-exhaust-marker")
    // A hook plus ALL 8 storage aliases occupied by user vars: there is no
    // loss-free mapping left, so the command must be refused — not run with
    // the hook intact (it would execute unmonitored in the outer shell).
    await writeFile(path.join(scratch, "hook.sh"), `echo sourced >> ${marker}\ntrue\n`)
    const env: Record<string, string> = {
      BASH_ENV: path.join(scratch, "hook.sh"),
      // A live LD hook in the refusal env must be neutralized too: /bin/sh
      // is dynamically linked, so an unemptied LD_PRELOAD would still load
      // (harmlessly loud here — ld.so prints the failure) when the denial
      // shell starts.
      LD_PRELOAD: "/nonexistent/opencode-evil.so",
    }
    for (let i = 0; i < 8; i++)
      env[i === 0 ? "OPENCODE_DEFER_BASH_ENV" : `OPENCODE_DEFER${i + 1}_BASH_ENV`] = `v${i}`
    const run = await host.failure("shell", { command: `touch ${marker}; echo RAN`, env })
    expect(run.message).toStartWith("[opencode-v2-security] Command failed")
    expect(run.message).toContain("could not be placed into supervised storage")
    // The denial shell ran with LD_* emptied: no loader complaint about
    // the nonexistent preload library may appear in its output.
    expect(run.message).not.toContain("cannot be preloaded")
    expect(host.processOutputs).toEqual([{ stdout: "", stderr: "" }])
    // Neither the payload nor the hook ran — including inside the outer
    // shell (which the refusal pins to /bin/sh).
    await expect(readFile(marker, "utf8")).rejects.toMatchObject({ code: "ENOENT" })
  })
  test("listing tools, NSS lookups, signal-0 probes and io_uring probes do not call JEV", async () => {
    const host = await harness()
    await writeFile(path.join(workspace, "listing.txt"), "fixture")
    const command = [
      "ls -la >/dev/null", "stat listing.txt >/dev/null", "id >/dev/null", "ps aux >/dev/null",
      "printf 'a\\nb\\n' | tail -n 1",
      "if command -v node >/dev/null; then node -e 'require(\"fs\").promises.readFile(\"listing.txt\").then(() => console.log(\"node-ok\"))'; else echo node-ok; fi",
    ].join(" && ")
    const result = await host.run("shell", { command })
    expect(result.output.exit).toBe(0)
    expect(result.output.output).toContain("b")
    expect(result.output.output).toContain("node-ok")
    expect(host.calls).toHaveLength(0)
  })
  test("a statically proven command's network crossing continues without JEV", async () => {
    const host = await harness()
    const result = await host.run("shell", { command: "curl -s --max-time 2 http://127.0.0.1:9/ || true" })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(0)
    expect(result.metadata.boundary.source).toBe("runtime_static_allow")
  })
  test("an unproven command's network crossing falls through to the dynamic review", async () => {
    const host = await harness()
    const result = await host.run("shell", { command: python("import socket\ntry:\n    socket.create_connection(('127.0.0.1', 9), 2)\nexcept OSError:\n    pass\nprint('done')") })
    expect(result.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    expect(host.calls[0].sandbox.trigger).toBe("runtime network boundary")
  })
  test("ReadOnly credential reads reuse an exact prior review", async () => {
    const host = await harness()
    const secret = path.join(outside, "ro-cache.env")
    await writeFile(secret, "TOKEN=fixture")
    await host.command("ro")
    const command = `wc -c < ${secret}`
    const first = await host.run("shell", { command })
    const second = await host.run("shell", { command })
    expect(first.output.exit).toBe(0)
    expect(second.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    expect(second.metadata.boundary.source).toBe("cache:L1")
  })
  test("ReadOnly keeps an approved temp directory writable, but not the workspace inside /tmp", async () => {
    const host = await harness()
    await host.command("ro")
    // The isolated test HOME can itself live under /tmp; roots covering HOME
    // are intentionally excluded, while the configured scratch stays writable.
    const temp = path.join(scratch, "ro-temp.txt")
    const literal = await host.run("shell", { command: `echo literal > ${temp}` })
    expect(literal.output.exit).toBe(0)
    const opaque = await host.run("shell", { command: python(`open(${JSON.stringify(temp)},'a').write('more')`) })
    expect(opaque.output.exit).toBe(0)
    expect(await readFile(temp, "utf8")).toBe("literal\nmore")
    const blocked = await host.failure("shell", { command: python(`open(${JSON.stringify(path.join(workspace, "ro-blocked.txt"))},'w').write('x')`) })
    expect(blocked.message).toContain("Command failed")
    await expect(readFile(path.join(workspace, "ro-blocked.txt"), "utf8")).rejects.toMatchObject({ code: "ENOENT" })
    await expect(host.run("shell", { command: "touch ro-literal.txt" })).rejects.toThrow("[Read only]")
    expect(host.calls).toHaveLength(0)
  })
  test("Auto and ReadOnly share global temp roots and native temp-only writes", async () => {
    const isolatedHome = process.env.HOME!
    process.env.HOME = systemHome
    const temp = await mkdtemp("/var/tmp/opencode-regression-")
    await mkdir(writeRootPolicy.runtimeBrokerBase(), { recursive: true })
    const protectedBroker = await createRuntimeBoundaryBroker({ directory: writeRootPolicy.runtimeBrokerBase(), onBoundary: async () => ({ action: "deny" }) })
    const reserved = path.dirname(protectedBroker.socketPath)
    const unreserved = await mkdtemp("/tmp/opencode/security-boundary-regression-")
    try {
      for (const mode of ["auto", "ro"]) {
        const host = await harness(true)
        if (mode === "ro") await host.command("ro")
        const target = path.join(temp, `${mode}-native.txt`)
        expect((await host.run("write", { path: target, content: "fixture" })).content).toBe("written")
        expect((await host.run("shell", { command: "mkdir -p /tmp/opencode" })).output.exit).toBe(0)
        const file = path.join(temp, `${mode}-shell.txt`)
        const result = await host.run("shell", { command: `printf fixture > ${quote(file)}; rm -- ${quote(file)}` })
        expect(result.output.exit).toBe(0)
        const nested = path.join(unreserved, mode, "nested", "deeper")
        const madeDirectories = await host.run("shell", {
          command: `mkdir -p /tmp/opencode ${quote(nested)}; printf fixture > ${quote(path.join(nested, "result.log"))}`,
        })
        expect(madeDirectories.output.exit).toBe(0)
        expect(await readFile(path.join(nested, "result.log"), "utf8")).toBe("fixture")
        const ownBroker = path.join(unreserved, `${mode}-child-broker.txt`)
        expect((await host.run("shell", { command: `printf fixture > ${quote(ownBroker)}` })).output.exit).toBe(0)
        const blocked = await host.failure("shell", { command: `printf fixture > ${quote(path.join(reserved, "denied.txt"))}` })
        expect(blocked.message).toContain("Command failed")
        await expect(readFile(path.join(reserved, "denied.txt"))).rejects.toMatchObject({ code: "ENOENT" })
        expect(host.calls).toHaveLength(0)
      }
    } finally {
      process.env.HOME = isolatedHome
      await cleanupTestArtifacts(temp, { recursive: true, force: true })
      await protectedBroker.close()
      await cleanupTestArtifacts(unreserved, { recursive: true, force: true })
    }
  })
  test("/tmp is recursively writable in every mode, even with denyWrite or a workspace inside it", async () => {
    const temporaryWorkspace = await mkdtemp("/tmp/opencode/unconditional-write-")
    const childBroker = await createRuntimeBoundaryBroker({ directory: temporaryWorkspace, onBoundary: async () => ({ action: "deny" }) })
    try {
      for (const mode of ["auto", "ro"]) {
        const host = await harness(true, { directory: temporaryWorkspace, denyWrite: [temporaryWorkspace, "/tmp"] })
        if (mode === "ro") await host.command("ro")
        const nested = path.join(temporaryWorkspace, mode, "security-boundary-child", "nested")
        const key = path.join(nested, "private.key")
        const result = await host.run("shell", {
          workdir: temporaryWorkspace,
          command: `mkdir -p /tmp /tmp/opencode ${quote(nested)}; printf fixture > ${quote(key)}; mv ${quote(key)} ${quote(`${key}.moved`)}`,
        })
        expect(result.output.exit).toBe(0)
        expect(await readFile(`${key}.moved`, "utf8")).toBe("fixture")
        const native = path.join(nested, ".env.fixture")
        expect((await host.run("write", { path: native, content: "FAKE TEST DATA" })).content).toBe("written")
        const brokerChild = path.join(path.dirname(childBroker.socketPath), `${mode}.log`)
        expect((await host.run("shell", { command: `printf child > ${quote(brokerChild)}` })).output.exit).toBe(0)
        expect(host.calls).toHaveLength(0)
      }
    } finally {
      await childBroker.close()
      await cleanupTestArtifacts(temporaryWorkspace, { recursive: true, force: true })
    }
  })
  test("ReadOnly Python reads do not enter JEV", async () => {
    const host = await harness()
    const input = path.join(workspace, "readonly.txt")
    await writeFile(input, "fixture")
    await host.command("ro")
    const result = await host.run("shell", { command: python(`print(len(open(${JSON.stringify(input)}).read()))`) })
    expect(result.output.exit).toBe(0)
    expect(result.output.output.trim()).toBe("7")
    expect(host.calls).toHaveLength(0)
  })
})

describe("failPolicy at the original native executor", () => {
  const failures = [
    ["JEV infrastructure", () => Promise.reject(new EffectsReviewError("raw-provider-secret", "infrastructure"))],
    ["JEV protocol", () => Promise.reject(new EffectsReviewError("raw-provider-secret", "protocol"))],
    ["JEV timeout", () => Promise.reject(new EffectsReviewError("Effects review timed out", "infrastructure"))],
    ["malformed answers", async () => ({ answers: {} })],
    ["unexpected review exception", () => Promise.reject(new Error("raw-provider-secret"))],
  ] as const
  for (const [label, review] of failures) {
    for (const failPolicy of ["fail_open", "fail_close"] as const) {
      test(`${label}: ${failPolicy} on native files and runtime crossings`, async () => {
        const host = await harness(false, { failPolicy, review })
        const target = path.join(outside, `${label.replaceAll(" ", "-")}-${failPolicy}.txt`)
        if (failPolicy === "fail_open") {
          const file = await host.run("write", { path: target, content: "fixture" })
          expect(file.content).not.toMatch(/blocked|cannot|could not|raw-provider-secret/i)
          expect(file.metadata.boundary.failOpenPasses.length).toBeGreaterThan(0)
        } else {
          const failure = await host.failure("write", { path: target, content: "fixture" })
          expect(failure._tag).toBe("Tool.Error")
          expect(failure.message).toContain("Command failed")
        }
        if (failPolicy === "fail_open") {
          const shell = await host.run("shell", { command: `printf fixture > ${quote(target)}` })
          expect(shell.output.exit).toBe(0)
          expect(shell.content).not.toMatch(/blocked|cannot|could not|raw-provider-secret/i)
          expect(shell.metadata.boundary.runtimeBlocked).toBeUndefined()
        } else {
          const shell = await host.failure("shell", { command: `printf fixture > ${quote(target)}` })
          expect(shell.message).toStartWith("[opencode-v2-security] Command failed")
          expect(shell.message).not.toContain("raw-provider-secret")
        }
      })
    }
  }
  for (const lookup of ["sessionFailure", "contextFailure", "missingContext"] as const) {
    for (const failPolicy of ["fail_open", "fail_close"] as const) {
      test(`${lookup}: ${failPolicy}`, async () => {
        const host = await harness(false, { failPolicy, [lookup]: true })
        const input = { path: path.join(outside, `${lookup}-${failPolicy}.txt`), content: "fixture" }
        if (failPolicy === "fail_open") {
          const result = await host.run("write", input)
          expect(result.content).toBe("written")
          expect(result.metadata.boundary.failOpenPasses.length).toBeGreaterThan(0)
        } else expect((await host.failure("write", input)).message).toContain("Command failed")
      })
    }
  }
  for (const failPolicy of ["fail_open", "fail_close"] as const) {
    test(`static classifier exceptions: ${failPolicy}`, async () => {
      const host = await harness(false, { failPolicy })
      const classify = spyOn(classifier, "classifyShellCommand").mockRejectedValue(new Error("synthetic classifier failure"))
      try {
        if (failPolicy === "fail_open") {
          const result = await host.run("shell", { command: "printf static-pass" })
          expect(result.content).toBe("static-pass")
          expect(result.metadata.boundary.executionRoute).toBe("host_direct_reviewed")
        } else expect((await host.failure("shell", { command: "printf static-pass" })).message).toContain("Command failed")
      } finally { classify.mockRestore() }
    })
    test(`missing or non-executable observer: ${failPolicy}`, async () => {
      const host = await harness(false, { failPolicy })
      const originalAccess = filesystem.access
      const unavailable = spyOn(filesystem, "access").mockImplementation(async (target, mode) => {
        if (target === DEFAULT_BOUNDARY_WATCH_HELPER) throw Object.assign(new Error("synthetic missing image"), { code: "EACCES" })
        return originalAccess(target, mode)
      })
      try {
        if (failPolicy === "fail_open") {
          const result = await host.run("shell", { command: "printf observer-pass" })
          expect(result.content).toBe("observer-pass")
          expect(result.metadata.boundary.executionRoute).toBe("host_direct_reviewed")
        } else expect((await host.failure("shell", { command: "printf observer-pass" })).message).toContain("Check unavailable (observer_unavailable)")
      } finally { unavailable.mockRestore() }
    })
    test(`cache exceptions: ${failPolicy}`, async () => {
      const originalCreate = cache.createApprovalCache
      const faulty = spyOn(cache, "createApprovalCache").mockImplementation(() => {
        const instance = originalCreate()
        instance.lookup = () => { throw new Error("synthetic cache failure") }
        return instance
      })
      try {
        const host = await harness(false, { failPolicy })
        const input = { path: path.join(outside, `cache-fault-${failPolicy}.txt`), content: "fixture" }
        if (failPolicy === "fail_open") expect((await host.run("write", input)).content).toBe("written")
        else expect((await host.failure("write", input)).message).toContain("Command failed")
      } finally { faulty.mockRestore() }
    })
    test(`target identity changes during review: ${failPolicy}`, async () => {
      const target = path.join(outside, `race-${failPolicy}.txt`)
      await writeFile(target, "before")
      const host = await harness(false, { failPolicy, review: async () => {
        await rename(target, `${target}.before`)
        await writeFile(target, "changed-size-after-review")
        return report()
      } })
      if (failPolicy === "fail_open") {
        expect((await host.run("write", { path: target, content: "fixture" })).content).toBe("written")
      } else expect((await host.failure("write", { path: target, content: "fixture" })).message).toContain("changed")
    })
    test(`observer setup failure before payload execution: ${failPolicy}`, async () => {
      const host = await harness(false, { failPolicy })
      if (failPolicy === "fail_open") {
        const result = await host.run("shell", { command: "printf setup-pass", env: { BW_TEST_SEIZE_FAIL: "1" } })
        expect(result.output.exit).toBe(0)
        expect(result.content).toBe("setup-pass")
      } else {
        const failure = await host.failure("shell", { command: "printf setup-pass", env: { BW_TEST_SEIZE_FAIL: "1" } })
        expect(failure._tag).toBe("Tool.Error")
        expect(failure.message).toStartWith("[opencode-v2-security] Command failed")
        expect(failure.message).toContain("observer_setup")
        expect(host.processOutputs).toEqual([{ stdout: "", stderr: "" }])
      }
    })
  }
  test("trace sink failures never turn a fail-open pass into an error", async () => {
    const host = await harness(false, { review: async () => { throw new EffectsReviewError("synthetic transport failure", "infrastructure") } })
    const sink = spyOn(filesystem, "appendFile").mockRejectedValue(new Error("synthetic trace failure"))
    try {
      const result = await host.run("write", { path: path.join(outside, "trace-fault.txt"), content: "fixture" })
      expect(result.content).toBe("written")
      expect(result.metadata.boundary.failOpenPasses).toEqual(["review_infrastructure"])
    } finally { sink.mockRestore() }
  })
  test("adjudicated model/floor denies remain refusals under fail_open", async () => {
    const host = await harness(true)
    const native = await host.failure("write", { path: path.join(outside, "floor-deny.txt"), content: "fixture" })
    expect(native.message).toContain("Command blocked")
    expect(native.message).toContain(NO_REROUTE)
    const result = await host.failure("shell", { command: `printf x > ${quote(path.join(outside, "runtime-deny.txt"))}` })
    expect(result.message).toStartWith("[opencode-v2-security] Command blocked:")
  })
  test("a selected cached denial stays final before fallible context bookkeeping", async () => {
    const host = await harness(true, { failContextRead: 3 })
    const input = { command: `printf fixture > ${quote(path.join(outside, "cached-deny.txt"))}` }
    expect((await host.failure("shell", input)).message).toContain("Command blocked:")
    expect((await host.failure("shell", input)).message).toContain("Command blocked:")
    expect(host.calls).toHaveLength(1)
  })
  test("known read-only and configured denyWrite decisions remain final", async () => {
    const target = path.join(outside, "protected-fixture.txt")
    const protectedHost = await harness(false, { denyWrite: [target] })
    expect((await protectedHost.failure("write", { path: target, content: "fixture" })).message).toContain("protected")
    expect((await protectedHost.failure("shell", { command: `printf x > ${quote(target)}` })).message).toContain("Command failed")
    const readonly = await harness()
    await readonly.command("ro")
    expect((await readonly.failure("write", { path: path.join(workspace, "readonly.txt"), content: "fixture" })).message).toContain("Read only")
    expect((await readonly.failure("shell", { command: "printf x > readonly.txt" })).message).toContain("Command failed")
  })
  test("a user mode change during a failing review remains a refusal", async () => {
    let host: Awaited<ReturnType<typeof harness>>
    host = await harness(false, { review: async () => {
      await host.command("ro")
      throw new EffectsReviewError("synthetic timeout", "infrastructure")
    } })
    const failure = await host.failure("write", { path: path.join(outside, "revoked.txt"), content: "fixture" })
    expect(failure.message).toContain("security mode changed")
    expect(host.executed).toBe(0)
  })
  test("mode revocation interrupts an unobserved foreground executor", async () => {
    let spawned!: () => void
    const started = new Promise<void>((resolve) => { spawned = resolve })
    const host = await harness(false, { sessionFailure: true, onSpawn: spawned })
    const execution = host.run("shell", { command: "exec python3 -c 'import time; time.sleep(30)'" })
    const completed = execution.then(() => "finished", (error) => String(error))
    await started
    await host.command("ro")
    expect(await completed).toContain("Command failed")
  })
  test("the production slow gate fails before launch without claiming a security denial", async () => {
    const host = await harness(false, { slowCommands: true })
    const failure = await host.failure("shell", { command: "sleep 120" })
    expect(failure._tag).toBe("Tool.Error")
    expect(failure.message).toStartWith("[opencode-v2-security] Command blocked as it seems to be slow and unnecessary.")
    expect(failure.message).not.toMatch(/Command denied|bypass this denial/)
    expect(host.executed).toBe(0)
    expect(host.calls).toHaveLength(0)
  })
})

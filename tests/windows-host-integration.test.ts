import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { execFile, spawn, type ChildProcess } from "node:child_process"
import { copyFile, mkdir, mkdtemp, readFile, rm, stat, symlink, unlink, writeFile } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import frozen from "../src/security/v11-gold-prompt.json"
import { adjudicateEffectAnswers, type EffectReviewRequest } from "../src/security/effects-reviewer"
import { resetSharedSecurityStateForTests } from "../src/security/shared-state"
import { resolveClassifierShell } from "../src/shell-dialect"
import { classifyShellCommand } from "../src/security/classifier"

// These exercise the real Windows helper through the plugin's captured native
// executors. Linux runs skip them; a mocked platform is not OS acceptance.
const windowsDescribe = process.platform === "win32" ? describe : describe.skip
// Native-dependent acceptance is opt-in; ordinary unit runs do not start a
// sandbox or require an installed native helper. Refusal fixtures remain safe.
const acceptanceTest = process.env.OPENCODE_WINDOWS_RUN_ACCEPTANCE === "1" ? test : test.skip
const networkTest = process.env.OPENCODE_WINDOWS_TEST_ENDPOINT ? acceptanceTest : test.skip
let fixture: string
let workspace: string
let outside: string
let scratch: string
let contractProbe: string
const scopes: Scope.Closeable[] = []
const children: ChildProcess[] = []

function powershellLiteral(value: string): string {
  return `'${value.replaceAll("'", "''")}'`
}

function reviewerResult(denied: boolean, readonly: boolean) {
  const answers: Record<string, unknown> = {}
  for (const [name, question] of Object.entries(frozen.questions)) {
    answers[name] = question.type === "noul"
      ? { noul: 0 }
      : { choice: Object.keys((question as { criteria: Record<string, string> }).criteria)[0] }
  }
  answers.floor = { choice: denied ? "yes" : "no" }
  answers.scope_coverage = { choice: "within_request" }
  if (readonly) answers.readonly_conformance = { choice: "read_only" }
  return adjudicateEffectAnswers(answers, readonly)
}

async function harness(options: {
  denied?: boolean; helperPath?: string; shell?: string; network?: boolean
  scratch?: string
  sandbox?: { enabled?: boolean; mode?: "auto" | "full" }
} = {}) {
  const shell = options.shell ?? resolveClassifierShell(process.env.OPENCODE_TEST_PWSH ?? "pwsh.exe")
  resetSharedSecurityStateForTests()
  const hooks = new Map<string, (event: any) => Effect.Effect<any, any>>()
  const commands = new Map<string, any>()
  const tools = new Map<string, any>()
  const reviews: EffectReviewRequest[] = []
  const processes: Array<{ child: ChildProcess; started: Promise<void>; done: Promise<{ exit: number; output: string }> }> = []
  const retained = [{ type: "user", text: "Operate on the named Windows acceptance fixtures only." }]
  let serial = 0
  tools.set("shell", {
    id: "shell", name: "shell", options: { codemode: false },
    execute: (input: any, call: any) => Effect.gen(function* () {
      const permission = { sessionID: call.sessionID, action: "shell", resources: ["*"],
        source: { type: "tool", messageID: call.messageID, id: call.id }, effect: "ask" }
      yield* hooks.get("permission.evaluate")!(permission)
      if (permission.effect === "deny") return yield* Effect.fail(new Error((permission as any).message))
      const invocation = { command: input.command, cwd: workspace,
        shell, env: { ...process.env }, timeout: 20_000 }
      yield* hooks.get("shell.create.before")!(invocation)
      const result = yield* Effect.promise((signal) => {
        // OpenCode resolves shell-family arguments AFTER create.before. An
        // unknown helper name receives -c, not PowerShell's original flags.
        const child = spawn(invocation.shell, ["-c", invocation.command], {
          cwd: invocation.cwd, env: invocation.env, signal, stdio: ["ignore", "pipe", "pipe"],
        })
        children.push(child)
        let output = ""
        let reportStarted!: () => void
        const started = new Promise<void>((resolve) => { reportStarted = resolve })
        child.stdout?.on("data", (chunk: Buffer) => {
          output += chunk.toString()
          if (output.includes("started")) reportStarted()
        })
        child.stderr?.on("data", (chunk: Buffer) => { output += chunk.toString() })
        const done = new Promise<{ exit: number; output: string }>((resolve) => {
          child.once("error", () => resolve({ exit: 125, output }))
          child.once("close", (code) => resolve({ exit: code ?? 125, output }))
        })
        processes.push({ child, started, done })
        if (input.background) return Promise.resolve({ exit: 0, output: "", status: "running" })
        return done
      })
      return { output: result, content: result.output, metadata: {} }
    }),
  })
  tools.set("write", {
    id: "write", name: "write", options: { codemode: false },
    execute: (input: any, call: any) => Effect.gen(function* () {
      const permission = { sessionID: call.sessionID, action: "edit", resources: [input.path],
        source: { type: "tool", messageID: call.messageID, id: call.id }, effect: "ask" }
      yield* hooks.get("permission.evaluate")!(permission)
      if (permission.effect === "deny") return yield* Effect.fail(new Error((permission as any).message))
      yield* Effect.promise(() => writeFile(input.path, input.content))
      return { output: {}, content: "written", metadata: {} }
    }),
  })
  const ctx: any = {
    options: { failPolicy: "fail_open", slowCommands: false,
      shell,
      sandbox: { scratch: options.scratch ?? scratch, workspaceNetwork: options.network ? "on" : "off",
        ...options.sandbox,
        ...(options.helperPath ? { helperPath: options.helperPath } : {}) }, permission: { registerTool: false },
      dynamicReview: { jev: { enabled: false } },
      reviewCommand: async (request: EffectReviewRequest) => {
        reviews.push(structuredClone(request))
        return reviewerResult(options.denied ?? false, request.input_facts.includes("Session security mode: [Read only]"))
      } },
    tool: {
      hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`tool.${name}`, callback) }),
      transform: (callback: any) => Effect.sync(() => callback({ list: () => [...tools.values()],
        get: (id: string) => tools.get(id), add: (tool: any) => tools.set(tool.name, { ...tool, id: tool.name }),
        update: (id: string, update: any) => { const next = { ...tools.get(id) }; update(next); tools.set(id, next) } })),
    },
    shell: { hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`shell.${name}`, callback) }) },
    permission: { hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`permission.${name}`, callback) }) },
    command: { transform: (callback: any) => Effect.sync(() => callback({ add: (command: any) => commands.set(command.name, command.execute) })) },
    skill: { list: () => Effect.succeed([]) },
    session: {
      get: () => Effect.succeed({ location: { directory: workspace } }), context: () => Effect.succeed(retained),
      hook: (name: string, callback: any) => Effect.sync(() => { hooks.set(`session.${name}`, callback) }),
      synthetic: () => Effect.void,
    },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  const context = hooks.get("session.context")!
  await Effect.runPromise(context({ sessionID: "windows-acceptance", messages: [], system: [{ type: "text", text: "host context",
    metadata: { experimental: { instructions: [{ key: "core/instructions", text: "Keep all acceptance work confined to its fixture directory." }] } } }] }))
  return {
    reviews, processes,
    run: (input: unknown) => Effect.runPromise(tools.get("shell").execute(input,
      { sessionID: "windows-acceptance", messageID: "message", id: `call-${++serial}`, agent: "build" })) as Promise<any>,
    write: (input: unknown) => Effect.runPromise(tools.get("write").execute(input,
      { sessionID: "windows-acceptance", messageID: "message", id: `call-${++serial}`, agent: "build" })) as Promise<any>,
    failure: async (input: unknown) => {
      const exit = await Effect.runPromise(Effect.exit(tools.get("shell").execute(input,
        { sessionID: "windows-acceptance", messageID: "message", id: `call-${++serial}`, agent: "build" })))
      if (!Exit.isFailure(exit)) throw new Error("Expected the Windows call to be refused")
      const error = Cause.findErrorOption(exit.cause)
      return Option.isSome(error) ? error.value as any : undefined
    },
    permission: (text: string) => Effect.runPromise(commands.get("perm")({ sessionID: "windows-acceptance", prompt: { text } })),
    bypass: (text: string) => Effect.runPromise(commands.get("bypass")({ sessionID: "windows-acceptance", prompt: { text } })),
  }
}

windowsDescribe("Windows native executor → preflight → OS sandbox", () => {
  beforeAll(async () => {
    fixture = await mkdtemp(path.join(homedir(), ".opencode-windows-acceptance-"))
    workspace = path.join(fixture, "workspace")
    outside = path.join(fixture, "outside")
    scratch = await mkdtemp(path.join(tmpdir(), "opencode-windows-scratch-"))
    await Promise.all([mkdir(workspace), mkdir(outside)])
    // Keep contract-failure coverage independent of whether the real backend
    // is currently available. This fixture cannot execute a shell payload.
    contractProbe = path.join(fixture, "contract-probe.exe")
    const probeSource = path.join(fixture, "contract-probe.cs")
    await writeFile(probeSource, `
using System;
static class ContractProbe {
    static int Main(string[] args) {
        if (args.Length != 1 || args[0] != "--probe") return 125;
        Console.WriteLine(@"{""version"":1,""backend"":""windows-lpac"",""available"":false,""contractFailure"":true}");
        return 0;
    }
}
`)
    // Windows' inbox compiler avoids a Rust toolchain requirement for these
    // host-boundary tests. The fixture never executes any command argument.
    const compiler = path.join(process.env.WINDIR!, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe")
    await new Promise<void>((resolve, reject) => {
      execFile(compiler, ["/nologo", "/target:exe", "/platform:x64", `/out:${contractProbe}`, probeSource], { timeout: 30_000 }, (error, stdout, stderr) => {
        if (error) reject(new Error(`Cannot build the Windows contract fixture: ${stdout}${stderr}`, { cause: error }))
        else resolve()
      })
    })
  }, 30_000)
  afterAll(async () => {
    for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
    for (const child of children) {
      if (child.exitCode === null) child.kill()
    }
    if (fixture) await rm(fixture, { recursive: true, force: true })
    if (scratch) await rm(scratch, { recursive: true, force: true })
  })

  test("a failed native security contract cannot fail open or start the original executor", async () => {
    const host = await harness({ helperPath: contractProbe })
    const destination = path.join(workspace, "contract-failure.txt")
    const failure = await host.failure({ command: `[System.IO.File]::WriteAllText(${powershellLiteral(destination)}, 'must-not-run')` })
    expect(failure?._tag).toBe("Tool.Error")
    expect(failure.message).toContain("security acceptance")
    expect(host.processes).toHaveLength(0)
    expect(await readFile(destination, "utf8").catch(() => undefined)).toBeUndefined()
  }, 30_000)

  test("fail-open preparation cannot waive a static floor", async () => {
    // The destructive sample is only an opaque argument to this compiled
    // fixture. It cannot execute commands even if the floor guard regresses.
    const fakePowerShell = path.join(fixture, "pwsh.exe")
    await copyFile(contractProbe, fakePowerShell)
    const host = await harness({ helperPath: path.join(fixture, "missing-helper.exe"), shell: fakePowerShell })
    const command = String.raw`Remove-Item -Path "C:\" -Recurse -Force`
    const classification = await classifyShellCommand({ script: command, cwd: workspace,
      worktree: workspace, shell: fakePowerShell, strictness: "LOOSE" })
    expect(classification.rules).toContain("filesystem.root-delete")
    const failure = await host.failure({ command })
    expect(failure?._tag).toBe("Tool.Error")
    expect(failure.message).toContain("Static restriction")
    expect(host.processes).toHaveLength(0)
  }, 30_000)

  test("disabling only Windows isolation still honors a dynamic denial", async () => {
    for (const sandbox of [{ enabled: false }, { mode: "full" as const }, { mode: "auto" as const }]) {
      const host = await harness({ denied: true, sandbox, helperPath: contractProbe })
      if (sandbox.mode === "auto") await host.bypass("sandbox")
      const destination = path.join(workspace, "disabled-isolation-denied.txt")
      const failure = await host.failure({ command: `[System.IO.File]::WriteAllText(${powershellLiteral(destination)}, 'must-not-run')` })
      expect(failure?._tag).toBe("Tool.Error")
      expect(host.processes).toHaveLength(0)
      expect(host.reviews).toHaveLength(1)
      expect(host.reviews[0]!.sandbox.trigger).toBe("Windows host-direct launch preflight")
      expect(host.reviews[0]!.input_facts.join("\n")).toContain("without private HOME/TEMP")
      expect(await readFile(destination, "utf8").catch(() => undefined)).toBeUndefined()
    }
  }, 30_000)

  test("native writes reject NTFS streams before any host filesystem mutation", async () => {
    const host = await harness({ helperPath: contractProbe })
    const target = path.join(workspace, "ads-protected.txt")
    await writeFile(target, "original")
    for (const suffix of [":stream", ":$DATA", "::$DATA"]) {
      await expect(host.write({ path: target + suffix, content: "forbidden" })).rejects.toThrow()
    }
    expect(await readFile(target, "utf8")).toBe("original")
    expect(await readFile(target + ":stream", "utf8").catch(() => undefined)).toBeUndefined()
    expect(host.reviews).toHaveLength(0)
  }, 30_000)

  test("an earlier preparation failure cannot fail open an unsupported Windows file path", async () => {
    const redirectedScratch = path.join(fixture, "redirected-scratch")
    await symlink(scratch, redirectedScratch, "junction")
    try {
      const host = await harness({ scratch: redirectedScratch, helperPath: contractProbe })
      const target = path.join(workspace, "early-failure-protected.txt")
      await writeFile(target, "original")
      await expect(host.write({ path: target + ":stream", content: "forbidden" })).rejects.toThrow("alternate data stream")
      expect(await readFile(target, "utf8")).toBe("original")
      expect(await readFile(target + ":stream", "utf8").catch(() => undefined)).toBeUndefined()
      expect(host.reviews).toHaveLength(0)
    } finally {
      await unlink(redirectedScratch)
    }
  }, 30_000)

  test("dangerous TEMP roots and a junction to HOME cannot widen native read-only writes", async () => {
    const originalTemp = process.env.TEMP
    const junction = path.join(fixture, "temp-junction")
    await symlink(homedir(), junction, "junction")
    try {
      for (const temporary of [homedir(), path.parse(homedir()).root, junction]) {
        process.env.TEMP = temporary
        const host = await harness({ helperPath: contractProbe })
        await host.permission("readonly")
        const target = path.join(workspace, "dangerous-temp-write.txt")
        await expect(host.write({ path: target, content: "forbidden" })).rejects.toThrow()
        expect(await readFile(target, "utf8").catch(() => undefined)).toBeUndefined()
        expect(host.reviews).toHaveLength(0)
      }
    } finally {
      if (originalTemp === undefined) delete process.env.TEMP
      else process.env.TEMP = originalTemp
      await unlink(junction)
    }
  }, 30_000)

  acceptanceTest("uses the actual shell, includes trusted instructions and keeps the OS boundary after approval", async () => {
    const host = await harness()
    const destination = path.join(workspace, "approved.txt")
    const result = await host.run({ command: `[System.IO.File]::WriteAllText(${powershellLiteral(destination)}, 'approved'); [Console]::WriteLine('done')` })
    expect(result.output.exit).toBe(0)
    expect(result.metadata.boundary.executionRoute).toBe("windows_sandbox")
    expect(await readFile(destination, "utf8")).toBe("approved")
    expect(host.reviews.length).toBeGreaterThan(0)
    expect(host.reviews[0]!.trusted_instructions?.some((instruction) => instruction.text.includes("acceptance work"))).toBe(true)
    expect(host.reviews[0]!.environment).toContain("pwsh")
  }, 30_000)

  acceptanceTest("a real denial cannot fail open or execute a refusal shell", async () => {
    const host = await harness({ denied: true })
    const destination = path.join(workspace, "denied.txt")
    const failure = await host.failure({ command: `[System.IO.File]::WriteAllText(${powershellLiteral(destination)}, 'must-not-exist')` })
    expect(failure?._tag).toBe("Tool.Error")
    expect(await readFile(destination, "utf8").catch(() => undefined)).toBeUndefined()
  }, 30_000)

  acceptanceTest("Windows signed exit status is not mistaken for a broken control channel", async () => {
    const host = await harness()
    const result = await host.run({ command: "exit -1" })
    expect(result.output.exit).not.toBe(0)
    expect(result.metadata.boundary.executionRoute).toBe("windows_sandbox")
  }, 30_000)

  networkTest("an explicit network grant reaches the authorized test endpoint", async () => {
    const host = await harness({ network: true })
    const endpoint = new URL(process.env.OPENCODE_WINDOWS_TEST_ENDPOINT!)
    const address = powershellLiteral(endpoint.hostname)
    const port = Number(endpoint.port)
    const result = await host.run({ command: `$client = [Net.Sockets.TcpClient]::new(); try { $client.ConnectAsync(${address}, ${port}).WaitAsync([TimeSpan]::FromSeconds(5)).GetAwaiter().GetResult(); [Console]::WriteLine($client.Connected) } finally { $client.Dispose() }` })
    expect(result.output.exit).toBe(0)
    expect(result.content).toContain("True")
    expect(result.metadata.boundary.executionRoute).toBe("windows_sandbox")
  }, 30_000)

  acceptanceTest("Read only prevents nested external writes even when the reviewer approves", async () => {
    const host = await harness()
    await host.permission("readonly")
    const destination = path.join(outside, "readonly-escape.txt")
    await host.failure({ command: `$target = [IO.Path]::Combine(${powershellLiteral(outside)}, 'readonly-escape.txt'); [IO.File]::WriteAllText($target, 'blocked')` })
    expect(await readFile(destination, "utf8").catch(() => undefined)).toBeUndefined()
  }, 30_000)

  acceptanceTest("a background command is terminated when its session permissions are revoked", async () => {
    const host = await harness()
    const result = await host.run({ command: "[Console]::WriteLine('started'); Start-Sleep -Seconds 30", background: true })
    expect(result.output.status).toBe("running")
    await Promise.race([
      host.processes[0]!.started,
      host.processes[0]!.done.then((completion) => {
        throw new Error(`The Windows payload exited before starting: ${completion.output}`)
      }),
    ])
    await host.permission("readonly")
    const completion = await Promise.race([
      host.processes[0]!.done,
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("Windows background revocation timed out")), 8_000)),
    ])
    expect(completion.exit).not.toBe(0)
  }, 30_000)

  acceptanceTest("native file tools enforce Windows read-only and resolve junction targets before review", async () => {
    const host = await harness()
    const destination = path.join(workspace, "native-write.txt")
    await host.write({ path: destination, content: "first" })
    expect(await readFile(destination, "utf8")).toBe("first")
    const controlState = path.join(process.env.LOCALAPPDATA!, "opencode-windows-sandbox-state")
    expect((await stat(controlState)).isDirectory()).toBe(true)
    // A directory target cannot be overwritten even if this guard regresses;
    // require our protected-path rejection, not a later filesystem EISDIR.
    await expect(host.write({ path: controlState, content: "forbidden" })).rejects.toThrow("Write protection")
    await host.permission("readonly")
    await expect(host.write({ path: destination, content: "forbidden" })).rejects.toThrow()
    expect(await readFile(destination, "utf8")).toBe("first")

    const denied = await harness({ denied: true })
    const junction = path.join(workspace, "outside-junction")
    await symlink(outside, junction, "junction")
    try {
      await expect(denied.write({ path: path.join(junction, "escape.txt"), content: "forbidden" })).rejects.toThrow()
      expect(await readFile(path.join(outside, "escape.txt"), "utf8").catch(() => undefined)).toBeUndefined()
      expect(denied.reviews[0]!.sandbox.resolved_writes).toContain(path.join(outside, "escape.txt"))
    } finally {
      await unlink(junction)
    }
  }, 30_000)
})

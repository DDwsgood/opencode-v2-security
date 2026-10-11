import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { execFile } from "node:child_process"
import { chmod, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import frozen from "../src/security/v10-8-pipeexec.json"
import { adjudicateEffectAnswers, type EffectReviewRequest } from "../src/security/effects-reviewer"
import { cleanupTestArtifacts } from "./artifacts"

let root: string, workspace: string, outside: string, scratch: string, probe: string
const scopes: Scope.Closeable[] = []
beforeAll(async () => {
  root = await mkdtemp("/tmp/opencode/runtime-host-")
  workspace = path.join(root, "workspace")
  outside = path.join(root, "outside")
  scratch = path.join(root, "scratch")
  await Promise.all([mkdir(workspace), mkdir(outside), mkdir(scratch)])
  probe = path.join(root, "probe-fixture")
  await writeFile(probe, "#!/bin/sh\nprintf 'bwrap: /usr/bin/bwrap\\nuserns: yes\\nlandlock_abi: 7\\nsandbox_path: full\\n'\n", { mode: 0o700 })
})
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})
const quote = (text: string) => `'${text.replaceAll("'", "'\\''")}'`
const python = (code: string) => `python3 -c ${quote(code)}`
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

async function harness(deny = false) {
  const hooks = new Map<string, (event: any) => Effect.Effect<any, any>>()
  const commands = new Map<string, any>()
  const calls: EffectReviewRequest[] = []
  const notifications: any[] = []
  const retained = [{ type: "user", text: "Operate on the named fixture files and directories for this acceptance test." }]
  const tools = new Map<string, any>()
  let executed = 0, serial = 0
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
      const output = yield* Effect.promise(() => new Promise<{ output: string; exit: number; status?: string }>((resolve) => {
        if (input.background) {
          // Host shape: background=true returns status:"running" at once and
          // keeps the process alive; the exit frame arrives over the broker.
          execFile(spawn.shell === "/bin/sh" ? "/bin/sh" : "/bin/bash",
            ["-c", spawn.command],
            { cwd: spawn.cwd, env: spawn.env, timeout: 15_000 })
          resolve({ output: "", exit: 0, status: "running" })
          return
        }
        // Honor spawn.shell: the host resolves the shell before the hook
        // and spawns invocation.shell — the watcher wrap may switch it.
        execFile(spawn.shell, ["-c", spawn.command], { cwd: spawn.cwd, env: spawn.env, timeout: 15_000, maxBuffer: 1024 * 1024 },
          (error, stdout, stderr) => resolve({ output: stdout + stderr, exit: typeof error?.code === "number" ? error.code : error ? 1 : 0 }))
      }))
      return { output, content: output.output, metadata: {} }
    }),
  })
  const ctx: any = {
    options: { sandbox: { enabled: true, mode: "auto", scratch, helperPath: probe }, slowCommands: false, logReviewerTrace: false,
      dynamicReview: { jev: { enabled: false } }, permission: { registerTool: false },
      reviewCommand: async (request: EffectReviewRequest) => {
        calls.push(structuredClone(request))
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
      synthetic: (input: any) => Effect.sync(() => { notifications.push(structuredClone(input)) }) },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  return {
    calls, notifications, get executed() { return executed },
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
  }
}

describe("real observer → broker → frozen reviewer → original process", () => {
  test("an inspection gap still reaches a floor denial as a proper Tool.Error", async () => {
    const host = await harness(true)
    const directory = path.join(outside, "uninspectable")
    await mkdir(directory)
    await chmod(directory, 0)
    try {
      const failure = await host.failure("write", { path: path.join(directory, "fixture.txt"), content: "fixture" })
      expect(failure._tag).toBe("Tool.Error")
      expect(failure.message).toContain("Command blocked:")
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
  test("runtime refusal blocks the crossing, not falsely all earlier steps", async () => {
    const host = await harness(true)
    const counter = path.join(workspace, "before-refusal.txt"), target = path.join(outside, "denied.txt")
    await writeFile(target, "UNCHANGED")
    const result = await host.run("shell", { command: python(`open(${JSON.stringify(counter)},'a').write('A'); open(${JSON.stringify(target)},'w').write('replacement')`) })
    expect(result.output.exit).not.toBe(0)
    expect(await readFile(counter, "utf8")).toBe("A")
    expect(await readFile(target, "utf8")).toBe("UNCHANGED")
    expect(result.content).toContain("Command blocked:")
    expect(result.content).toContain("earlier steps")
    expect(result.content).not.toContain("The whole command was not run.")
    expect(host.calls).toHaveLength(1)
    // Entry-gate refusal keeps its honest wording: the operation was
    // paused before its boundary effect and was not performed.
    expect(host.calls[0].input_facts[0]).toContain("paused this operation before its boundary effect")
    expect(result.content).toContain("was not performed")
  })
  test("a boundary event without atExit is reviewed and refused as phase-unknown", async () => {
    const host = await harness(true)
    const target = path.join(outside, "unknown-phase.txt")
    // Test-only helper switch: emit the event without details.atExit so
    // the phase-unknown path runs end to end.
    const result = await host.run("shell", {
      command: python(`open(${JSON.stringify(target)},'w').write('x')`),
      env: { BW_TEST_OMIT_ATEXIT: "1" },
    })
    expect(result.output.exit).not.toBe(0)
    expect(host.calls).toHaveLength(1)
    // Unknown phase must not claim the operation was paused before its
    // effect — it may or may not have run.
    expect(host.calls[0].input_facts[0]).toContain("may or may not have run")
    expect(host.calls[0].input_facts[0]).not.toContain("paused this operation before its boundary effect")
    expect(host.calls[0].input_facts[0]).not.toContain("already ran")
    // And the appended refusal notice must not claim the operation was
    // not performed. (The helper's own stderr may truthfully say "The
    // boundary operation was not performed" — it knows the stop was an
    // entry stop; only the notice wording is phase-derived.)
    expect(result.content).toContain("Command blocked:")
    expect(result.content).toContain("The command was stopped")
    expect(result.content).not.toContain("The blocked boundary operation was not performed")
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
  test("mode revocation and new true-user authorization invalidate prior grants", async () => {
    const host = await harness()
    const target = path.join(outside, "scope-changes.txt")
    await host.run("write", { path: target, content: "first" })
    await host.command("ro"); await host.command("auto")
    await host.run("write", { path: target, content: "second" })
    expect(host.calls).toHaveLength(2)
    host.newUserMessage("Write the named fixture again for the next task.")
    await host.run("write", { path: target, content: "third" })
    expect(host.calls).toHaveLength(3)
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
    const host = await harness()
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
    const run = await host.run("shell", { command: `touch ${marker}; echo RAN`, env })
    expect(run.output.exit).toBe(126)
    expect(run.output.output).toContain("could not be placed into supervised storage")
    // The denial shell ran with LD_* emptied: no loader complaint about
    // the nonexistent preload library may appear in its output.
    expect(run.output.output).not.toContain("cannot be preloaded")
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
  test("ReadOnly keeps global temp directories writable, but not the workspace inside them", async () => {
    const host = await harness()
    await host.command("ro")
    const temp = path.join(outside, "ro-temp.txt")
    const literal = await host.run("shell", { command: `echo literal > ${temp}` })
    expect(literal.output.exit).toBe(0)
    const opaque = await host.run("shell", { command: python(`open(${JSON.stringify(temp)},'a').write('more')`) })
    expect(opaque.output.exit).toBe(0)
    expect(await readFile(temp, "utf8")).toBe("literal\nmore")
    const blocked = await host.run("shell", { command: python(`open(${JSON.stringify(path.join(workspace, "ro-blocked.txt"))},'w').write('x')`) })
    expect(blocked.output.exit).not.toBe(0)
    await expect(readFile(path.join(workspace, "ro-blocked.txt"), "utf8")).rejects.toMatchObject({ code: "ENOENT" })
    await expect(host.run("shell", { command: "touch ro-literal.txt" })).rejects.toThrow("[Read only]")
    expect(host.calls).toHaveLength(0)
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

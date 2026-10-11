// Feature: a linked git worktree's private metadata dir as a shell write root.
//
// In a linked worktree, `cwd/.git` is a FILE pointing at the worktree's
// private directory `<common>/.git/worktrees/<name>` — outside the workspace.
// Git's routine bookkeeping (index refresh, HEAD, reflogs) writes there, so
// without the extra root every `git status` in a linked worktree costs a
// runtime boundary review. linkedWorktreePrivateDir verifies the pointer
// round-trip before the runBoundaryBefore shell path adds it — and only in
// sessions that can write (Auto), never in ReadOnly, never for native file
// tools. These tests use REAL temporary repositories under /tmp/opencode.

import { afterAll, beforeAll, describe, expect, mock, test } from "bun:test"
import { execFile } from "node:child_process"
import { mkdtemp, mkdir, readFile, realpath, writeFile } from "node:fs/promises"
import path from "node:path"
import { promisify } from "node:util"
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
const { linkedWorktreePrivateDir } = await import("../src/security/worktree-roots")
const { rootWideningCandidates } = await import("../src/security/root-widening")
const { adjudicateEffectAnswers } = await import("../src/security/effects-reviewer")
import type { EffectReviewRequest } from "../src/security/effects-reviewer"
const frozen = (await import("../src/security/v10-8-pipeexec.json")).default

const exec = promisify(execFile)
const git = (...args: string[]) => exec("git", args)

let root: string
let main: string
let linked: string
let other: string
let privateDir: string
beforeAll(async () => {
  root = await mkdtemp("/tmp/opencode/worktree-roots-")
  main = path.join(root, "main")
  await mkdir(main)
  await git("-C", main, "init", "--quiet")
  await git("-C", main, "config", "user.email", "test@example.invalid")
  await git("-C", main, "config", "user.name", "test")
  await git("-C", main, "commit", "--quiet", "--allow-empty", "-m", "init")
  linked = path.join(root, "linked")
  other = path.join(root, "other")
  await git("-C", main, "worktree", "add", "--quiet", "--detach", linked)
  await git("-C", main, "worktree", "add", "--quiet", "--detach", other)
  // Ask git itself where the private dir is rather than re-deriving its name.
  privateDir = await realpath((await git("-C", linked, "rev-parse", "--git-dir")).stdout.trim())
})
const scopes: Scope.Closeable[] = []
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  await cleanupTestArtifacts(root, { recursive: true, force: true })
})

describe("linkedWorktreePrivateDir verification", () => {
  test("a real linked worktree's .git file disqualifies its directory from L3", async () => {
    expect((await readFile(path.join(linked, ".git"), "utf8")).startsWith("gitdir:")).toBe(true)
    const policy = { home: path.join(root, "fixture-home"), cwd: other, credentialPaths: [], denyWrite: [], protect: [] }
    expect(await rootWideningCandidates(linked, policy, other, [privateDir])).toEqual([])
    expect(await rootWideningCandidates(privateDir, policy, other, [privateDir])).toEqual([])
  })

  test("a real linked worktree resolves to <common>/.git/worktrees/<name>", async () => {
    expect(await linkedWorktreePrivateDir(linked)).toBe(privateDir)
    expect(privateDir).toBe(path.join(await realpath(path.join(main, ".git")), "worktrees", path.basename(privateDir)))
  })

  test("an ordinary repository checkout (.git directory) yields no extra root", async () => {
    expect(await linkedWorktreePrivateDir(main)).toBeUndefined()
  })

  test("a .git file naming ANOTHER worktree's private dir is rejected", async () => {
    const otherPrivate = await realpath((await git("-C", other, "rev-parse", "--git-dir")).stdout.trim())
    const forged = path.join(root, "forged-other")
    await mkdir(forged)
    await writeFile(path.join(forged, ".git"), `gitdir: ${otherPrivate}\n`)
    // The pointer is valid and fully verified — but its private dir's own
    // gitdir file points back at `other`, not at this workspace.
    expect(await linkedWorktreePrivateDir(forged)).toBeUndefined()
  })

  test("a .git file naming the common .git directory itself is rejected", async () => {
    const forged = path.join(root, "forged-common")
    await mkdir(forged)
    await writeFile(path.join(forged, ".git"), `gitdir: ${await realpath(path.join(main, ".git"))}\n`)
    expect(await linkedWorktreePrivateDir(forged)).toBeUndefined()
  })

  test("a crafted directory with a commondir file but no back-pointer is rejected", async () => {
    const crafted = path.join(root, "crafted-private")
    await mkdir(crafted)
    await writeFile(path.join(crafted, "commondir"), `${await realpath(path.join(main, ".git"))}\n`)
    const forged = path.join(root, "forged-crafted")
    await mkdir(forged)
    await writeFile(path.join(forged, ".git"), `gitdir: ${crafted}\n`)
    // Fails the <commondir>/worktrees/<name> placement rule before the
    // back-pointer is even consulted.
    expect(await linkedWorktreePrivateDir(forged)).toBeUndefined()
  })

  test("unparseable or dangling pointers yield no root", async () => {
    const garbage = path.join(root, "garbage-pointer")
    await mkdir(garbage)
    await writeFile(path.join(garbage, ".git"), "this is not a gitdir pointer\n")
    expect(await linkedWorktreePrivateDir(garbage)).toBeUndefined()
    const dangling = path.join(root, "dangling-pointer")
    await mkdir(dangling)
    await writeFile(path.join(dangling, ".git"), `gitdir: ${path.join(root, "missing-private")}\n`)
    expect(await linkedWorktreePrivateDir(dangling)).toBeUndefined()
    expect(await linkedWorktreePrivateDir(path.join(root, "no-such-worktree"))).toBeUndefined()
  })
})

// --- integration: the private dir reaches shell write roots in Auto only ---

const report = (readonly = false, deny = false) => {
  const answers: Record<string, unknown> = {}
  for (const [id, q] of Object.entries(frozen.questions)) {
    answers[id] = q.type === "noul" ? { noul: 0 } : { choice: Object.keys((q as { criteria: Record<string, string> }).criteria)[0] }
  }
  answers.floor = { choice: deny ? "yes" : "no" }
  answers.scope_coverage = { choice: "within_request" }
  if (readonly) answers.readonly_conformance = { choice: "read_only" }
  return adjudicateEffectAnswers(answers, readonly)
}

/** One plugin instance over the real boundary observer, with the linked
 *  worktree as the session workspace. Commands genuinely run — a write that
 *  is not inside a granted root produces a runtime boundary event and one
 *  review call. */
async function harness(deny = false) {
  resetSharedSecurityStateForTests()
  const hooks = new Map<string, (event: any) => Effect.Effect<any, any>>()
  const commands = new Map<string, any>()
  const calls: EffectReviewRequest[] = []
  const retained = [{ type: "user", text: "Run the named git and file operations inside the linked worktree." }]
  const scratch = path.join(root, "scratch-harness")
  const outside = path.join(root, "outside-harness")
  const probe = path.join(root, "probe-fixture")
  await Promise.all([
    mkdir(scratch, { recursive: true }), mkdir(outside, { recursive: true }),
    writeFile(probe, "#!/bin/sh\nprintf 'bwrap: /usr/bin/bwrap\\nuserns: yes\\nlandlock_abi: 7\\nsandbox_path: full\\n'\n", { mode: 0o700 }),
  ])
  const tools = new Map<string, any>([
    ["shell", {
      id: "shell", name: "shell", options: { codemode: false }, input: { type: "object", properties: {} },
      execute: (input: any, call: any) => Effect.gen(function* () {
        const permission = { sessionID: call.sessionID, action: "shell", resources: ["*"],
          source: { type: "tool", messageID: call.messageID, id: call.id }, effect: "ask" }
        yield* hooks.get("permission.evaluate")!(permission)
        if (permission.effect === "deny") return yield* Effect.fail(new Error(permission.message))
        const spawn = { command: input.command, cwd: input.workdir ?? linked, shell: "/bin/bash", env: { ...process.env, ...input.env } }
        yield* hooks.get("shell.create.before")!(spawn)
        const output = yield* Effect.promise(() => new Promise<{ output: string; exit: number; status?: string }>((resolve) => {
          execFile(spawn.shell, ["-c", spawn.command], { cwd: spawn.cwd, env: spawn.env, timeout: 15_000, maxBuffer: 1024 * 1024 },
            (error, stdout, stderr) => resolve({ output: stdout + stderr, exit: typeof error?.code === "number" ? error.code : error ? 1 : 0 }))
        }))
        return { output, content: output.output, metadata: {} }
      }),
    }],
  ])
  let serial = 0
  let statusHandler: any
  const ctx: any = {
    options: { sandbox: { enabled: true, mode: "auto", scratch, helperPath: probe }, slowCommands: false, logReviewerTrace: false,
      dynamicReview: { jev: { enabled: false } }, permission: { registerTool: false },
      reviewCommand: async (request: EffectReviewRequest) => {
        calls.push(structuredClone(request))
        return report(request.input_facts.includes("Session security mode: [Read only]"), deny)
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
    session: { get: () => Effect.succeed({ location: { directory: linked } }), context: () => Effect.succeed(retained),
      synthetic: () => Effect.sync(() => {}) },
    rpc: { register: (_definition: unknown, handlers: any) =>
      Effect.sync(() => { statusHandler = handlers.status; return { events: { emit: () => Effect.void } } }) },
    event: { subscribe: () => Stream.fromIterable([]) },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  return {
    calls, outside,
    run: (command: string) =>
      Effect.runPromise(tools.get("shell")!.execute({ command }, { sessionID: "worktree", messageID: "m", id: `call-${++serial}`, agent: "build" })) as Promise<any>,
    command: (text: string) => Effect.runPromise(commands.get("perm")({ sessionID: "worktree", prompt: { text } })),
    status: () => Effect.runPromise(statusHandler({ sessionID: "worktree" })),
  }
}

describe("worktree private dir as a shell write root", () => {
  test("private worktree roots keep sensitive writes observed while ordinary writes skip review", async () => {
    const host = await harness(true)
    const plain = await host.run(`printf fixture > ${path.join(privateDir, "observed-plain.log")}`)
    expect(plain.output.exit).toBe(0)
    expect(host.calls).toHaveLength(0)
    const sensitive = path.join(privateDir, "observed-private.key")
    const refused = await host.run(`python3 -c 'open("${sensitive}", "w").write("FAKE TEST DATA")'`)
    expect(refused.output.exit).toBe(126)
    expect(host.calls).toHaveLength(1)
    await expect(readFile(sensitive)).rejects.toMatchObject({ code: "ENOENT" })
  })

  test("Auto: git index bookkeeping and direct writes in the private dir skip review", async () => {
    const host = await harness()
    // git status refreshes the worktree index inside the private dir —
    // outside the workspace, so without the extra root this is a runtime
    // write-boundary review. A direct write makes the same point explicit.
    const status = await host.run("git status --porcelain")
    expect(status.output.exit).toBe(0)
    const target = path.join(privateDir, "root-probe.txt")
    const write = await host.run(`printf 'probe' > ${target}`)
    expect(write.output.exit).toBe(0)
    expect(await readFile(target, "utf8")).toBe("probe")
    expect(host.calls).toHaveLength(0)
    // Control: the same write one level outside the private dir still costs
    // a review — the root did not widen past its exact directory. The common
    // .git directory (objects, refs) is NOT part of the grant either.
    const beyond = await host.run(`printf 'beyond' > ${path.join(host.outside, "beyond.txt")}`)
    expect(beyond.output.exit).toBe(0)
    const common = await host.run(`printf 'x' > ${path.join(main, ".git", "common-probe.txt")}`)
    expect(common.output.exit).toBe(0)
    expect(host.calls).toHaveLength(2)
    expect(host.calls[0].sandbox.trigger).toBe("runtime write boundary")
    expect(host.calls[1].sandbox.trigger).toBe("runtime write boundary")
  })

  test("ReadOnly does not advertise the private dir among its writable roots", async () => {
    const host = await harness()
    await host.command("ro")
    expect((await host.status()).mode).toBe("readonly")
    // Under /tmp every path is inside a global ReadOnly temp root, so an RO
    // write cannot observe the difference through the filesystem. What RO
    // must not do is tell the reviewer the private dir is a permitted write
    // root: trigger one reviewed outside read and inspect the advertised
    // writable roots verbatim.
    const secret = path.join(host.outside, "ro.env")
    await writeFile(secret, "TOKEN=fixture")
    const read = await host.run(`wc -c < ${secret}`)
    expect(read.output.exit).toBe(0)
    expect(host.calls).toHaveLength(1)
    const facts = host.calls[0].input_facts.join("\n")
    expect(facts).toContain("[Read only]")
    expect(facts).not.toContain(privateDir)
    expect(facts).not.toContain("worktrees/linked")
  })
})

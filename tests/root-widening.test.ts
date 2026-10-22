import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import { resolveSandbox } from "../src/config"
import { EFFECTS_MODEL } from "../src/security/effects-reviewer"
import {
  buildRootWideningBody, createRootWidening, L3_POLICY_VERSION, L3_QUESTION_TEXT, L3_STATE_TEXT, L3_WINDOW_MS,
  parseRootWideningChoice, reviewRootWidening, rootWideningCandidates,
  type L3Trace, type RootWideningInput, type RootWideningScope, type RootWideningStore,
} from "../src/security/root-widening"
import { registerRuntimeBrokerDirectory, resolveAllowWriteRoots, writeTargetExempt, type WriteRootPolicy } from "../src/security/write-root-policy"
import { credentialStoreReadPaths } from "../src/security/paths"
import type { RuntimeBoundaryEvent } from "../src/runtime-boundary"
import { cleanupTestArtifacts } from "./artifacts"

let root: string
let home: string
let logs: string
let workspace: string
let policy: WriteRootPolicy
beforeAll(async () => {
  root = await mkdtemp("/var/tmp/opencode-l3-roots-")
  home = path.join(root, "home")
  logs = path.join(home, ".local/share/opencode/log")
  workspace = path.join(root, "workspace")
  await mkdir(logs, { recursive: true })
  await mkdir(workspace)
  await writeFile(path.join(logs, "opencode.log"), "fixture")
  await writeFile(path.join(path.dirname(logs), "auth.json"), "FAKE TEST DATA")
  await writeFile(path.join(path.dirname(logs), "opencode.db"), "fixture")
  policy = { home, cwd: workspace, credentialPaths: credentialStoreReadPaths(home), denyWrite: [], protect: [path.join(root, "package"), path.join(root, "helper")], brokerBase: "/tmp/opencode" }
})
afterAll(async () => { await cleanupTestArtifacts(root, { recursive: true, force: true }) }, 30_000)

async function directory(name: string): Promise<string> {
  const target = path.join(home, name)
  await mkdir(target, { recursive: true })
  return target
}

const scope = (): RootWideningScope => ({ sessionID: "session", canWrite: true, userMessageDigest: "user", securitySnapshot: "auto-1" })
const event = (target: string, operation = "append"): RuntimeBoundaryEvent => ({
  version: 1, type: "boundary", eventID: 1, pid: 1, kind: "write", syscall: "openat", operation,
  targets: [{ path: target, exists: false }], details: { executable: "/usr/bin/opencode", requiresFullApproval: false },
})
const answer = (choice: string) => ({ answers: { widen_root: { choice } } })

function fixture(review: (input: RootWideningInput) => Promise<unknown> = async () => answer("root_1")) {
  let timestamp = 0
  let currentScope = scope()
  const requests: RootWideningInput[] = []
  const traces: L3Trace[] = []
  const store: RootWideningStore = { repetitions: new Map(), grants: new Map() }
  const waiters: Array<(trace: L3Trace) => void> = []
  const manager = createRootWidening({ now: () => timestamp, state: store,
    review: async (input) => { requests.push(input); return review(input) },
    trace: (trace) => {
      traces.push(trace)
      if (["l3_root_granted", "l3_root_declined", "l3_root_error"].includes(trace.kind)) waiters.shift()?.(trace)
    },
  })
  const record = (callID: string, target = path.join(logs, "opencode.log"), roots: string[] = []) => manager.recordAllowedWrite({
    scope: currentScope, callID, command: `opencode inspect ${callID}`, event: event(target), policy, workspace, currentRoots: roots,
    context: async () => ({ scope: currentScope, user_request: "Inspect OpenCode", session_context: ["user: Inspect OpenCode", "assistant: Checking status"] }),
  })
  return { manager, requests, traces, record, store,
    next: () => new Promise<L3Trace>((resolve) => waiters.push(resolve)),
    advance: (amount: number) => { timestamp += amount },
    change: (changes: Partial<RootWideningScope>) => { currentScope = { ...currentScope, ...changes } },
    active: () => manager.activeRoots(currentScope),
    exempt: (targets: string[], exclusions = policy) => manager.targetsExempt(currentScope, targets, exclusions),
  }
}

describe("configured allowWrite roots", () => {
  test("parses absolute paths, HOME expansion and missing descendants", () => {
    const parsed = resolveAllowWriteRoots(["~/.local/share/opencode/log", `${logs}/new/child`, logs], policy)
    expect(parsed.roots).toEqual([logs, `${logs}/new/child`])
    expect(parsed.warnings).toEqual([])
    expect(resolveSandbox({ allowWrite: [logs] }).allowWrite).toEqual([logs])
  })
  test("rejects malformed types and relative entries as validation errors", () => {
    for (const raw of ["/tmp/log", [42], [null], ["relative"], ["~someone/log"], [""]]) {
      expect(() => resolveSandbox({ allowWrite: raw })).toThrow("sandbox.allowWrite")
    }
    expect(resolveSandbox(undefined).allowWrite).toEqual([])
  })
  test("unsafe roots are skipped with exactly one warning each", () => {
    const denied = path.join(home, "denied")
    const protectedRoot = path.join(root, "package")
    const inputs = ["/", home, path.dirname(home), path.join(home, ".ssh"), path.join(home, ".ssh/log"),
      path.join(home, ".config"), denied, `${denied}/logs`, path.dirname(denied), protectedRoot, `${protectedRoot}/logs`,
      path.join(root, "helper"), "/tmp/opencode/security-boundary-fixture/log", `${logs}/private.key`, "/etc/ssh"]
    const unregister = registerRuntimeBrokerDirectory("/tmp/opencode/security-boundary-fixture")
    try {
      const result = resolveAllowWriteRoots(inputs, { ...policy, denyWrite: [denied] })
      expect(result.roots).toEqual([])
      expect(result.warnings).toHaveLength(inputs.length)
    } finally {
      unregister()
    }
    expect(resolveSandbox({ allowWrite: [logs], denyWrite: [logs] }).allowWriteWarnings).toHaveLength(1)
    expect(resolveSandbox({ allowWrite: [path.resolve(import.meta.dir, "..") ] }).allowWrite).toEqual([])
  })
  test("redirected, symlinked and dangling roots never grant", async () => {
    const link = path.join(home, "redirected")
    const dangling = path.join(home, "dangling")
    await symlink(logs, link)
    await symlink(path.join(home, "missing"), dangling)
    const result = resolveAllowWriteRoots([link, `${link}/new`, dangling], policy)
    expect(result.roots).toEqual([])
    expect(result.warnings).toHaveLength(3)
  })
  test("per-target denied, protected, credential and sensitive exclusions win", () => {
    const guard = { ...policy, denyWrite: [`${logs}/denied`], protect: [`${logs}/protected`], credentialPaths: [`${logs}/credentials`] }
    expect(writeTargetExempt(`${logs}/plain.log`, guard)).toBe(true)
    expect(writeTargetExempt(`${logs}/[...404].css`, guard)).toBe(true)
    for (const target of [`${logs}/denied/file`, `${logs}/protected/file`, `${logs}/credentials/file`, `${logs}/.env`, `${logs}/[route]/private.key`, logs]) {
      expect(writeTargetExempt(target, guard)).toBe(false)
    }
  })
  test("shared temp roots can be granted without granting broker descendants", () => {
    const brokerBase = path.join(logs, "broker")
    const guard = { ...policy, brokerBase }
    const reserved = path.join(brokerBase, "security-boundary-fixture", "observer.sock")
    const unregister = registerRuntimeBrokerDirectory(path.dirname(reserved))
    try {
      const parsed = resolveAllowWriteRoots([logs, brokerBase, path.dirname(reserved)], guard)
      expect(parsed.roots).toEqual([logs, brokerBase])
      expect(parsed.warnings).toHaveLength(1)
      expect(writeTargetExempt(path.join(brokerBase, "ordinary.txt"), guard)).toBe(true)
      expect(writeTargetExempt(path.join(brokerBase, "security-boundary-child", "observer.sock"), guard)).toBe(true)
      expect(writeTargetExempt(reserved, guard)).toBe(false)
    } finally {
      unregister()
    }
    expect(writeTargetExempt(reserved, guard)).toBe(true)
  })
})

describe("L3 candidate generation", () => {
  test("OpenCode auth and database siblings leave only the log directory", async () => {
    expect(await rootWideningCandidates(logs, policy, workspace, [workspace])).toEqual([
      { option: "root_1", path: logs, sample_entries: ["opencode.log"] },
    ])
  })
  test("narrowest first, at most four directories, stopping before HOME", async () => {
    const narrow = await directory("clean/a/b/c/d")
    expect((await rootWideningCandidates(narrow, policy, workspace, [])).map((candidate) => candidate.path)).toEqual([
      narrow, path.dirname(narrow), path.dirname(path.dirname(narrow)),
    ])
    const shallow = await directory("shallow/leaf")
    expect((await rootWideningCandidates(shallow, policy, workspace, [])).map((candidate) => candidate.path)).toEqual([shallow, path.dirname(shallow)])
    expect(await rootWideningCandidates(home, policy, workspace, [])).toEqual([])
    expect(await rootWideningCandidates("/", policy, workspace, [])).toEqual([])
  })
  test("workspace/current-root ancestors and excluded-path overlaps are dropped", async () => {
    const target = await directory("scoped/log")
    for (const blocked of [target, path.dirname(target), `${target}/child`]) {
      expect(await rootWideningCandidates(target, { ...policy, denyWrite: [blocked] }, workspace, [])).toEqual([])
      expect(await rootWideningCandidates(target, { ...policy, protect: [blocked] }, workspace, [])).toEqual([])
      expect(await rootWideningCandidates(target, { ...policy, credentialPaths: [blocked] }, workspace, [])).toEqual([])
    }
    expect(await rootWideningCandidates(target, policy, `${target}/workspace`, [])).toEqual([])
    expect(await rootWideningCandidates(target, policy, workspace, [`${target}/current-root`])).toEqual([])
    expect(await rootWideningCandidates(`${home}/.ssh`, policy, workspace, [])).toEqual([])
  })
  test("credential and high-value names are filtered before a request", async () => {
    const names = ["auth.json", "credentials.yaml", "secret.toml", "token.ini", "passwords.txt", "private.pem", "private.key",
      "cert.p12", "cert.pfx", "vault.kdbx", "key.gpg", "key.asc", "key.jks", "key.keystore", "id_rsa.old", "id_ed25519",
      ".env.production", "netrc", ".netrc", ".git-credentials", "cookie.sqlite", "cookies", "opencode.db", "state.sqlite",
      "state.sqlite3", "state.db-wal", "state.db-shm"]
    for (const [index, name] of names.entries()) {
      const target = await directory(`sensitive-${index}`)
      await writeFile(path.join(target, name), "FAKE TEST DATA")
      expect(await rootWideningCandidates(target, policy, workspace, [])).toEqual([])
    }
    const repository = await directory("repository/.git")
    expect(await rootWideningCandidates(path.dirname(repository), policy, workspace, [])).toEqual([])
  })
  test("nested high-value entries and truncated depth/entry scans drop candidates", async () => {
    const nested = await directory("nested/a/b")
    await writeFile(path.join(nested, "auth.json"), "FAKE TEST DATA")
    expect(await rootWideningCandidates(path.dirname(path.dirname(nested)), policy, workspace, [])).toEqual([])
    const deep = await directory("deep/a/b/c/d")
    expect(await rootWideningCandidates(path.dirname(path.dirname(path.dirname(path.dirname(deep)))), policy, workspace, [])).toEqual([])
    const crowded = await directory("crowded")
    await Promise.all(Array.from({ length: 5001 }, (_, index) => writeFile(path.join(crowded, `entry-${index}`), "")))
    expect(await rootWideningCandidates(crowded, policy, workspace, [])).toEqual([])
  }, 30_000)
  test("sample entries are bounded to twenty names", async () => {
    const target = await directory("sample")
    await Promise.all(Array.from({ length: 21 }, (_, index) => writeFile(path.join(target, `file-${index}.log`), "")))
    expect((await rootWideningCandidates(target, policy, workspace, []))[0].sample_entries).toHaveLength(20)
  })
})

describe("L3 official choice request", () => {
  const input = (): RootWideningInput => ({ user_request: "Inspect OpenCode", session_context: ["user: Inspect OpenCode"], repeated_directory: logs,
    events: [{ command: "opencode status", syscall: "openat", operation: "append", target: `${logs}/opencode.log`, executable: "opencode" }],
    candidates: [{ option: "root_1", path: logs, sample_entries: ["opencode.log"] }], current_write_roots: [workspace] })
  test("exact state/instructions, stable input JSON and object criteria", () => {
    const body = buildRootWideningBody(input())
    expect(Object.keys(body)).toEqual(["model", "state", "questions"])
    expect(body.model).toBe(EFFECTS_MODEL)
    expect(body.state.startsWith(`${L3_STATE_TEXT}\n\n<review_input>\n`)).toBe(true)
    expect(L3_STATE_TEXT).toBe("A coding agent runs shell commands under a sandbox. Inside a writable root every file operation (create, modify, append, delete, rename) runs without further review, exactly like /tmp. Outside writable roots each write pauses for an individual safety review. The recent commands below each wrote inside the same directory, and every one of those writes was individually reviewed and allowed. You decide whether one directory may become an additional writable root for this session temporarily (20 minutes, ended early by the user's next message or any permission change). Granting saves future reviews; it must never expose data whose loss, alteration or disclosure would matter.")
    expect(body.questions.widen_root.instructions).toBe(L3_QUESTION_TEXT)
    expect(L3_QUESTION_TEXT).toBe("Choose the single directory to add as a temporary writable root, or none. Prefer the narrowest candidate that still covers the repeated writes — normally the directory the writes land in. Choose a broader ancestor only when the evidence shows the same tools routinely write across its subdirectories and nothing in it is sensitive. Choose none when a candidate that would cover the writes also holds data that should not be freely modified or deleted (credentials, tokens, keys, auth or session files, configuration that changes program or security behaviour, version-controlled source, databases, user documents); when the writes look like a task-specific action rather than a tool's routine bookkeeping (logs, caches, locks, temporary or trim files, history); or when the user's request and recent context do not support continued use of these tools.")
    expect(body.questions.widen_root.criteria).toEqual({ root_1: `Grant ${logs} as a temporary writable root.`, none: "Grant nothing; keep reviewing each write individually." })
    expect(JSON.parse(body.state.split("<review_input>\n")[1].split("\n</review_input>")[0])).toEqual(input())
    expect(L3_POLICY_VERSION).toBe("l3-root-widen-v1")
  })
  test("only returned choice matters; unexpected/missing choices fail", () => {
    expect(parseRootWideningChoice({ answers: { widen_root: { choice: "none", probabilities: { root_1: 1, none: 0 } } } }, input().candidates)).toBe("none")
    for (const payload of [{}, answer("root_2"), answer("/unsafe"), { answers: { widen_root: { probabilities: { root_1: 1 } } } }]) {
      expect(() => parseRootWideningChoice(payload, input().candidates)).toThrow()
    }
  })
  test("separate fetch uses effects endpoint/key/model/timeout without network", async () => {
    let observed: RequestInit | undefined
    const result = await reviewRootWidening(input(), { endpoint: "https://example.invalid/jev", apiKey: "fake-test-key", timeoutMs: 10_000,
      fetch: (async (endpoint, init) => {
        expect(String(endpoint)).toBe("https://example.invalid/jev")
        observed = init
        return new Response(JSON.stringify(answer("root_1")))
      }) as typeof fetch })
    expect(parseRootWideningChoice(result, input().candidates)).toBe("root_1")
    expect(JSON.parse(observed!.body as string)).toEqual(buildRootWideningBody(input()))
    expect(observed!.headers).toMatchObject({ Authorization: "Bearer fake-test-key" })
    expect(observed!.signal).toBeInstanceOf(AbortSignal)
  })
  test("availability failures use ordered L3 backups with their own model and credentials", async () => {
    const calls: Array<{ url: string; model: string; authorization: string | null }> = []
    const fetchFn = (async (url: URL, init: RequestInit) => {
      calls.push({
        url: String(url),
        model: JSON.parse(init.body as string).model,
        authorization: new Headers(init.headers).get("Authorization"),
      })
      if (calls.length === 1) return new Response("provider body must not leak", { status: 503 })
      if (calls.length === 2) throw new Error("transport fixture")
      return new Response(JSON.stringify(answer("root_1")))
    }) as unknown as typeof fetch
    const result = await reviewRootWidening(input(), {
      endpoint: "https://primary.invalid/jev",
      apiKey: "primary-key",
      model: "clef",
      fallbacks: [
        { endpoint: "https://second.invalid/jev", apiKey: "second-key", model: "typesafe/jev" },
        { endpoint: "https://third.invalid/jev", apiKey: "third-key", model: "jev-latest" },
      ],
      fetch: fetchFn,
    })
    expect(parseRootWideningChoice(result, input().candidates)).toBe("root_1")
    expect(calls.map((call) => [call.model, call.authorization])).toEqual([
      ["clef", "Bearer primary-key"],
      ["typesafe/jev", "Bearer second-key"],
      ["jev-latest", "Bearer third-key"],
    ])
  })
  test("a valid L3 choice is final and local endpoint config is never retried elsewhere", async () => {
    let calls = 0
    const tracked = (async () => { calls++; return new Response(JSON.stringify(answer("none"))) }) as unknown as typeof fetch
    const result = await reviewRootWidening(input(), {
      endpoint: "https://primary.invalid/jev", apiKey: "primary-key",
      fallbacks: [{ endpoint: "https://second.invalid/jev", apiKey: "second-key" }], fetch: tracked,
    })
    expect(parseRootWideningChoice(result, input().candidates)).toBe("none")
    expect(calls).toBe(1)
    for (const fallbacks of [
      [{ endpoint: "http://remote.invalid/jev", apiKey: "second-key" }],
      [{ endpoint: "https://user:pass@second.invalid/jev", apiKey: "second-key" }],
    ]) {
      calls = 0
      await expect(reviewRootWidening(input(), {
        endpoint: "https://primary.invalid/jev", apiKey: "primary-key", fallbacks, fetch: tracked,
      })).rejects.toMatchObject({ kind: "protocol" })
      expect(calls).toBe(0)
    }
  })
})

describe("L3 repetition and temporary grants", () => {
  test("session cleanup removes grants and repetitions; access and sweeps prune stale directories", async () => {
    const state = fixture()
    const completed = state.next()
    for (const call of ["one", "two", "three"]) state.record(call)
    await completed
    expect(state.store.grants.size).toBe(1)
    expect(state.store.repetitions.size).toBe(1)
    state.manager.clearSession("session")
    expect(state.store.grants.size).toBe(0)
    expect(state.store.repetitions.size).toBe(0)
    state.record("stale")
    state.advance(L3_WINDOW_MS)
    state.active()
    expect(state.store.repetitions.size).toBe(0)
    state.record("stale-again")
    state.advance(L3_WINDOW_MS)
    state.manager.sweep()
    expect(state.store.repetitions.size).toBe(0)
    state.record("still-active")
    state.advance(L3_WINDOW_MS - 1)
    state.record("still-active")
    state.advance(2)
    state.manager.sweep()
    expect(state.store.repetitions.size).toBe(1)
    state.advance(L3_WINDOW_MS)
    state.manager.sweep()
    expect(state.store.repetitions.size).toBe(0)
  })

  test("three distinct tool calls trigger once; duplicate events do not count", async () => {
    const state = fixture()
    const completed = state.next()
    state.record("one")
    state.record("one", `${logs}/opencode.log.trim`)
    state.record("two")
    expect(state.requests).toHaveLength(0)
    state.record("three")
    state.record("four")
    await completed
    expect(state.requests).toHaveLength(1)
    expect(state.requests[0].events).toHaveLength(3)
    expect(new Set(state.requests[0].events.map((event) => event.command)).size).toBe(3)
    expect(state.requests[0].events[0].executable).toBe("opencode")
    expect(state.active()).toEqual([logs])
    // The background query starts after both synchronous records and snapshots
    // the latest three events, ending with the fourth command.
    expect(state.traces[0].command).toBe("opencode inspect four")
    expect(state.traces[0]).not.toHaveProperty("commandSha256")
  })
  test("old calls leave the sliding window", async () => {
    const state = fixture()
    const completed = state.next()
    state.record("old")
    state.advance(L3_WINDOW_MS)
    state.record("one")
    state.record("two")
    expect(state.requests).toHaveLength(0)
    state.record("three")
    await completed
    expect(state.requests[0].events.map((event) => event.command)).toEqual(["opencode inspect one", "opencode inspect two", "opencode inspect three"])
  })
  test("none suppresses the directory for twenty minutes", async () => {
    const state = fixture(async () => answer("none"))
    const first = state.next()
    for (const call of ["one", "two", "three"]) state.record(call)
    await first
    state.record("four")
    expect(state.requests).toHaveLength(1)
    expect(state.active()).toEqual([])
    state.advance(L3_WINDOW_MS)
    const second = state.next()
    for (const call of ["next-one", "next-two", "next-three"]) state.record(call)
    await second
    expect(state.requests).toHaveLength(2)
  })
  test("a slow background query never blocks the triggering call", async () => {
    let release!: (payload: unknown) => void
    let started!: () => void
    const entered = new Promise<void>((resolve) => { started = resolve })
    const state = fixture(async () => { started(); return new Promise((resolve) => { release = resolve }) })
    const completed = state.next()
    for (const call of ["one", "two", "three"]) expect(state.record(call)).toBeUndefined()
    await entered
    expect(state.active()).toEqual([])
    release(answer("root_1"))
    await completed
    expect(state.active()).toEqual([logs])
  })
  test("grant use covers all targets and retains per-target exclusions", async () => {
    const state = fixture()
    const completed = state.next()
    for (const call of ["one", "two", "three"]) state.record(call)
    await completed
    expect(state.exempt([`${logs}/new.log`, `${logs}/opencode.log.trim`])).toBe(true)
    expect(state.exempt([`${logs}/new.log`, `${home}/outside.log`])).toBe(false)
    expect(state.exempt([`${logs}/private.key`])).toBe(false)
    expect(state.exempt([`${logs}/blocked`], { ...policy, denyWrite: [`${logs}/blocked`] })).toBe(false)
    expect(state.exempt([])).toBe(false)
  })
  test("time, user message, security snapshot and readonly lazily expire grants", async () => {
    for (const reason of ["time", "user_message", "security_snapshot", "readonly"]) {
      const state = fixture()
      const completed = state.next()
      for (const call of ["one", "two", "three"]) state.record(call)
      await completed
      if (reason === "time") state.advance(L3_WINDOW_MS)
      if (reason === "user_message") state.change({ userMessageDigest: "new-user" })
      if (reason === "security_snapshot") state.change({ securitySnapshot: "auto-2" })
      if (reason === "readonly") state.change({ canWrite: false })
      expect(state.active()).toEqual([])
      expect(state.traces.at(-1)).toMatchObject({ kind: "l3_root_expired", reason })
      state.change(scope())
      expect(state.active()).toEqual([])
    }
  })
  test("Read only and writes inside current roots cannot trigger", () => {
    const state = fixture()
    state.change({ canWrite: false })
    for (const call of ["one", "two", "three"]) state.record(call)
    state.change({ canWrite: true })
    for (const call of ["four", "five", "six"]) state.record(call, `${logs}/opencode.log`, [logs])
    expect(state.requests).toEqual([])
    expect(state.active()).toEqual([])
  })
  test("JEV, protocol and scan errors silently produce no grant, never a refusal", async () => {
    for (const review of [async () => { throw new Error("provider failure") }, async () => answer("unknown")]) {
      const state = fixture(review)
      const completed = state.next()
      for (const call of ["one", "two", "three"]) expect(state.record(call)).toBeUndefined()
      expect((await completed).kind).toBe("l3_root_error")
      expect(state.active()).toEqual([])
    }
    const state = fixture()
    const completed = state.next()
    const missing = `${home}/not-created/log.txt`
    for (const call of ["one", "two", "three"]) expect(state.record(call, missing)).toBeUndefined()
    expect((await completed).kind).toBe("l3_root_error")
    expect(state.requests).toEqual([])
    expect(state.active()).toEqual([])
  })
})

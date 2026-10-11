import { afterEach, describe, expect, test } from "bun:test"
import { connect, type Socket } from "node:net"
import { createRuntimeBoundaryBroker, knownSafeRuntimeBoundary, parseRuntimeBoundary, runtimeWriteEffect, staticCrossingReview, type RuntimeBoundaryBroker, type RuntimeBoundaryEvent } from "../src/runtime-boundary"

const brokers: RuntimeBoundaryBroker[] = []
const sockets: Socket[] = []
afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.destroy()
  for (const broker of brokers.splice(0)) await broker.close()
})
const event = (token = "capability") => ({
  version: 1, type: "boundary", token, eventID: 1, pid: 1234,
  syscall: "openat", kind: "write", operation: "create",
  targets: [{ path: "/outside/fixture.txt", exists: false, parentDev: "1", parentIno: "2" }],
  details: { requiresFullApproval: false },
})
async function open(broker: RuntimeBoundaryBroker) {
  const socket = connect(broker.socketPath)
  sockets.push(socket)
  await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject) })
  return socket
}
async function request(socket: Socket, payload: unknown): Promise<any> {
  const response = new Promise<any>((resolve, reject) => {
    socket.once("data", (data) => { try { resolve(JSON.parse(data.toString())) } catch (error) { reject(error) } })
    socket.once("error", reject)
  })
  socket.write(JSON.stringify(payload) + "\n")
  return response
}
async function broker(onBoundary: Parameters<typeof createRuntimeBoundaryBroker>[0]["onBoundary"]) {
  const created = await createRuntimeBoundaryBroker({ directory: "/tmp/opencode", onBoundary })
  brokers.push(created)
  return created
}

describe("runtime boundary broker", () => {
  test("an idle or in-boundary process makes no approval call", async () => {
    let calls = 0
    const host = await broker(async () => { calls++; return { action: "allow" } })
    await open(host)
    await Promise.resolve()
    expect(calls).toBe(0)
  })
  test("only an authenticated actual event reaches approval", async () => {
    const received: RuntimeBoundaryEvent[] = []
    const host = await broker(async (event) => { received.push(event); return { action: "continue" } })
    const socket = await open(host)
    const result = await request(socket, event(host.token))
    expect(result.action).toBe("continue")
    expect(result.eventID).toBe(1)
    expect(received).toHaveLength(1)
    expect(received[0].targets[0].domain).toBe("linux")
    expect("token" in received[0]).toBe(false)
  })
  test("wrong capabilities disconnect without reviewing", async () => {
    let calls = 0
    const host = await broker(async () => { calls++; return { action: "allow" } })
    const socket = await open(host)
    const closed = new Promise<void>((resolve) => socket.once("close", () => resolve()))
    socket.write(JSON.stringify(event("wrong")) + "\n")
    await closed
    expect(calls).toBe(0)
  })
  test("malformed observer output has a readable failure instead of an unhandled parse error", async () => {
    const failures: string[] = []
    const host = await createRuntimeBoundaryBroker({ directory: "/tmp/opencode", onBoundary: async () => ({ action: "allow" }), onError: (reason) => { failures.push(reason) } })
    brokers.push(host)
    const socket = await open(host)
    socket.write("not-json\n")
    const result = await host.finished
    expect(result.error).toContain("invalid JSON")
    expect(failures).toEqual([result.error!])
  })
  test("a synchronous inspection callback failure is a structured denial", async () => {
    const host = await broker(() => { throw Object.assign(new Error("fixture"), { code: "EIO" }) })
    const result = await request(await open(host), event(host.token))
    expect(result.action).toBe("deny")
    expect(result.reason).toContain("could not be completed")
  })
  test("fail_open callback exceptions allow without refusal text and report a safe code", async () => {
    const failures: string[] = []
    const host = await createRuntimeBoundaryBroker({ directory: "/tmp/opencode", failPolicy: "fail_open",
      onBoundary: () => { throw new Error("raw-provider-secret") }, onFailure: (code) => { failures.push(code) } })
    brokers.push(host)
    const result = await request(await open(host), event(host.token))
    expect(result.action).toBe("allow")
    expect(result.reason).toBeUndefined()
    expect(JSON.stringify(result)).not.toMatch(/blocked|cannot|could not|raw-provider-secret/i)
    expect(failures).toEqual(["broker_callback"])
  })
  test("opaque capabilities cannot use an event-only cache grant", async () => {
    const host = await broker(async () => ({ action: "continue" }))
    const socket = await open(host)
    const result = await request(socket, { ...event(host.token), kind: "opaque", details: { requiresFullApproval: true } })
    expect(result.action).toBe("deny")
  })
  test("fail_open treats an invalid full-approval reply as a protocol failure", async () => {
    const failures: string[] = []
    const host = await createRuntimeBoundaryBroker({ directory: "/tmp/opencode", failPolicy: "fail_open",
      onBoundary: async () => ({ action: "continue" }), onFailure: (code) => { failures.push(code) } })
    brokers.push(host)
    const result = await request(await open(host), { ...event(host.token), kind: "opaque", details: { requiresFullApproval: true } })
    expect(result.action).toBe("allow")
    expect(failures).toEqual(["broker_protocol"])
  })
  test("closing a call cancels its in-progress approval", async () => {
    let observed!: AbortSignal
    let entered!: () => void
    const started = new Promise<void>((resolve) => { entered = resolve })
    const host = await broker(async (_event, signal) => {
      observed = signal
      entered()
      return new Promise((resolve) => signal.addEventListener("abort", () => resolve({ action: "deny" }), { once: true }))
    })
    const socket = await open(host)
    socket.write(JSON.stringify(event(host.token)) + "\n")
    await started
    await host.close()
    expect(observed.aborted).toBe(true)
  })
  test("identity strings remain exact; numeric or malformed identities are not accepted", () => {
    const data = event()
    const big = "12345678901234567890"
    expect(parseRuntimeBoundary({ ...data, targets: [{ path: "/mnt/c/example", exists: true, dev: "1", ino: big }] }, "capability")?.targets[0].ino).toBe(big)
    expect(parseRuntimeBoundary({ ...data, targets: [{ path: "/outside/x", exists: true, ino: 42 }] }, "capability")).toBeUndefined()
    expect(parseRuntimeBoundary({ ...data, eventID: 0 }, "capability")).toBeUndefined()
  })
})

describe("observed-crossing static rules", () => {
  const network = { ...parseRuntimeBoundary(event(), "capability")!, kind: "network" as const }
  test("ordinary git remote reads receive event-only static permission", () => {
    for (const command of ["git fetch origin", "git pull --ff-only", "git clone https://example.invalid/repository", "cd /project && git fetch origin"]) {
      expect(knownSafeRuntimeBoundary(network, command, true)).toBe(true)
    }
  })
  test("different domains and unrelated commands are not accidentally exempted", () => {
    expect(knownSafeRuntimeBoundary(network, "git push origin", true)).toBe(false)
    expect(knownSafeRuntimeBoundary(network, "git -c custom=value fetch origin", true)).toBe(false)
    expect(knownSafeRuntimeBoundary(network, "git fetch origin; python3 program.py", true)).toBe(false)
    expect(knownSafeRuntimeBoundary({ ...network, kind: "write" }, "git fetch origin", true)).toBe(false)
    expect(knownSafeRuntimeBoundary({ ...network, details: { requiresFullApproval: true } }, "git fetch origin", true)).toBe(false)
    expect(knownSafeRuntimeBoundary(network, "git fetch origin", false)).toBe(false)
  })
})

describe("static stage of a runtime crossing (ALLOW or ASK only)", () => {
  const crossing = (overrides: Partial<RuntimeBoundaryEvent>): RuntimeBoundaryEvent => ({
    version: 1, type: "boundary", eventID: 1, pid: 1, syscall: "connect", kind: "network",
    operation: "connect", targets: [], details: { requiresFullApproval: false }, ...overrides,
  })
  const review = (event: RuntimeBoundaryEvent, verdict: "ALLOW" | "ASK", extra: { workspaceNetwork?: "on" | "off"; trustedGitReader?: boolean; command?: string; readonly?: boolean } = {}) => {
    let consulted = 0
    return staticCrossingReview({
      event, command: extra.command ?? "npm install", trustedGitReader: extra.trustedGitReader ?? false,
      workspaceNetwork: extra.workspaceNetwork ?? "off",
      readonly: extra.readonly,
      commandVerdict: async () => { consulted++; return verdict },
    }).then((result) => ({ result, consulted }))
  }
  test("a proven-safe command's network crossing continues statically", async () => {
    expect(await review(crossing({}), "ALLOW")).toEqual({ result: "ALLOW", consulted: 1 })
    expect(await review(crossing({}), "ASK")).toEqual({ result: "ASK", consulted: 1 })
  })
  test("credential reads, outside writes and detaching kinds are never proven statically", async () => {
    for (const kind of ["read", "write", "privilege", "interop", "opaque"] as const) {
      expect(await review(crossing({ kind, syscall: "openat", operation: "open" }), "ALLOW")).toEqual({ result: "ASK", consulted: 0 })
    }
    const full = crossing({ details: { requiresFullApproval: true } })
    expect(await review(full, "ALLOW", { workspaceNetwork: "on" })).toEqual({ result: "ASK", consulted: 0 })
  })
  test("configured workspace network and trusted Git remote reads need no command proof", async () => {
    expect(await review(crossing({}), "ASK", { workspaceNetwork: "on" })).toEqual({ result: "ALLOW", consulted: 0 })
    expect(await review(crossing({}), "ASK", { trustedGitReader: true, command: "git fetch origin" })).toEqual({ result: "ALLOW", consulted: 0 })
  })
  test("RO ignores network/Git shortcuts and consults the RO command proof", async () => {
    for (const kind of ["read", "network"] as const) {
      expect(await review(crossing({ kind }), "ASK", {
        readonly: true, workspaceNetwork: "on", trustedGitReader: true, command: "git fetch origin",
      })).toEqual({ result: "ASK", consulted: 1 })
      expect(await review(crossing({ kind }), "ALLOW", { readonly: true })).toEqual({ result: "ALLOW", consulted: 1 })
    }
    expect(await review(crossing({ kind: "interop", details: { requiresFullApproval: true } }), "ALLOW", {
      readonly: true, workspaceNetwork: "on",
    })).toEqual({ result: "ASK", consulted: 0 })
  })
})

describe("write effect of a runtime crossing", () => {
  const write = (syscall: string, flags?: string): RuntimeBoundaryEvent => ({
    version: 1, type: "boundary", eventID: 1, pid: 1, syscall, kind: "write", operation: "modify",
    targets: [], details: flags ? { flags } : {},
  })
  test("open flags separate truncation, append and in-place writes", () => {
    expect(runtimeWriteEffect(write("openat", "0x241"))).toBe("replace") // O_WRONLY|O_CREAT|O_TRUNC
    expect(runtimeWriteEffect(write("openat", "0x441"))).toBe("append") // O_WRONLY|O_CREAT|O_APPEND
    expect(runtimeWriteEffect(write("openat", "0x42"))).toBe("overwrite") // O_RDWR|O_CREAT
    expect(runtimeWriteEffect(write("openat"))).toBeUndefined()
  })
  test("syscalls map to their effect; links and device nodes have none", () => {
    expect(runtimeWriteEffect(write("ftruncate"))).toBe("replace")
    expect(runtimeWriteEffect(write("creat"))).toBe("replace")
    expect(runtimeWriteEffect(write("write"))).toBe("fd-write")
    expect(runtimeWriteEffect(write("mkdir"))).toBe("mkdir")
    for (const syscall of ["symlink", "symlinkat", "link", "linkat", "mknod", "mknodat", "rename", "unlink"]) {
      expect(runtimeWriteEffect(write(syscall))).toBeUndefined()
    }
    expect(runtimeWriteEffect({ ...write("openat", "0x241"), kind: "read" })).toBeUndefined()
  })
})

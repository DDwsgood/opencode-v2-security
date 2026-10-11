import { randomBytes } from "node:crypto"
import { chmod, lstat, mkdtemp, unlink, rmdir } from "node:fs/promises"
import { createServer, type Socket } from "node:net"
import path from "node:path"
import type { ApprovalCacheTarget, ApprovalCacheWriteEffect } from "./security/approval-cache"
import { scan } from "./security/shell-scan"
import { inspectionErrorCode, isMissingPathError } from "./security/inspection"

export type RuntimeBoundaryEvent = {
  version: 1
  type: "boundary"
  eventID: number
  pid: number
  syscall: string
  kind: "write" | "read" | "network" | "privilege" | "interop" | "opaque"
  operation: string
  targets: ApprovalCacheTarget[]
  details: { requiresFullApproval?: boolean; [key: string]: unknown }
}

export type RuntimeBoundaryResponse = {
  action: "allow" | "continue" | "deny"
  reason?: string
}

export interface RuntimeBoundaryBroker {
  socketPath: string
  token: string
  signal: AbortSignal
  finished: Promise<{ exit?: number; error?: string }>
  close(): Promise<void>
}

const MAX_MESSAGE_BYTES = 65_536
const KINDS = new Set(["write", "read", "network", "privilege", "interop", "opaque"])
const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value)
const identity = (value: unknown): value is string | undefined =>
  value === undefined || typeof value === "string" && /^\d{1,32}$/.test(value)

/** Missing and uninspectable objects stay distinct; neither an errno nor a
 * metadata race is proof of danger. Unknown identities cannot enter the cache. */
export async function currentCacheTargets(targets: readonly ApprovalCacheTarget[]): Promise<ApprovalCacheTarget[]> {
  return Promise.all(targets.map(async (target) => {
    let inspectionError: string | undefined
    const parent = await lstat(path.dirname(target.path), { bigint: true }).catch((error: unknown) => {
      inspectionError = `parent metadata: ${inspectionErrorCode(error)}`
      return undefined
    })
    const object = await lstat(target.path, { bigint: true }).catch((error: unknown) => {
      if (!isMissingPathError(error)) inspectionError = `object metadata: ${inspectionErrorCode(error)}`
      return undefined
    })
    return { path: target.path, domain: target.domain, exists: object !== undefined,
      ...(object ? { dev: String(object.dev), ino: String(object.ino), mode: String(object.mode & 0o7777n) } : {}),
      ...(parent ? { parentDev: String(parent.dev), parentIno: String(parent.ino) } : {}),
      ...(inspectionError ? { inspectionError } : {}) }
  }))
}

/** Only a known difference proves drift. Unavailable metadata instead enters
 * the fresh review as a gap, with cache reuse disabled. */
export function targetIdentitiesMatch(expected: readonly ApprovalCacheTarget[], current: readonly ApprovalCacheTarget[]): boolean {
  return expected.length === current.length && expected.every((target, index) => {
    const other = current[index]!
    if (target.path !== other.path || target.domain !== other.domain) return false
    if (target.inspectionError || other.inspectionError) {
      for (const key of ["dev", "ino", "mode", "parentDev", "parentIno"] as const) {
        if (target[key] !== undefined && other[key] !== undefined && target[key] !== other[key]) return false
      }
      return true
    }
    return JSON.stringify(target) === JSON.stringify(other)
  })
}

/** Static permission for the observed network crossing only, not approval of
 *  a whole script. Git remote reads keep being watched for other crossings.
 *  No Python/body inspection or dangerous-command scan belongs here. */
export function knownSafeRuntimeBoundary(event: RuntimeBoundaryEvent, command: string, trustedGitReader = false): boolean {
  if (!trustedGitReader || event.kind !== "network" || event.details.requiresFullApproval) return false
  const parsed = scan(command)
  if (parsed.kind !== "scanned" || parsed.commands.length === 0) return false
  let remoteRead = false
  for (const item of parsed.commands) {
    const words = item.words
    if (words[0] === "cd" && words.length === 2) continue
    if (!["git", "/usr/bin/git", "/bin/git"].includes(words[0] ?? "")) return false
    if (!["fetch", "pull", "clone", "ls-remote"].includes(words[1] ?? "")) return false
    remoteRead = true
  }
  return remoteRead
}

/** Static stage of a runtime crossing: ALLOW or ASK, never a refusal. The
 *  whole-command verdict (classifyBoundaryCommand) only vouches for effects
 *  a command-text proof can foresee, so it is applied per crossing kind:
 *  - network: a proven-safe command contacting the network is expected
 *    (fetch, install, version checks); only this syscall continues and the
 *    tree stays watched.
 *  - read: the crossing exists because the path is a credential or a
 *    configured denyRead path, which command text cannot prove safe.
 *  - write: an outside-root/protected write is exactly what the classifier
 *    itself routes to ASK; a runtime one was not foreseen by the proof.
 *  - privilege/interop/opaque and every requiresFullApproval event: the only
 *    positive reply detaches the tree, so a static proof cannot grant it. */
export async function staticCrossingReview(input: {
  event: RuntimeBoundaryEvent
  command: string
  commandVerdict: () => Promise<"ALLOW" | "ASK">
  trustedGitReader: boolean
  workspaceNetwork: "on" | "off"
  /** Read-only session: only the RO-scoped whole-command proof may allow a
   *  crossing statically — no workspaceNetwork shortcut (remote reads still
   *  answer the read-only conformance question) and no trusted-git-reader
   *  shortcut. requiresFullApproval events always need the review. */
  readonly?: boolean
}): Promise<"ALLOW" | "ASK"> {
  const { event } = input
  if (event.details.requiresFullApproval) return "ASK"
  if (input.readonly === true) {
    return (await input.commandVerdict()) === "ALLOW" ? "ALLOW" : "ASK"
  }
  if (knownSafeRuntimeBoundary(event, input.command, input.trustedGitReader)) return "ALLOW"
  if (event.kind !== "network") return "ASK"
  if (input.workspaceNetwork === "on") return "ALLOW"
  return input.commandVerdict()
}

const O_APPEND = 0o2000
const O_TRUNC = 0o1000
const FD_WRITES = new Set(["write", "writev", "pwrite64", "pwritev", "pwritev2", "sendfile", "splice", "tee", "copy_file_range"])
const MAPPED_WRITES = new Set(["mmap", "msync", "mprotect", "pkey_mprotect"])

/** Content effect of a write crossing, for L2 cache reuse. Link, symlink
 *  and device-node creation have no effect class and never reuse a grant. */
export function runtimeWriteEffect(event: RuntimeBoundaryEvent): ApprovalCacheWriteEffect | undefined {
  if (event.kind !== "write") return undefined
  const syscall = event.syscall
  if (syscall === "truncate" || syscall === "ftruncate" || syscall === "creat") return "replace"
  if (syscall === "open" || syscall === "openat" || syscall === "openat2") {
    const flags = typeof event.details.flags === "string" && /^0x[0-9a-f]+$/i.test(event.details.flags)
      ? Number.parseInt(event.details.flags.slice(2), 16) : undefined
    if (flags === undefined) return undefined
    if (flags & O_TRUNC) return "replace"
    return flags & O_APPEND ? "append" : "overwrite"
  }
  if (FD_WRITES.has(syscall)) return "fd-write"
  if (MAPPED_WRITES.has(syscall) || syscall === "fallocate") return "overwrite"
  if (syscall === "mkdir" || syscall === "mkdirat") return "mkdir"
  return undefined
}

/** Only the observer's bounded, structured facts enter the reviewer. A
 *  capability token is checked before accepting any runtime event. */
export function parseRuntimeBoundary(value: unknown, token: string): RuntimeBoundaryEvent | undefined {
  if (!record(value) || value.version !== 1 || value.type !== "boundary" || value.token !== token ||
    !Number.isSafeInteger(value.eventID) || Number(value.eventID) < 1 ||
    !Number.isSafeInteger(value.pid) || Number(value.pid) < 1 ||
    typeof value.syscall !== "string" || !/^[a-z0-9_-]{1,64}$/.test(value.syscall) ||
    typeof value.kind !== "string" || !KINDS.has(value.kind) ||
    typeof value.operation !== "string" || !/^[a-z0-9_-]{1,64}$/.test(value.operation) ||
    !Array.isArray(value.targets) || value.targets.length > 32 ||
    value.details !== undefined && (!record(value.details) ||
      value.details.requiresFullApproval !== undefined && typeof value.details.requiresFullApproval !== "boolean")) return undefined
  const targets: ApprovalCacheTarget[] = []
  for (const target of value.targets) {
    if (!record(target) || typeof target.path !== "string" || !path.isAbsolute(target.path) ||
      target.path.length > 4096 || target.path.includes("\0") || typeof target.exists !== "boolean" ||
      ![target.dev, target.ino, target.mode, target.parentDev, target.parentIno].every(identity) ||
      target.domain !== undefined && target.domain !== "linux" && target.domain !== "drvfs" ||
      target.inspectionError !== undefined && (typeof target.inspectionError !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(target.inspectionError))) return undefined
    targets.push({
      path: target.path,
      domain: target.domain === "drvfs" || /^\/mnt\/[a-z](?:\/|$)/i.test(target.path) ? "drvfs" : "linux",
      exists: target.exists,
      ...(target.dev !== undefined ? { dev: target.dev as string } : {}),
      ...(target.ino !== undefined ? { ino: target.ino as string } : {}),
      // Key order must match currentCacheTargets for the stringify identity
      // check: dev, ino, mode, then parent identity.
      ...(target.mode !== undefined ? { mode: target.mode as string } : {}),
      ...(target.parentDev !== undefined ? { parentDev: target.parentDev as string } : {}),
      ...(target.parentIno !== undefined ? { parentIno: target.parentIno as string } : {}),
      ...(target.inspectionError !== undefined ? { inspectionError: target.inspectionError as string } : {}),
    })
  }
  return {
    version: 1, type: "boundary", eventID: Number(value.eventID), pid: Number(value.pid),
    syscall: value.syscall, kind: value.kind as RuntimeBoundaryEvent["kind"],
    operation: value.operation, targets,
    details: (value.details ?? {}) as RuntimeBoundaryEvent["details"],
  }
}

/** Call-local IPC only. No provider request is made until the native observer
 *  pauses a real boundary operation and sends its event. Closing kills the
 *  observer's pending approval channel; it must not silently resume. */
export async function createRuntimeBoundaryBroker(options: {
  directory: string
  onBoundary(event: RuntimeBoundaryEvent, signal: AbortSignal): Promise<RuntimeBoundaryResponse>
  onError?(reason: string): void
}): Promise<RuntimeBoundaryBroker> {
  const directory = await mkdtemp(path.join(options.directory, "security-boundary-"))
  try {
    await chmod(directory, 0o700)
  } catch (error) {
    await rmdir(directory).catch(() => {})
    throw error
  }
  const socketPath = path.join(directory, "observer.sock")
  const token = randomBytes(32).toString("hex")
  const controller = new AbortController()
  const sockets = new Set<Socket>()
  let closed = false
  let active: Socket | undefined
  let terminalExit: number | undefined
  let brokerError: string | undefined
  let complete!: (result: { exit?: number; error?: string }) => void
  const finished = new Promise<{ exit?: number; error?: string }>((resolve) => { complete = resolve })
  const fail = (reason: string) => {
    brokerError ??= reason
    try { options.onError?.(reason) } catch { /* A diagnostic callback cannot revive a rejected channel. */ }
    controller.abort()
    complete({ error: brokerError })
  }
  const server = createServer((socket) => {
    sockets.add(socket)
    socket.on("error", () => { fail("the runtime observer connection failed"); socket.destroy() })
    socket.on("close", () => {
      sockets.delete(socket)
      if (socket === active) controller.abort()
      if (socket === active && terminalExit === undefined && !closed && !brokerError) fail("the runtime observer disconnected before reporting its exit")
      if (sockets.size === 0) complete({ ...(terminalExit !== undefined ? { exit: terminalExit } : {}), ...(brokerError ? { error: brokerError } : {}) })
    })
    let buffer = ""
    let lastEvent = 0
    let pending = false
    socket.setEncoding("utf8")
    socket.on("data", (chunk: string) => {
      if (closed || active && active !== socket) { socket.destroy(); return }
      const invalid = (reason: string) => { fail(reason); socket.destroy() }
      buffer += chunk
      if (Buffer.byteLength(buffer, "utf8") > MAX_MESSAGE_BYTES) { invalid("the runtime observer message exceeds its size limit"); return }
      const newline = buffer.indexOf("\n")
      if (newline < 0) return
      const line = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      // One outstanding event per observer; pipelining cannot manufacture
      // multiple approvals from one held syscall. Trailing bytes after a
      // line are only acceptable while a reply is in flight — the terminal
      // exit frame may share the chunk.
      if (buffer.length > 0 && !pending) { invalid("the runtime observer sent overlapping messages"); return }
      let raw: unknown
      try { raw = JSON.parse(line) } catch { invalid("the runtime observer returned invalid JSON"); return }
      if (record(raw) && raw.version === 1 && raw.type === "exit" && raw.token === token &&
        Number.isInteger(raw.exit) && Number(raw.exit) >= 0 && Number(raw.exit) <= 255) {
        active = socket
        terminalExit = Number(raw.exit)
        return
      }
      const event = parseRuntimeBoundary(raw, token)
      // A second boundary event while one is unanswered is a protocol
      // violation; the terminal exit frame above stays legal mid-flight.
      if (!event || pending || event.eventID <= lastEvent) { invalid("the runtime observer returned an invalid or unauthenticated boundary event"); return }
      active = socket
      lastEvent = event.eventID
      pending = true
      void Promise.resolve().then(() => options.onBoundary(event, controller.signal)).then((response) => {
        if (closed || socket.destroyed) return
        // An opaque capability cannot be resumed under an event-only cache
        // grant, since its future effects would no longer be observable.
        const action = event.details.requiresFullApproval && response.action === "continue" ? "deny" : response.action
        socket.write(JSON.stringify({ version: 1, eventID: event.eventID, action, reason: response.reason }) + "\n")
      }).catch(() => {
        if (!closed && !socket.destroyed) socket.write(JSON.stringify({
          version: 1, eventID: event.eventID, action: "deny",
          reason: "the boundary check could not be completed",
        }) + "\n")
      }).finally(() => { pending = false }).catch(() => { fail("the runtime boundary response could not be sent"); socket.destroy() })
    })
  })
  const cleanup = async () => {
    await unlink(socketPath).catch(() => {})
    await rmdir(directory).catch(() => {})
  }
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject)
      server.listen(socketPath, () => { server.removeListener("error", reject); resolve() })
    })
    await chmod(socketPath, 0o600)
  } catch (error) {
    server.close()
    await cleanup()
    throw error
  }
  server.on("error", () => { fail("the runtime observer listener failed"); for (const socket of sockets) socket.destroy() })
  return {
    socketPath, token, signal: controller.signal, finished,
    async close() {
      if (closed) return
      closed = true
      controller.abort()
      complete({ ...(terminalExit !== undefined ? { exit: terminalExit } : {}) })
      for (const socket of sockets) socket.destroy()
      await new Promise<void>((resolve) => server.close(() => resolve()))
      await cleanup()
    },
  }
}

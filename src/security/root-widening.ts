import { opendir } from "node:fs/promises"
import path from "node:path"
import { canonicalCandidate } from "./automatic-write-roots"
import { EFFECTS_MODEL, EffectsReviewError, requestSystemOne, type EffectsReviewOptions } from "./effects-reviewer"
import { containsWritePath, writeRootRejection, writeTargetExempt, type WriteRootPolicy } from "./write-root-policy"
import type { RuntimeBoundaryEvent } from "../runtime-boundary"

export const L3_POLICY_VERSION = "l3-root-widen-v1"
export const L3_WINDOW_MS = 20 * 60 * 1000
export const L3_STATE_TEXT = "A coding agent runs shell commands under a sandbox. Inside a writable root every file operation (create, modify, append, delete, rename) runs without further review, exactly like /tmp. Outside writable roots each write pauses for an individual safety review. The recent commands below each wrote inside the same directory, and every one of those writes was individually reviewed and allowed. You decide whether one directory may become an additional writable root for this session temporarily (20 minutes, ended early by the user's next message or any permission change). Granting saves future reviews; it must never expose data whose loss, alteration or disclosure would matter."
export const L3_QUESTION_TEXT = "Choose the single directory to add as a temporary writable root, or none. Prefer the narrowest candidate that still covers the repeated writes — normally the directory the writes land in. Choose a broader ancestor only when the evidence shows the same tools routinely write across its subdirectories and nothing in it is sensitive. Choose none when a candidate that would cover the writes also holds data that should not be freely modified or deleted (credentials, tokens, keys, auth or session files, configuration that changes program or security behaviour, version-controlled source, databases, user documents); when the writes look like a task-specific action rather than a tool's routine bookkeeping (logs, caches, locks, temporary or trim files, history); or when the user's request and recent context do not support continued use of these tools."

export interface RootCandidate {
  option: string
  path: string
  sample_entries: string[]
}

export interface RepeatedWriteEvent {
  command: string
  syscall: string
  operation: string
  target: string
  executable: string
}

export interface RootWideningInput {
  user_request: string
  session_context: string[]
  repeated_directory: string
  events: RepeatedWriteEvent[]
  candidates: RootCandidate[]
  current_write_roots: readonly string[]
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`
  const object = value as Record<string, unknown>
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(",")}}`
}

export function buildRootWideningBody(input: RootWideningInput) {
  const criteria: Record<string, string> = {}
  for (const candidate of input.candidates) criteria[candidate.option] = `Grant ${candidate.path} as a temporary writable root.`
  criteria.none = "Grant nothing; keep reviewing each write individually."
  // Project trusted fields only; host scope, digests and API configuration are
  // intentionally outside the model's state.
  const facts: RootWideningInput = {
    user_request: input.user_request,
    session_context: input.session_context,
    repeated_directory: input.repeated_directory,
    events: input.events.map(({ command, syscall, operation, target, executable }) => ({ command, syscall, operation, target, executable })),
    candidates: input.candidates.map(({ option, path, sample_entries }) => ({ option, path, sample_entries })),
    current_write_roots: input.current_write_roots,
  }
  const body = {
    model: EFFECTS_MODEL,
    state: `${L3_STATE_TEXT}\n\n<review_input>\n${stableJson(facts)}\n</review_input>\n`,
    questions: { widen_root: { type: "choice", instructions: L3_QUESTION_TEXT, criteria } },
  }
  if (Buffer.byteLength(JSON.stringify(body)) > 512 * 1024) throw new Error("L3 request size")
  return body
}

export function parseRootWideningChoice(payload: unknown, candidates: readonly RootCandidate[]): string {
  const answer = (payload as { answers?: { widen_root?: { type?: unknown; choice?: unknown } } } | null)?.answers?.widen_root
  if (!answer || (answer.type !== undefined && answer.type !== "choice") ||
    typeof answer.choice !== "string" || (answer.choice !== "none" && !candidates.some((candidate) => candidate.option === answer.choice))) {
    throw new Error("L3 choice protocol")
  }
  // Probabilities are deliberately ignored: only the returned choice grants.
  return answer.choice
}

export async function reviewRootWidening(input: RootWideningInput, options: EffectsReviewOptions): Promise<unknown> {
  const body = buildRootWideningBody(input)
  return requestSystemOne(body, options, (payload) => {
    try {
      parseRootWideningChoice(payload, input.candidates)
    } catch {
      throw new EffectsReviewError("L3 choice protocol", "protocol")
    }
    return payload
  })
}

const HIGH_VALUE_NAMES = [
  /^(auth|credentials?|secrets?|tokens?|passwords?)(\.(json|ya?ml|toml|ini|txt))?$/i,
  /\.(pem|key|p12|pfx|kdbx|gpg|asc|jks|keystore)$/i,
  /^id_(rsa|ed25519|ecdsa|dsa)/,
  /^\.env(\..*)?$/,
  /^\.?netrc$/,
  /^\.git-credentials$/,
  /^cookies?(\.sqlite)?$/i,
  /\.(db|sqlite3?|db-wal|db-shm)$/i,
]

/** Incremental name-only inspection: no file contents, no symlink traversal.
 * A depth/entry cutoff is uncertainty, never evidence of a safe directory. */
async function scanCandidate(root: string): Promise<string[] | undefined> {
  const pending = [{ directory: root, depth: 0 }]
  const sample: string[] = []
  let entries = 0
  while (pending.length) {
    const current = pending.pop()!
    const directory = await opendir(current.directory)
    for await (const entry of directory) {
      entries++
      if (entries > 5000) return undefined
      if (HIGH_VALUE_NAMES.some((pattern) => pattern.test(entry.name)) || entry.name === ".git") return undefined
      if (current.depth === 0 && sample.length < 20) sample.push(entry.name)
      if (entry.isDirectory()) {
        if (current.depth + 1 >= 3) return undefined
        pending.push({ directory: path.join(current.directory, entry.name), depth: current.depth + 1 })
      }
    }
  }
  return sample.sort()
}

export async function rootWideningCandidates(
  key: string,
  policy: WriteRootPolicy,
  workspace: string,
  currentRoots: readonly string[],
): Promise<RootCandidate[]> {
  const candidates: RootCandidate[] = []
  let directory = key
  for (let count = 0; count < 4; count++) {
    if (directory === path.parse(directory).root || containsWritePath(directory, policy.home)) break
    if (!writeRootRejection(directory, policy) && !containsWritePath(directory, workspace) &&
      !currentRoots.some((root) => containsWritePath(directory, root))) {
      const sample = await scanCandidate(directory)
      if (sample) candidates.push({ option: `root_${candidates.length + 1}`, path: directory, sample_entries: sample })
    }
    directory = path.dirname(directory)
  }
  return candidates
}

export interface RootWideningScope {
  sessionID: string
  canWrite: boolean
  userMessageDigest: string
  securitySnapshot: string
}

export interface RootWideningContext {
  scope: RootWideningScope
  user_request: string
  session_context: string[]
}

interface RootGrant {
  root: string
  grantedAt: number
  userMessageDigest: string
  securitySnapshot: string
}

interface Repetition {
  events: Array<{ callID: string; at: number; event: RepeatedWriteEvent }>
  lastSeenAt: number
  scope: RootWideningScope
  lastQueryAt?: number
  suppressedUntil?: number
  pending: boolean
}

/** Mutable L3 state (per-session repetitions and grants). Several plugin
 *  instances run in one server process; the store is shared so a session's
 *  grants are not split by which instance serves a call. */
export interface RootWideningStore {
  repetitions: Map<string, Repetition>
  grants: Map<string, RootGrant[]>
}

export interface L3Trace {
  kind: "l3_root_request" | "l3_root_granted" | "l3_root_declined" | "l3_root_error" | "l3_root_expired"
  sessionID: string
  policyVersion: typeof L3_POLICY_VERSION
  repeatedDirectory?: string
  root?: string
  command?: string
  reason?: string
}

function sameScope(left: RootWideningScope, right: RootWideningScope): boolean {
  return right.canWrite && left.sessionID === right.sessionID && left.userMessageDigest === right.userMessageDigest && left.securitySnapshot === right.securitySnapshot
}

export function createRootWidening(options: {
  review: (input: RootWideningInput) => Promise<unknown>
  trace: (event: L3Trace) => void
  now?: () => number
  /** Shared state store (several plugin instances in one process share one);
   *   defaults to a fresh private store. */
  state?: RootWideningStore
}) {
  const now = options.now ?? Date.now
  const { repetitions, grants } = options.state ?? { repetitions: new Map<string, Repetition>(), grants: new Map<string, RootGrant[]>() }
  const trace = (event: Omit<L3Trace, "policyVersion">) => {
    try { options.trace({ ...event, policyVersion: L3_POLICY_VERSION }) } catch { /* Optional optimization cannot affect execution. */ }
  }

  function sweep(): void {
    const timestamp = now()
    for (const [key, repetition] of repetitions) {
      if (timestamp - repetition.lastSeenAt >= L3_WINDOW_MS) repetitions.delete(key)
    }
    for (const [sessionID, entries] of grants) {
      for (const grant of entries) {
        if (timestamp - grant.grantedAt >= L3_WINDOW_MS) {
          trace({ kind: "l3_root_expired", sessionID, root: grant.root, reason: "time" })
        }
      }
      const active = entries.filter((grant) => timestamp - grant.grantedAt < L3_WINDOW_MS)
      if (active.length) grants.set(sessionID, active)
      else grants.delete(sessionID)
    }
  }

  function clearSession(sessionID: string): void {
    grants.delete(sessionID)
    for (const [key, repetition] of repetitions) {
      if (repetition.scope.sessionID === sessionID) repetitions.delete(key)
    }
  }

  function activeRoots(scope: RootWideningScope): string[] {
    const active: RootGrant[] = []
    for (const grant of grants.get(scope.sessionID) ?? []) {
      let reason: string | undefined
      if (!scope.canWrite) reason = "readonly"
      else if (now() - grant.grantedAt >= L3_WINDOW_MS) reason = "time"
      else if (scope.userMessageDigest !== grant.userMessageDigest) reason = "user_message"
      else if (scope.securitySnapshot !== grant.securitySnapshot) reason = "security_snapshot"
      else if (canonicalCandidate(grant.root) !== grant.root) reason = "root_redirected"
      if (reason) trace({ kind: "l3_root_expired", sessionID: scope.sessionID, root: grant.root, reason })
      else active.push(grant)
    }
    if (active.length) grants.set(scope.sessionID, active)
    else grants.delete(scope.sessionID)
    sweep()
    return active.map((grant) => grant.root)
  }

  async function query(key: string, repetition: Repetition, input: {
    scope: RootWideningScope
    policy: WriteRootPolicy
    workspace: string
    currentRoots: readonly string[]
    context: () => Promise<RootWideningContext>
  }): Promise<void> {
    const audit = { sessionID: input.scope.sessionID, repeatedDirectory: key,
      command: repetition.events.at(-1)!.event.command }
    try {
      const events = repetition.events.slice(-3).map(({ event }) => event)
      const candidates = await rootWideningCandidates(key, input.policy, input.workspace, input.currentRoots)
      if (!candidates.length) return
      const retained = await input.context()
      if (!sameScope(input.scope, retained.scope)) return
      trace({ kind: "l3_root_request", ...audit })
      const payload = await options.review({ user_request: retained.user_request, session_context: retained.session_context,
        repeated_directory: key, events, candidates, current_write_roots: input.currentRoots })
      const choice = parseRootWideningChoice(payload, candidates)
      if (choice === "none") {
        repetition.suppressedUntil = now() + L3_WINDOW_MS
        trace({ kind: "l3_root_declined", ...audit })
        return
      }
      const latest = await input.context()
      if (!sameScope(input.scope, latest.scope) || now() - repetition.lastQueryAt! >= L3_WINDOW_MS) return
      const candidate = candidates.find((candidate) => candidate.option === choice)!
      // Re-scan after the background response: a credential planted while the
      // model was running cannot turn an old name scan into a fresh grant.
      const currentCandidates = await rootWideningCandidates(key, input.policy, input.workspace, input.currentRoots)
      if (!currentCandidates.some((current) => current.path === candidate.path)) return
      const finalContext = await input.context()
      if (!sameScope(input.scope, finalContext.scope) || repetitions.get(JSON.stringify([input.scope.sessionID, key])) !== repetition) return
      const active = grants.get(input.scope.sessionID) ?? []
      active.push({ root: candidate.path, grantedAt: now(), userMessageDigest: input.scope.userMessageDigest, securitySnapshot: input.scope.securitySnapshot })
      grants.set(input.scope.sessionID, active)
      trace({ kind: "l3_root_granted", ...audit, root: candidate.path })
    } catch {
      trace({ kind: "l3_root_error", ...audit })
    } finally {
      repetition.pending = false
    }
  }

  function recordAllowedWrite(input: {
    scope: RootWideningScope
    callID: string
    command: string
    event: RuntimeBoundaryEvent
    policy: WriteRootPolicy
    workspace: string
    currentRoots: readonly string[]
    context: () => Promise<RootWideningContext>
  }): void {
    if (!input.scope.canWrite || input.event.kind !== "write") return
    sweep()
    const timestamp = now()
    for (const target of input.event.targets) {
      if (input.currentRoots.some((root) => containsWritePath(root, target.path))) continue
      const key = canonicalCandidate(path.dirname(target.path))
      if (!key) continue
      const mapKey = JSON.stringify([input.scope.sessionID, key])
      let repetition = repetitions.get(mapKey)
      if (!repetition) {
        repetition = { events: [], lastSeenAt: timestamp, scope: input.scope, pending: false }
        repetitions.set(mapKey, repetition)
      }
      repetition.lastSeenAt = timestamp
      if (!sameScope(repetition.scope, input.scope)) {
        repetition.events = []
        repetition.scope = input.scope
      }
      repetition.events = repetition.events.filter((event) => timestamp - event.at < L3_WINDOW_MS)
      if (repetition.events.some((event) => event.callID === input.callID)) continue
      const executable = typeof input.event.details.executable === "string" ? path.basename(input.event.details.executable) : ""
      repetition.events.push({ callID: input.callID, at: timestamp,
        event: { command: input.command, syscall: input.event.syscall, operation: input.event.operation, target: target.path, executable } })
      if (repetition.events.length < 3 || repetition.pending ||
        (repetition.lastQueryAt !== undefined && timestamp - repetition.lastQueryAt < L3_WINDOW_MS) ||
        (repetition.suppressedUntil !== undefined && timestamp < repetition.suppressedUntil)) continue
      repetition.lastQueryAt = timestamp
      repetition.pending = true
      // No await at the boundary: scanning and the separate JEV call cannot
      // hold up, refuse or detach the command whose crossing was just allowed.
      void Promise.resolve().then(() => query(key, repetition!, input)).catch(() => {})
    }
  }

  return {
    clearSession,
    sweep,
    activeRoots,
    hasGrants: (sessionID: string) => grants.has(sessionID),
    recordAllowedWrite,
    targetsExempt(scope: RootWideningScope, targets: readonly string[], policy: WriteRootPolicy): boolean {
      const roots = activeRoots(scope)
      return targets.length > 0 && targets.every((target) => roots.some((root) => containsWritePath(root, target)) && writeTargetExempt(target, policy))
    },
  }
}

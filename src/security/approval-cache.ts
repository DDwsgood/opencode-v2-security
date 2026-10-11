import { createHash } from "node:crypto"
import type { EffectReviewResult } from "./effects-reviewer"

/** Memory-only, per-session approval cache shared by the broker.
 *
 * Two layers, deliberately narrow:
 * - L1 replays an exact prior adjudication (`exactDigest`) within one scope.
 * - L2 reuses a prior *routine same-level write* on the same object identity;
 *   it never re-adjudicates and never widens the write level (create/modify/open
 *   only, never delete/rename/metadata/exec) or the write effect: a grant for
 *   an append does not cover a truncating rewrite, and link/symlink/device
 *   creation never enters L2.
 *
 * The cache is not a new risk analyzer: it only records decisions the caller
 * already adjudicated, never downgrades them, and never invents an approval.
 */

export type ApprovalCacheScope = {
  sessionID: string
  securitySnapshot: string
  userAuthorizationDigest: string
}

export type ApprovalCacheTarget = {
  path: string
  domain: "linux" | "drvfs"
  exists: boolean
  dev?: string
  ino?: string
  /** Permission bits (st_mode & 0o7777) as decimal string: a chmod on the
   *  same inode must invalidate grants; content mtime does not. */
  mode?: string
  parentDev?: string
  parentIno?: string
  /** Unknown metadata is not a missing object and never authorizes cache reuse. */
  inspectionError?: string
}

export type ApprovalCacheKind =
  | "write"
  | "read"
  | "network"
  | "privilege"
  | "interop"
  | "opaque"

/** What a write does to the object's existing content. Ordered by reach:
 *  each effect's grant also covers the effects listed after it in
 *  WRITE_EFFECT_COVERS. Absent = not L2-eligible. */
export type ApprovalCacheWriteEffect = "replace" | "overwrite" | "append" | "fd-write" | "mkdir"

export type ApprovalCacheFacts = {
  exactDigest: string
  kind: ApprovalCacheKind
  operation: string
  targets: readonly ApprovalCacheTarget[]
  requiresFullApproval?: boolean
  effect?: ApprovalCacheWriteEffect
}

export type ApprovalCacheHit = {
  layer: "L1" | "L2"
  decision: "allow" | "deny"
  result?: EffectReviewResult
}

export interface ApprovalCacheOptions {
  /** Injected clock for deterministic TTL tests. */
  now?: () => number
  /** LRU bound applied to each session's L1 entries and L2 grants. */
  maxPerSession?: number
  /** LRU bound on the number of sessions holding cache state. */
  maxSessions?: number
  /** Positive (allow) L1 lifetime. A hit never extends it. */
  allowTtlMs?: number
  /** Negative (deny) L1 lifetime. */
  denyTtlMs?: number
}

export interface ApprovalCache {
  lookup(scope: ApprovalCacheScope, facts: ApprovalCacheFacts): ApprovalCacheHit | undefined
  store(scope: ApprovalCacheScope, facts: ApprovalCacheFacts, result: EffectReviewResult): void
  recordTargets(scope: ApprovalCacheScope, facts: ApprovalCacheFacts, targets: readonly ApprovalCacheTarget[]): void
  clear(sessionID: string): void
  clearAll(): void
}

const DEFAULT_MAX_PER_SESSION = 256
const DEFAULT_MAX_SESSIONS = 64
const DEFAULT_ALLOW_TTL_MS = 30 * 60 * 1000
const DEFAULT_DENY_TTL_MS = 5 * 60 * 1000

const L1_ALLOW_SOURCES_EXCLUDED: ReadonlySet<EffectReviewResult["source"]> = new Set([
  "accepted_unknown",
  "evidence_limit",
])

// Insufficient-evidence outcomes are not explicit model rejection; caching them
// as negative would turn a collection gap into a lasting denial.
const L1_DENY_SOURCES_EXCLUDED: ReadonlySet<EffectReviewResult["source"]> = new Set([
  "accepted_unknown",
  "evidence_limit",
])

const WRITE_LEVEL_OPERATIONS: ReadonlySet<string> = new Set(["create", "modify", "open"])

// fd-write is covered by every content grant: the descriptor it writes
// through was itself opened under a gated (and so separately judged) open.
const WRITE_EFFECT_COVERS: Readonly<Record<ApprovalCacheWriteEffect, ReadonlySet<ApprovalCacheWriteEffect>>> = {
  replace: new Set(["replace", "overwrite", "append", "fd-write"]),
  overwrite: new Set(["overwrite", "append", "fd-write"]),
  append: new Set(["append", "fd-write"]),
  "fd-write": new Set(["fd-write"]),
  mkdir: new Set(["mkdir"]),
}

function effectCovers(grant: ApprovalCacheWriteEffect, requested: ApprovalCacheWriteEffect): boolean {
  return WRITE_EFFECT_COVERS[grant].has(requested)
}

type L1Entry = {
  decision: "allow" | "deny"
  result: EffectReviewResult
  storedAt: number
  ttlMs: number
}

type L2Grant = {
  effect: ApprovalCacheWriteEffect
  expectedExists: boolean
  expectedDev?: string
  expectedIno?: string
  expectedMode?: string
  result: EffectReviewResult
  storedAt: number
}

type SessionState = {
  scopeDigest: string
  l1: Map<string, L1Entry>
  l2: Map<string, L2Grant>
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}

/** Only a digest of the scope is retained; the raw snapshot string is never stored. */
function scopeDigest(scope: ApprovalCacheScope): string {
  return digest(`${digest(scope.securitySnapshot)}\u0000${scope.userAuthorizationDigest}`)
}

function cacheableAllow(result: EffectReviewResult): boolean {
  return (
    result.decision === "allow" &&
    result.floor === "no" &&
    !L1_ALLOW_SOURCES_EXCLUDED.has(result.source)
  )
}

function isWriteLevel(operation: string): boolean {
  return WRITE_LEVEL_OPERATIONS.has(operation.toLowerCase())
}

function present(value: string | undefined): value is string {
  return typeof value === "string" && value.length > 0
}

/** Every target must carry parent identity; existing objects must carry their own. */
function targetFullyIdentified(target: ApprovalCacheTarget): boolean {
  if (target.inspectionError !== undefined) return false
  if (!present(target.parentDev) || !present(target.parentIno)) return false
  if (target.exists && (!present(target.dev) || !present(target.ino))) return false
  return true
}

function grantKey(target: ApprovalCacheTarget): string {
  // dev/ino stay strings: they are opaque identifiers, never parsed as numbers.
  return JSON.stringify([target.domain, target.path, target.parentDev ?? null, target.parentIno ?? null])
}

function grantMatches(grant: L2Grant, target: ApprovalCacheTarget): boolean {
  if (target.exists) {
    return (
      grant.expectedExists &&
      present(target.dev) &&
      present(target.ino) &&
      grant.expectedDev === target.dev &&
      grant.expectedIno === target.ino &&
      // A chmod on the same inode is a different authorization question:
      // permission-bit drift misses the grant. Both-undefined stays a match
      // for callers that never had mode data (no silent widening either way).
      grant.expectedMode === target.mode
    )
  }
  // A not-yet-existing object matches only a create grant that has not advanced.
  return !grant.expectedExists
}

export function createApprovalCache(options: ApprovalCacheOptions = {}): ApprovalCache {
  const now = options.now ?? (() => Date.now())
  const maxPerSession = options.maxPerSession ?? DEFAULT_MAX_PER_SESSION
  const maxSessions = options.maxSessions ?? DEFAULT_MAX_SESSIONS
  const allowTtlMs = options.allowTtlMs ?? DEFAULT_ALLOW_TTL_MS
  const denyTtlMs = options.denyTtlMs ?? DEFAULT_DENY_TTL_MS

  const sessions = new Map<string, SessionState>()

  /** State for exactly this scope, or undefined. Read paths never mutate:
   *  a caller still holding an older scope (an in-flight call that began
   *  before a new user message) must miss, not wipe the newer entries. */
  function currentSession(scope: ApprovalCacheScope): SessionState | undefined {
    const existing = sessions.get(scope.sessionID)
    if (!existing || existing.scopeDigest !== scopeDigest(scope)) return undefined
    touch(sessions, scope.sessionID, existing)
    return existing
  }

  /** Writing under a new scope discards every prior entry of the session:
   *  stale approvals must not survive cap/lease or authorization changes. */
  function sessionForStore(scope: ApprovalCacheScope): SessionState {
    const current = currentSession(scope)
    if (current) return current
    const fresh: SessionState = { scopeDigest: scopeDigest(scope), l1: new Map(), l2: new Map() }
    sessions.delete(scope.sessionID)
    sessions.set(scope.sessionID, fresh)
    while (sessions.size > maxSessions) {
      const oldest = sessions.keys().next().value
      if (oldest === undefined) break
      sessions.delete(oldest)
    }
    return fresh
  }

  function expired(storedAt: number, ttlMs: number): boolean {
    return now() - storedAt >= ttlMs
  }

  function touch<K, V>(map: Map<K, V>, key: K, value: V): void {
    map.delete(key)
    map.set(key, value)
  }

  function evictOldest<K, V>(map: Map<K, V>): void {
    while (map.size > maxPerSession) {
      const oldest = map.keys().next().value
      if (oldest === undefined) return
      map.delete(oldest)
    }
  }

  function l2Eligible(facts: ApprovalCacheFacts): boolean {
    return (
      facts.kind === "write" &&
      isWriteLevel(facts.operation) &&
      facts.requiresFullApproval === false &&
      facts.effect !== undefined &&
      facts.targets.length > 0 &&
      facts.targets.every(targetFullyIdentified)
    )
  }

  return {
    lookup(scope, facts) {
      if (facts.targets.some((target) => target.inspectionError !== undefined)) return undefined
      const state = currentSession(scope)
      if (!state) return undefined

      const entry = state.l1.get(facts.exactDigest)
      if (entry) {
        if (expired(entry.storedAt, entry.ttlMs)) {
          state.l1.delete(facts.exactDigest)
        } else {
          touch(state.l1, facts.exactDigest, entry)
          return { layer: "L1", decision: entry.decision, result: structuredClone(entry.result) }
        }
      }

      if (!l2Eligible(facts)) return undefined

      const matched: Array<{ key: string; grant: L2Grant }> = []
      for (const target of facts.targets) {
        const key = grantKey(target)
        const grant = state.l2.get(key)
        if (!grant || expired(grant.storedAt, allowTtlMs) || !grantMatches(grant, target) ||
          !effectCovers(grant.effect, facts.effect!)) {
          // Identity drift (or no grant) must miss, never reuse a neighbor.
          if (grant && expired(grant.storedAt, allowTtlMs)) state.l2.delete(key)
          return undefined
        }
        matched.push({ key, grant })
      }
      // A hit must cover every target; partial coverage is not a reuse.
      for (const { key, grant } of matched) touch(state.l2, key, grant)
      return { layer: "L2", decision: "allow", result: structuredClone(matched[0].grant.result) }
    },

    store(scope, facts, result) {
      if (facts.targets.some((target) => target.inspectionError !== undefined)) return
      const state = sessionForStore(scope)

      const allow = cacheableAllow(result)
      const deny = result.decision === "deny" && !L1_DENY_SOURCES_EXCLUDED.has(result.source)
      if (!allow && !deny) return

      const ttlMs = allow ? allowTtlMs : denyTtlMs
      state.l1.set(facts.exactDigest, {
        decision: allow ? "allow" : "deny",
        result: structuredClone(result),
        storedAt: now(),
        ttlMs,
      })
      evictOldest(state.l1)

      if (!allow) return
      if (!l2Eligible(facts)) return

      // Initial approval of a routine write installs same-object grants. A target
      // that does not exist yet is granted with no object identity; the outcome
      // later advances it via recordTargets.
      const time = now()
      const effect = facts.effect!
      for (const target of facts.targets) {
        const key = grantKey(target)
        const previous = state.l2.get(key)
        // A second approval on the same object keeps the wider of the two
        // effects; both were adjudicated under this same scope.
        const kept = previous && !expired(previous.storedAt, allowTtlMs) && effectCovers(previous.effect, effect)
          ? previous.effect : effect
        state.l2.delete(key)
        state.l2.set(key, {
          effect: kept,
          expectedExists: target.exists,
          expectedDev: target.dev,
          expectedIno: target.ino,
          expectedMode: target.mode,
          result: structuredClone(result),
          storedAt: time,
        })
      }
      evictOldest(state.l2)
    },

    recordTargets(scope, facts, targets) {
      const state = currentSession(scope)
      if (!state) return
      // The outcome may only advance a routine write-level grant; a full-approval
      // or non-write request never advances object identity.
      if (
        facts.kind !== "write" ||
        !isWriteLevel(facts.operation) ||
        facts.requiresFullApproval !== false
      ) {
        return
      }

      // Bind the update to *this* call's targets: a caller cannot smuggle another
      // previously granted path and rewrite that object's identity.
      const authorizedKeys = new Set(facts.targets.map(grantKey))

      for (const target of targets) {
        if (!targetFullyIdentified(target)) continue
        const key = grantKey(target)
        if (!authorizedKeys.has(key)) continue
        const grant = state.l2.get(key)
        // Only already-granted same path/parent write objects may advance.
        if (!grant) continue
        if (expired(grant.storedAt, allowTtlMs)) {
          state.l2.delete(key)
          continue
        }
        // Atomic in-place identity advance: the same grant, never a new path.
        grant.expectedExists = target.exists
        grant.expectedDev = target.dev
        grant.expectedIno = target.ino
        grant.expectedMode = target.mode
      }
    },

    clear(sessionID) {
      sessions.delete(sessionID)
    },

    clearAll() {
      sessions.clear()
    },
  }
}

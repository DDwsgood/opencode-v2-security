// Process-wide shared security state for the opencode-v2-security plugin.
//
// The host loads ONE plugin instance per session location, but every instance
// runs in the SAME server OS process. Security state that used to live in
// per-instance closures (bypass leases, session permission baselines,
// ancestry maps, notice snapshots, the approval cache and L3 grants) therefore
// split per location: a `/bypass yolo` armed in the main session never
// reached a subagent served by another instance, and a location re-boot
// reloaded the plugin and silently dropped that location's state.
//
// Every instance now keeps USER-AUTHORITY / SESSION-SECURITY state in a single
// registry stored on `globalThis[Symbol.for("opencode-v2-security.state.v1")]`
// — created once, reused by every instance and by reloaded instances. Only
// genuinely instance-bound resources (ctx handles, broker sockets, RPC
// registrations, timers, in-flight review single-flights) stay per-instance.
//
// There is deliberately NO file persistence: a service restart still clears
// every lease (leases are memory-only by design).
//
// Change propagation: instances mutate shared maps directly and then publish
// a `session-state-changed` event on the registry's in-process listener set.
// Every other instance reacts exactly as the mutating instance does for its
// own descendants — refresh the merged security notice (which also revokes
// that instance's running monitored calls and clears the shared approval
// cache when the security basis moved), re-sync descendants, and re-emit the
// TUI RPC snapshots through its own channel. Reactions are idempotent, so
// duplicated events are harmless.

import type { BypassCategory } from "../config"
import { permIntersect, type Perm } from "../permissions"
import { createApprovalCache, type ApprovalCache } from "./approval-cache"
import { createNoticeStore, type NoticeStore } from "../session-notifications"
import type { RootWideningStore } from "./root-widening"

/** A temporary bypass lease. In-memory by design: a service restart clears
 *  every lease. `expiresAt` is an absolute deadline; `all` is the Bypass
 *  kill switch; `restoreBaseline` is stashed by the Bypass transition so
 *  expiry can never leave a read-only baseline permanently widened. */
export interface BypassLease {
  categories: Set<BypassCategory>
  expiresAt: number
  all?: boolean
  custom?: string[]
  restoreBaseline?: Perm
}

/** Declared permission waiting for an authoritative execute.after childID. */
export interface PermStashEntry {
  parentSessionID: string
  perm: Perm
  at: number
  /** A real agent-supplied ceiling (vs. a default bookkeeping entry). */
  declared?: boolean
}

export interface SharedStateEvent {
  readonly kind: "session-state-changed"
  readonly sessionID: string
  /** Instance token of the mutator; its own listener skips these. */
  readonly origin: symbol
}

export interface LocationSecurityPolicy {
  defaultPerm: Perm
  permanentBypass: readonly BypassCategory[]
  propagateBypass: boolean
  failPolicy: "fail_open" | "fail_close"
  sandboxEnabled: boolean
  sandboxFull: boolean
}

interface LocationPolicyEntry {
  basis: LocationSecurityPolicy
  owners: Set<symbol>
}

export function securityLocationKey(location: { directory: string; workspaceID?: unknown }): string {
  return JSON.stringify([location.directory, location.workspaceID ?? null])
}

export type SharedStateListener = (event: SharedStateEvent) => void

interface SharedSecurityStateFields {
  readonly version: 1
  // Temporary bypass leases + child→parent links (session lifetime).
  readonly bypassLeases: Map<string, BypassLease>
  readonly bypassParent: Map<string, string>
  // Session rwx baselines + hydrated ancestry.
  readonly sessionPerms: Map<string, Perm>
  readonly permParent: Map<string, string>
  readonly permStash: Map<string, PermStashEntry>
  readonly permCreatedAt: Map<string, number>
  readonly permBoundChildren: Set<string>
  readonly permKnownRoots: Set<string>
  readonly permUnresolved: Set<string>
  readonly explicitNoBypass: Set<string>
  // Security-snapshot bases and epochs: shared so a snapshot computed by one
  // instance is byte-identical for every instance (the approval cache keys on
  // it, and admissions are re-verified against it mid-flight).
  readonly securityBases: Map<string, string>
  readonly securityEpochs: Map<string, number>
  readonly locationPolicies: Map<string, LocationPolicyEntry>
  readonly sessionLocations: Map<string, string>
  // Per-session approval cache: one shared object, so a session's cached
  // approvals are not split by which instance serves the call.
  readonly approvalCache: ApprovalCache
  // L3 temporary write-root grants/repetitions, shared for the same reason.
  readonly l3: RootWideningStore
  // Security-notice snapshot store: shared so a notice recorded by one
  // instance is delivered exactly once, by whichever instance handles that
  // session's prompt hook / tool result.
  readonly notices: NoticeStore
}

export interface SharedSecurityState extends SharedSecurityStateFields {
  registerLocationPolicy(location: string, owner: symbol, basis: LocationSecurityPolicy, warn: () => void): void
  unregisterLocationPolicy(owner: symbol): void
  policyForLocation(location: string): LocationSecurityPolicy
  /** Register a change listener. Returns the unsubscribe function. */
  subscribe(listener: SharedStateListener): () => void
  /** Notify every other instance's listeners. Listener errors are contained
   *  so a broken reaction can never fail the mutating call. */
  publish(event: SharedStateEvent): void
}

const STATE_KEY = Symbol.for("opencode-v2-security.state.v1")
const STATE_VERSION = 1

function createSharedState(): SharedSecurityState {
  const state: SharedSecurityStateFields = {
    version: STATE_VERSION,
    bypassLeases: new Map(),
    bypassParent: new Map(),
    sessionPerms: new Map(),
    permParent: new Map(),
    permStash: new Map(),
    permCreatedAt: new Map(),
    permBoundChildren: new Set(),
    permKnownRoots: new Set(),
    permUnresolved: new Set(),
    explicitNoBypass: new Set(),
    securityBases: new Map(),
    securityEpochs: new Map(),
    locationPolicies: new Map(),
    sessionLocations: new Map(),
    approvalCache: createApprovalCache(),
    l3: { repetitions: new Map(), grants: new Map() },
    notices: createNoticeStore(),
  }
  const listeners = new Set<SharedStateListener>()
  const warnedLocations = new Set<string>()
  const registry: SharedSecurityState = {
    ...state,
    registerLocationPolicy(location, owner, basis, warn) {
      const normalized = { ...basis, defaultPerm: { ...basis.defaultPerm },
        permanentBypass: [...basis.permanentBypass].sort() }
      const existing = state.locationPolicies.get(location)
      if (!existing) {
        state.locationPolicies.set(location, { basis: normalized, owners: new Set([owner]) })
      } else {
        if (JSON.stringify(existing.basis) !== JSON.stringify(normalized)) {
          if (!warnedLocations.has(location)) {
            warnedLocations.add(location)
            warn()
          }
          existing.basis = {
            defaultPerm: permIntersect(existing.basis.defaultPerm, normalized.defaultPerm),
            permanentBypass: existing.basis.permanentBypass.filter((category) => normalized.permanentBypass.includes(category)),
            propagateBypass: existing.basis.propagateBypass && normalized.propagateBypass,
            failPolicy: existing.basis.failPolicy === "fail_close" || normalized.failPolicy === "fail_close" ? "fail_close" : "fail_open",
            sandboxEnabled: existing.basis.sandboxEnabled || normalized.sandboxEnabled,
            sandboxFull: existing.basis.sandboxFull && normalized.sandboxFull,
          }
        }
        existing.owners.add(owner)
      }
      for (const [sessionID, home] of state.sessionLocations) {
        if (home === location) registry.publish({ kind: "session-state-changed", sessionID, origin: owner })
      }
    },
    unregisterLocationPolicy(owner) {
      for (const [location, entry] of state.locationPolicies) {
        if (!entry.owners.delete(owner) || entry.owners.size > 0) continue
        for (const [sessionID, home] of state.sessionLocations) {
          if (home === location) registry.publish({ kind: "session-state-changed", sessionID, origin: owner })
        }
      }
    },
    policyForLocation(location) {
      const entry = state.locationPolicies.get(location)
      if (entry?.owners.size) return entry.basis
      // A missing/reloading home instance is not authority to widen. Preserve
      // a known read restriction, prohibit writes and inherited bypass.
      return { defaultPerm: { r: entry?.basis.defaultPerm.r ?? true, w: false, x: true },
        permanentBypass: [], propagateBypass: false, failPolicy: "fail_close",
        sandboxEnabled: true, sandboxFull: false }
    },
    subscribe(listener: SharedStateListener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    publish(event: SharedStateEvent) {
      for (const listener of [...listeners]) {
        if (listener === undefined) continue
        try {
          listener(event)
        } catch {
          // A reaction failure in one instance must never break the
          // instance that mutated the state.
        }
      }
    },
  }
  return registry
}

/** Shape check for a registry found under the state key: version match plus
 *  the maps/objects this version depends on. An incompatible older registry
 *  (different shape) is never reused — a fresh one replaces it. */
function isCompatibleState(value: unknown): value is SharedSecurityState {
  if (!value || typeof value !== "object") return false
  const record = value as Record<string, unknown>
  if (record.version !== STATE_VERSION) return false
  for (const key of [
    "bypassLeases", "bypassParent", "sessionPerms", "permParent", "permStash",
    "permCreatedAt", "permBoundChildren", "permKnownRoots", "permUnresolved",
    "explicitNoBypass", "securityBases", "securityEpochs", "approvalCache",
    "l3", "notices",
    "locationPolicies", "sessionLocations",
  ] as const) {
    if (!record[key]) return false
  }
  return (
    typeof (record.approvalCache as { clearAll?: unknown }).clearAll === "function" &&
    typeof (value as SharedSecurityState).subscribe === "function" &&
    typeof (value as SharedSecurityState).publish === "function"
  )
}

/** The process-wide security-state registry. Every plugin instance captures
 *  the returned object ONCE at effect start, so a test reset mid-run cannot
 *  split one instance across two registries. */
export function getSharedSecurityState(): SharedSecurityState {
  const holder = globalThis as Record<symbol, unknown>
  const existing = holder[STATE_KEY]
  if (isCompatibleState(existing)) return existing
  const fresh = createSharedState()
  holder[STATE_KEY] = fresh
  return fresh
}

/** Test-only: replace the registry with a fresh one under the same key.
 *  Instances created before the reset keep their captured (now detached)
 *  registry, so old harnesses stay isolated; instances created afterwards
 *  share the fresh registry. Never call this in production code. */
export function resetSharedSecurityStateForTests(): void {
  ;(globalThis as Record<symbol, unknown>)[STATE_KEY] = createSharedState()
}

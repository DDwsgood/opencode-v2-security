import { describe, expect, test } from "bun:test"
import { STATIC_BYPASS_CATEGORIES } from "../src/categories"
import { EFFECTS_POLICY_VERSION, type EffectReviewResult } from "../src/security/effects-reviewer"
import {
  boundaryCoreDigest,
  createApprovalCache,
  isShellInterpreter,
  observedNetworkEndpoint,
  type ApprovalCacheFacts,
  type ApprovalCacheScope,
  type ApprovalCacheTarget,
} from "../src/security/approval-cache"

// Focused logic tests for the memory-only approval cache. No shell command is
// executed and no real credential or host state is touched: every fact is a
// synthetic fixture and time is an injected clock.

const ALLOW_TTL = 20 * 60 * 1000
const DENY_TTL = 5 * 60 * 1000

function makeResult(overrides: Partial<EffectReviewResult> = {}): EffectReviewResult {
  const base: EffectReviewResult = {
    decision: "allow",
    floor: "no",
    coverage: "no_material_effects",
    gapReach: "no_blocking_gap",
    uncoveredOwner: "none",
    severity: Object.fromEntries(STATIC_BYPASS_CATEGORIES.map((cat) => [cat, 0])) as EffectReviewResult["severity"],
    facts: Object.fromEntries(STATIC_BYPASS_CATEGORIES.map((cat) => [cat, ""])) as EffectReviewResult["facts"],
    answers: {},
    policyVersion: EFFECTS_POLICY_VERSION,
    source: "bounded",
  }
  return { ...base, ...overrides }
}

function scope(overrides: Partial<ApprovalCacheScope> = {}): ApprovalCacheScope {
  return {
    sessionID: "session-1",
    securitySnapshot: "snapshot-a",
    userAuthorizationDigest: "auth-a",
    ...overrides,
  }
}

function target(overrides: Partial<ApprovalCacheTarget> = {}): ApprovalCacheTarget {
  return {
    path: "/workspace/data.txt",
    domain: "linux",
    exists: true,
    dev: "8",
    ino: "1001",
    parentDev: "8",
    parentIno: "2",
    ...overrides,
  }
}

type FactsOverrides = Partial<Omit<ApprovalCacheFacts, "targets">> & { targets?: readonly ApprovalCacheTarget[] }

function facts(overrides: FactsOverrides = {}): ApprovalCacheFacts {
  return {
    coreDigest: "digest-1",
    kind: "write",
    operation: "modify",
    targets: [target()],
    requiresFullApproval: false,
    effect: "overwrite",
    ...overrides,
  }
}

function clock(start = 0) {
  let time = start
  return {
    now: () => time,
    set: (value: number) => {
      time = value
    },
    advance: (delta: number) => {
      time += delta
    },
  }
}

describe("L1 exact adjudication", () => {
  test("replays an exact allow and returns a detached copy", () => {
    const cache = createApprovalCache()
    const s = scope()
    const result = makeResult({ severity: { ...makeResult().severity, filesystem: 0.75 } })
    cache.store(s, facts({ kind: "read", targets: [] }), result)

    const hit = cache.lookup(s, facts({ kind: "read", targets: [] }))
    expect(hit).toMatchObject({ layer: "L1", decision: "allow" })
    expect(hit!.result!.severity.filesystem).toBe(0.75)
  })

  test("a caller mutating the stored report cannot poison the cache", () => {
    const cache = createApprovalCache()
    const s = scope()
    const result = makeResult({ severity: { ...makeResult().severity, filesystem: 0.75 } })
    cache.store(s, facts({ kind: "read", targets: [] }), result)

    ;(result.severity as Record<string, number>).filesystem = 0
    result.decision = "deny"
    const hit = cache.lookup(s, facts({ kind: "read", targets: [] }))
    expect(hit!.result!.decision).toBe("allow")
    expect(hit!.result!.severity.filesystem).toBe(0.75)
  })

  test("a caller mutating a returned report cannot poison the next hit", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ kind: "read", targets: [] }), makeResult())

    const first = cache.lookup(s, facts({ kind: "read", targets: [] }))
    ;(first!.result as EffectReviewResult).decision = "deny"
    const second = cache.lookup(s, facts({ kind: "read", targets: [] }))
    expect(second!.result!.decision).toBe("allow")
  })

  test("explicit denies are cached negatively and expire on the deny TTL", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const f = facts({ kind: "read", targets: [] })
    cache.store(s, f, makeResult({ decision: "deny", floor: "yes", source: "floor" }))

    c.set(DENY_TTL - 1)
    expect(cache.lookup(s, f)).toMatchObject({ layer: "L1", decision: "deny" })
    c.set(DENY_TTL)
    expect(cache.lookup(s, f)).toBeUndefined()
  })

  test("allows expire after the default 20 minute TTL", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const f = facts({ kind: "read", targets: [] })
    cache.store(s, f, makeResult())

    c.set(ALLOW_TTL - 1)
    expect(cache.lookup(s, f)?.layer).toBe("L1")
    c.set(ALLOW_TTL * 2 - 1)
    expect(cache.lookup(s, f)).toBeUndefined()
  })

  test("every allow hit slides the TTL window forward", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const f = facts({ kind: "read", targets: [] })
    cache.store(s, f, makeResult())

    // Without the slide this entry would have died at ALLOW_TTL.
    c.set(ALLOW_TTL - 1)
    expect(cache.lookup(s, f)?.layer).toBe("L1")
    // The hit re-anchored at ALLOW_TTL - 1: still alive near the new horizon,
    // dead once the new window fully elapses.
    c.set(ALLOW_TTL * 2 - 2)
    expect(cache.lookup(s, f)?.layer).toBe("L1")
    c.set(ALLOW_TTL * 3 - 2)
    expect(cache.lookup(s, f)).toBeUndefined()
  })

  test("the deny TTL is fixed and does not slide on hits", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const f = facts({ kind: "read", targets: [] })
    cache.store(s, f, makeResult({ decision: "deny", floor: "yes", source: "floor" }))

    c.set(DENY_TTL - 1)
    expect(cache.lookup(s, f)).toMatchObject({ layer: "L1", decision: "deny" })
    c.set(DENY_TTL)
    expect(cache.lookup(s, f)).toBeUndefined()
  })

  test("custom TTL options are honored", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now, allowTtlMs: 100, denyTtlMs: 10 })
    const s = scope()
    cache.store(s, facts({ kind: "read", targets: [] }), makeResult())
    c.set(99)
    expect(cache.lookup(s, facts({ kind: "read", targets: [] }))?.layer).toBe("L1")
    // Sliding: the hit at 99 re-anchored the window, so it survives past 100.
    c.set(198)
    expect(cache.lookup(s, facts({ kind: "read", targets: [] }))?.layer).toBe("L1")
    c.set(298)
    expect(cache.lookup(s, facts({ kind: "read", targets: [] }))).toBeUndefined()
  })
})

describe("weak decisions are not cached", () => {
  const uncacheable: Array<[string, EffectReviewResult]> = [
    ["collect_evidence", makeResult({ decision: "collect_evidence", floor: "no", source: "evidence" })],
    ["allow with unclear floor", makeResult({ decision: "allow", floor: "unclear", source: "coverage" })],
    ["allow accepted_unknown", makeResult({ decision: "allow", floor: "no", source: "accepted_unknown" })],
    ["allow evidence_limit", makeResult({ decision: "allow", floor: "no", source: "evidence_limit" })],
  ]

  for (const [label, result] of uncacheable) {
    test(`${label} does not survive as an allow`, () => {
      const cache = createApprovalCache()
      const s = scope()
      const f = facts({ kind: "read", targets: [] })
      cache.store(s, f, result)
      expect(cache.lookup(s, f)).toBeUndefined()
    })
  }

  test("an allow that is not clean never installs an L2 grant either", () => {
    const cache = createApprovalCache()
    const s = scope()
    const f = facts({ operation: "modify" })
    cache.store(s, f, makeResult({ decision: "allow", floor: "unclear", source: "coverage" }))
    const later = facts({ coreDigest: "digest-2", operation: "modify" })
    expect(cache.lookup(s, later)).toBeUndefined()
  })

  test("insufficient-evidence denies are not negative-cached", () => {
    for (const source of ["evidence_limit", "accepted_unknown"] as const) {
      const cache = createApprovalCache()
      const s = scope()
      const f = facts({ kind: "read", targets: [] })
      cache.store(s, f, makeResult({ decision: "deny", floor: "no", source }))
      expect(cache.lookup(s, f)).toBeUndefined()
    }
  })

  test("explicit floor and effect denies remain negative-cached", () => {
    for (const source of ["floor", "effect"] as const) {
      const cache = createApprovalCache()
      const s = scope()
      const f = facts({ kind: "read", targets: [] })
      cache.store(s, f, makeResult({ decision: "deny", floor: source === "floor" ? "yes" : "no", source }))
      expect(cache.lookup(s, f)).toMatchObject({ layer: "L1", decision: "deny" })
    }
  })

  test("a deny never installs an L2 grant", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ operation: "modify" }), makeResult({ decision: "deny", floor: "yes", source: "floor" }))
    expect(cache.lookup(s, facts({ coreDigest: "digest-2", operation: "modify" }))).toBeUndefined()
  })
})

describe("scope and session isolation", () => {
  test("changing the security snapshot clears prior approvals", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope(), f, makeResult())

    expect(cache.lookup(scope({ securitySnapshot: "snapshot-b" }), f)).toBeUndefined()
    cache.store(scope({ securitySnapshot: "snapshot-b" }), facts({ kind: "read", targets: [], coreDigest: "other" }), makeResult())
    // The old snapshot is gone: a new scope discards, it does not branch.
    expect(cache.lookup(scope(), f)).toBeUndefined()
  })

  test("a new user message keeps positive approvals", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope(), f, makeResult())

    // Only the security snapshot scopes positive state: the user-message
    // digest does not drop an allow.
    expect(cache.lookup(scope({ userAuthorizationDigest: "auth-b" }), f)?.layer).toBe("L1")
    cache.store(scope({ userAuthorizationDigest: "auth-b" }), facts({ kind: "read", targets: [], coreDigest: "other" }), makeResult())
    expect(cache.lookup(scope(), f)?.layer).toBe("L1")
  })

  test("a deny stays bound to its user authorization digest", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope(), f, makeResult({ decision: "deny", floor: "yes", source: "floor" }))

    // A new user message may authorize what was denied: the negative entry
    // misses, while a repeated identical authorization hits again.
    expect(cache.lookup(scope({ userAuthorizationDigest: "auth-b" }), f)).toBeUndefined()
    expect(cache.lookup(scope(), f)).toMatchObject({ layer: "L1", decision: "deny" })
    // A positive verdict for the same core then replaces the stale denial.
    cache.store(scope({ userAuthorizationDigest: "auth-b" }), f, makeResult())
    expect(cache.lookup(scope({ userAuthorizationDigest: "auth-b" }), f)).toMatchObject({ layer: "L1", decision: "allow" })
  })

  test("a lookup under a stale snapshot scope misses without wiping the current scope", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope({ securitySnapshot: "snapshot-new" }), f, makeResult())

    expect(cache.lookup(scope({ securitySnapshot: "snapshot-old" }), f)).toBeUndefined()
    cache.recordTargets(scope({ securitySnapshot: "snapshot-old" }), facts(), [target({ ino: "777" })])
    expect(cache.lookup(scope({ securitySnapshot: "snapshot-new" }), f)?.layer).toBe("L1")
  })

  test("the number of sessions holding cache state is bounded", () => {
    const cache = createApprovalCache({ maxSessions: 2 })
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope({ sessionID: "a" }), f, makeResult())
    cache.store(scope({ sessionID: "b" }), f, makeResult())
    expect(cache.lookup(scope({ sessionID: "a" }), f)?.layer).toBe("L1")
    cache.store(scope({ sessionID: "c" }), f, makeResult())

    expect(cache.lookup(scope({ sessionID: "b" }), f)).toBeUndefined()
    expect(cache.lookup(scope({ sessionID: "a" }), f)?.layer).toBe("L1")
    expect(cache.lookup(scope({ sessionID: "c" }), f)?.layer).toBe("L1")
  })

  test("approvals never cross sessions or reach a subagent id", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope({ sessionID: "parent" }), f, makeResult())

    expect(cache.lookup(scope({ sessionID: "subagent-child" }), f)).toBeUndefined()
    expect(cache.lookup(scope({ sessionID: "parent" }), f)?.layer).toBe("L1")
  })

  test("clear and clearAll remove only their target", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope({ sessionID: "a" }), f, makeResult())
    cache.store(scope({ sessionID: "b" }), f, makeResult())

    cache.clear("a")
    expect(cache.lookup(scope({ sessionID: "a" }), f)).toBeUndefined()
    expect(cache.lookup(scope({ sessionID: "b" }), f)?.layer).toBe("L1")

    cache.clearAll()
    expect(cache.lookup(scope({ sessionID: "b" }), f)).toBeUndefined()
  })
})

describe("LRU bounding", () => {
  test("default cap evicts the least recently used of 256 entries", () => {
    const cache = createApprovalCache()
    const s = scope()
    for (let i = 0; i < 257; i++) {
      cache.store(s, facts({ kind: "read", targets: [], coreDigest: `d-${i}` }), makeResult())
    }
    expect(cache.lookup(s, facts({ kind: "read", targets: [], coreDigest: "d-0" }))).toBeUndefined()
    expect(cache.lookup(s, facts({ kind: "read", targets: [], coreDigest: "d-1" }))?.layer).toBe("L1")
    expect(cache.lookup(s, facts({ kind: "read", targets: [], coreDigest: "d-256" }))?.layer).toBe("L1")
  })

  test("a hit refreshes recency for LRU eviction", () => {
    const cache = createApprovalCache({ maxPerSession: 2 })
    const s = scope()
    const a = facts({ kind: "read", targets: [], coreDigest: "a" })
    const b = facts({ kind: "read", targets: [], coreDigest: "b" })
    const c = facts({ kind: "read", targets: [], coreDigest: "c" })
    cache.store(s, a, makeResult())
    cache.store(s, b, makeResult())
    expect(cache.lookup(s, a)?.layer).toBe("L1")
    cache.store(s, c, makeResult())

    expect(cache.lookup(s, b)).toBeUndefined()
    expect(cache.lookup(s, a)?.layer).toBe("L1")
  })
})

describe("L2 same-object routine writes", () => {
  test("reuses a same-level write after the exact content digest changes", () => {
    const cache = createApprovalCache()
    const s = scope()
    const existing = target()
    cache.store(s, facts({ coreDigest: "before", targets: [existing] }), makeResult({ source: "coverage", coverage: "within_request" }))

    const hit = cache.lookup(s, facts({ coreDigest: "after", targets: [target()] }))
    expect(hit).toMatchObject({ layer: "L2", decision: "allow" })
    expect(hit!.result!.decision).toBe("allow")
  })

  test("normalizes open to the same write level as create", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    cache.store(s, facts({ operation: "create", targets: [missing] }), makeResult())

    const hit = cache.lookup(s, facts({ coreDigest: "open-again", operation: "open", targets: [missing] }))
    expect(hit?.layer).toBe("L2")
  })

  test("advances a create grant to modify after the outcome stat arrives", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    const authorized = facts({ operation: "create", targets: [missing] })
    cache.store(s, authorized, makeResult())

    const modify = facts({ coreDigest: "modify-after", operation: "modify", targets: [target()] })
    expect(cache.lookup(s, modify)).toBeUndefined()

    cache.recordTargets(s, authorized, [target({ exists: true, dev: "8", ino: "1001" })])
    expect(cache.lookup(s, modify)?.layer).toBe("L2")
  })

  test("recordTargets cannot create a grant for an ungranted path", () => {
    const cache = createApprovalCache()
    const s = scope()
    const authorized = facts({ operation: "create", targets: [target({ exists: false, dev: undefined, ino: undefined })] })
    cache.store(s, authorized, makeResult())

    const other = target({ path: "/workspace/other.txt", ino: "9999" })
    cache.recordTargets(s, authorized, [other])

    expect(cache.lookup(s, facts({ coreDigest: "other", operation: "modify", targets: [other] }))).toBeUndefined()
  })

  test("recordTargets cannot rewrite an identity outside this call's facts", () => {
    const cache = createApprovalCache()
    const s = scope()
    const a = target({ path: "/workspace/a.txt", ino: "1" })
    const b = target({ path: "/workspace/b.txt", ino: "2" })
    cache.store(s, facts({ targets: [a, b] }), makeResult())

    // Call facts authorize only a, but the caller smuggles b with a new ino.
    const smuggled = target({ path: "/workspace/b.txt", ino: "999" })
    cache.recordTargets(s, facts({ targets: [a] }), [smuggled])

    expect(cache.lookup(s, facts({ coreDigest: "b-new", targets: [smuggled] }))).toBeUndefined()
    expect(cache.lookup(s, facts({ coreDigest: "b-old", targets: [target({ path: "/workspace/b.txt", ino: "2" })] }))?.layer).toBe("L2")
  })

  test("recordTargets refuses full-approval or non-write facts", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    cache.store(s, facts({ operation: "create", targets: [missing] }), makeResult())
    const actual = target({ exists: true, ino: "1001" })

    cache.recordTargets(s, facts({ operation: "create", targets: [missing], requiresFullApproval: true }), [actual])
    expect(cache.lookup(s, facts({ coreDigest: "after-full", operation: "modify", targets: [target()] }))).toBeUndefined()

    cache.recordTargets(s, facts({ operation: "create", targets: [missing], kind: "read" }), [actual])
    expect(cache.lookup(s, facts({ coreDigest: "after-read", operation: "modify", targets: [target()] }))).toBeUndefined()

    cache.recordTargets(s, facts({ operation: "create", targets: [missing] }), [actual])
    expect(cache.lookup(s, facts({ coreDigest: "after-write", operation: "modify", targets: [target()] }))?.layer).toBe("L2")
  })

  test("identity drift misses instead of reusing a neighboring object", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ targets: [target({ ino: "1001" })] }), makeResult())

    expect(cache.lookup(s, facts({ coreDigest: "drift", targets: [target({ ino: "2002" })] }))).toBeUndefined()
  })

  test("dev/ino are compared as opaque strings, never coerced to numbers", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ targets: [target({ ino: "1001" })] }), makeResult())

    expect(cache.lookup(s, facts({ coreDigest: "padded", targets: [target({ ino: "01001" })] }))).toBeUndefined()
  })

  test("delete and other non-write-level operations never hit L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ operation: "modify", targets: [target()] }), makeResult())

    for (const operation of ["delete", "rename", "metadata", "exec"]) {
      expect(cache.lookup(s, facts({ coreDigest: operation, operation, targets: [target()] }))).toBeUndefined()
    }
  })

  test("read/privilege/interop/opaque kinds never hit L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    for (const kind of ["read", "privilege", "interop", "opaque"] as const) {
      const store = facts({ kind, targets: [target()] })
      cache.store(s, store, makeResult())
      expect(cache.lookup(s, facts({ kind, coreDigest: `${kind}-again`, targets: [target()] }))).toBeUndefined()
    }
  })

  test("requiresFullApproval must be explicitly false for L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ requiresFullApproval: true, targets: [target()] }), makeResult())
    expect(cache.lookup(s, facts({ coreDigest: "full", requiresFullApproval: true, targets: [target()] }))).toBeUndefined()

    const cache2 = createApprovalCache()
    cache2.store(s, facts({ requiresFullApproval: undefined, targets: [target()] }), makeResult())
    expect(cache2.lookup(s, facts({ coreDigest: "unspecified", requiresFullApproval: undefined, targets: [target()] }))).toBeUndefined()
  })

  test("partial multi-target coverage misses", () => {
    const cache = createApprovalCache()
    const s = scope()
    const a = target()
    const b = target({ path: "/workspace/b.txt", ino: "2002" })
    cache.store(s, facts({ targets: [a] }), makeResult())

    expect(cache.lookup(s, facts({ coreDigest: "multi", targets: [a, b] }))).toBeUndefined()
  })

  test("drvfs with reliable string identities supports L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ targets: [target({ domain: "drvfs" })] }), makeResult())
    expect(cache.lookup(s, facts({ coreDigest: "drvfs-again", targets: [target({ domain: "drvfs" })] }))?.layer).toBe("L2")
  })

  test("a target missing any required identity disables L2 without guessing", () => {
    const cache = createApprovalCache()
    const s = scope()

    // drvfs without a reliable object identity: the initial write is still
    // eligible for L1, but no L2 grant is guessed.
    const drvfs = target({ domain: "drvfs", exists: true, dev: undefined, ino: undefined })
    cache.store(s, facts({ targets: [drvfs] }), makeResult())
    expect(cache.lookup(s, facts({ coreDigest: "drvfs-again", targets: [drvfs] }))).toBeUndefined()

    // A missing parent identity also disables L2.
    const noParent = target({ parentIno: undefined })
    cache.store(s, facts({ targets: [noParent] }), makeResult())
    expect(cache.lookup(s, facts({ coreDigest: "no-parent", targets: [noParent] }))).toBeUndefined()
  })

  test("a scope change also discards L2 grants", () => {
    const cache = createApprovalCache()
    cache.store(scope(), facts({ targets: [target()] }), makeResult())

    expect(cache.lookup(scope({ securitySnapshot: "snapshot-b" }), facts({ coreDigest: "b", targets: [target()] }))).toBeUndefined()
    cache.store(scope({ securitySnapshot: "snapshot-b" }), facts({ kind: "read", targets: [], coreDigest: "x" }), makeResult())
    expect(cache.lookup(scope(), facts({ coreDigest: "a", targets: [target()] }))).toBeUndefined()
  })

  test("a grant never widens the write effect", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ effect: "append", targets: [target()] }), makeResult())

    expect(cache.lookup(s, facts({ coreDigest: "append-2", effect: "append" }))?.layer).toBe("L2")
    expect(cache.lookup(s, facts({ coreDigest: "fd-write", effect: "fd-write" }))?.layer).toBe("L2")
    expect(cache.lookup(s, facts({ coreDigest: "overwrite", effect: "overwrite" }))).toBeUndefined()
    expect(cache.lookup(s, facts({ coreDigest: "truncate", effect: "replace" }))).toBeUndefined()
    expect(cache.lookup(s, facts({ coreDigest: "mkdir", effect: "mkdir" }))).toBeUndefined()
  })

  test("an L2 hit slides the grant's TTL window", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const existing = target()
    cache.store(s, facts({ coreDigest: "before", targets: [existing] }), makeResult())

    // The grant would have died at ALLOW_TTL without the slide.
    c.set(ALLOW_TTL - 1)
    const later = facts({ coreDigest: "after", targets: [target()] })
    expect(cache.lookup(s, later)?.layer).toBe("L2")
    c.set(ALLOW_TTL * 2 - 1)
    expect(cache.lookup(s, later)).toBeUndefined()
  })

  test("a replace grant covers narrower content writes, and a later narrower approval keeps it", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ effect: "replace", targets: [target()] }), makeResult())
    cache.store(s, facts({ coreDigest: "later-append", effect: "append", targets: [target()] }), makeResult())

    for (const effect of ["replace", "overwrite", "append", "fd-write"] as const) {
      expect(cache.lookup(s, facts({ coreDigest: `after-${effect}`, effect }))?.layer).toBe("L2")
    }
  })

  test("writes without a known effect (links, device nodes) never enter L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    cache.store(s, facts({ operation: "create", effect: undefined, targets: [missing] }), makeResult())

    expect(cache.lookup(s, facts({ coreDigest: "symlink-2", operation: "create", effect: undefined, targets: [missing] }))).toBeUndefined()
    expect(cache.lookup(s, facts({ coreDigest: "file", operation: "create", effect: "overwrite", targets: [missing] }))).toBeUndefined()
  })
})

describe("boundary core digest", () => {
  test("network host, port and family separate both allow and deny entries", () => {
    const endpoints = [
      { family: "AF_INET", target: "127.0.0.1:8080" },
      { family: "AF_INET", target: "203.0.113.1:8080" },
      { family: "AF_INET", target: "127.0.0.1:8081" },
      { family: "AF_INET6", target: "[::1]:8080", scopeID: 0 },
      { family: "AF_INET6", target: "[::1]:8080", scopeID: 1 },
    ]
    const crossings = endpoints.map((network) => facts({
      kind: "network", operation: "connect", targets: [],
      networkEndpoint: observedNetworkEndpoint(network),
      coreDigest: boundaryCoreDigest({ kind: "network", syscall: "connect", operation: "connect", targets: [], network }),
    }))
    expect(new Set(crossings.map((crossing) => crossing.coreDigest)).size).toBe(endpoints.length)
    for (const decision of ["allow", "deny"] as const) {
      const cache = createApprovalCache()
      cache.store(scope(), crossings[0]!, makeResult({ decision }))
      expect(cache.lookup(scope(), crossings[0]!)?.decision).toBe(decision)
      for (const crossing of crossings.slice(1)) expect(cache.lookup(scope(), crossing)).toBeUndefined()
    }
    const expanded = { family: "AF_INET6", target: "[0:0:0:0:0:0:0:1]:08080", scopeID: 0 }
    expect(boundaryCoreDigest({ kind: "network", syscall: "connect", operation: "connect", targets: [], network: expanded }))
      .toBe(crossings[3]!.coreDigest)
  })

  test("unidentified network endpoints never cache allows but retain denies", () => {
    for (const network of [{}, { family: "AF_INET6" }, { family: "AF_INET", target: "not-an-ip:443" },
      { family: "AF_INET", target: "127.0.0.1:65536" }]) {
      expect(observedNetworkEndpoint(network)).toBeUndefined()
      const crossing = facts({ kind: "network", operation: "connect", targets: [], requiresFullApproval: true,
        coreDigest: boundaryCoreDigest({ kind: "network", operation: "connect", targets: [], network }) })
      const cache = createApprovalCache()
      cache.store(scope(), crossing, makeResult())
      expect(cache.lookup(scope(), crossing)).toBeUndefined()
      cache.store(scope(), crossing, makeResult({ decision: "deny" }))
      expect(cache.lookup(scope(), crossing)?.decision).toBe("deny")
    }
  })

  function core(overrides: Partial<Parameters<typeof boundaryCoreDigest>[0]> = {}) {
    return boundaryCoreDigest({
      kind: "read",
      syscall: "openat",
      operation: "open",
      targets: [target()],
      executable: "/bin/bash",
      executableIdentity: "8:100:500:12345",
      argv: ["bash", "-c", "cat /workspace/data.txt | tail -30"],
      argvDigest: "argv-1",
      cwd: "/workspace",
      policyVersion: "v-test",
      bypassCategories: [],
      customBypass: [],
      ...overrides,
    })
  }

  test("a shell interpreter's argv never enters the core", () => {
    // `cmd | tail -30` → `cmd | tail -20`: the shell's argv embeds the whole
    // compound command line, so the same crossing still produces the core.
    const thirty = core({ argv: ["bash", "-c", "cat /workspace/data.txt | tail -30"], argvDigest: "argv-30" })
    const twenty = core({ argv: ["bash", "-c", "cat /workspace/data.txt | tail -20"], argvDigest: "argv-20" })
    const appended = core({ argv: ["bash", "-c", 'cat /workspace/data.txt | tail -30; echo "done"'], argvDigest: "argv-echo" })
    expect(twenty).toBe(thirty)
    expect(appended).toBe(thirty)
  })

  test("every known shell basename and busybox sh drop their argv", () => {
    for (const shell of ["bash", "sh", "dash", "zsh", "ksh", "fish"]) {
      expect(isShellInterpreter(`/bin/${shell}`, [shell, "-c", "x"])).toBe(true)
      const a = core({ executable: `/bin/${shell}`, argv: [shell, "-c", "a"], argvDigest: "argv-a" })
      const b = core({ executable: `/bin/${shell}`, argv: [shell, "-c", "b"], argvDigest: "argv-b" })
      expect(b).toBe(a)
    }
    expect(isShellInterpreter("/bin/busybox", ["busybox", "sh", "-c", "x"])).toBe(true)
    expect(isShellInterpreter("/bin/busybox", ["busybox", "ls", "/"])).toBe(false)
    expect(isShellInterpreter("/usr/bin/python3", ["python3", "-c", "x"])).toBe(false)
  })

  test("a non-shell crossing keeps its argv digest in the core", () => {
    const a = core({ executable: "/usr/bin/tail", argv: ["tail", "-30"], argvDigest: "argv-30" })
    const b = core({ executable: "/usr/bin/tail", argv: ["tail", "-20"], argvDigest: "argv-20" })
    expect(b).not.toBe(a)
    expect(core({ executable: "/usr/bin/tail", argvDigest: "argv-30" })).toBe(a)
  })

  test("command text, user authorization and volatile metadata never enter the core", () => {
    // Extra, non-contract properties a caller might carry — command text,
    // user_request, size/mtime/ctime — are not read by the digest at all.
    const base = core()
    const noisy = core({
      targets: [{ ...target(), size: "99", mtimeNs: "999", ctimeNs: "999" } as never],
    })
    expect(noisy).toBe(base)
    const extra = boundaryCoreDigest({
      kind: "read", operation: "open", targets: [target()],
      command: "rm -rf /", user_request: "anything",
    } as never)
    expect(extra).toBe(boundaryCoreDigest({ kind: "read", operation: "open", targets: [target()] }))
  })

  test("stable identities key the core; identity or mode drift changes it", () => {
    const base = core()
    expect(core({ targets: [target({ ino: "2002" })] })).not.toBe(base)
    expect(core({ targets: [target({ mode: "600" })] })).not.toBe(base)
    expect(core({ targets: [target({ path: "/workspace/other.txt" })] })).not.toBe(base)
    expect(core({ syscall: "open" })).not.toBe(base)
    expect(core({ executableIdentity: "8:100:500:99999" })).not.toBe(base)
    expect(core({ cwd: "/other" })).not.toBe(base)
    expect(core({ requiresFullApproval: true })).not.toBe(base)
    expect(core({ bypassCategories: ["filesystem"] })).not.toBe(base)
    // Same crossing, same digest.
    expect(core()).toBe(base)
  })
})

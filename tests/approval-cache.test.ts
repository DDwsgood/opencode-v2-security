import { describe, expect, test } from "bun:test"
import { STATIC_BYPASS_CATEGORIES } from "../src/categories"
import { EFFECTS_POLICY_VERSION, type EffectReviewResult } from "../src/security/effects-reviewer"
import {
  createApprovalCache,
  type ApprovalCacheFacts,
  type ApprovalCacheScope,
  type ApprovalCacheTarget,
} from "../src/security/approval-cache"

// Focused logic tests for the memory-only approval cache. No shell command is
// executed and no real credential or host state is touched: every fact is a
// synthetic fixture and time is an injected clock.

const ALLOW_TTL = 30 * 60 * 1000
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
    exactDigest: "digest-1",
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

  test("allows expire after the default 30 minute TTL", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const f = facts({ kind: "read", targets: [] })
    cache.store(s, f, makeResult())

    c.set(ALLOW_TTL - 1)
    expect(cache.lookup(s, f)?.layer).toBe("L1")
    c.set(ALLOW_TTL)
    expect(cache.lookup(s, f)).toBeUndefined()
  })

  test("a hit does not extend the TTL", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now })
    const s = scope()
    const f = facts({ kind: "read", targets: [] })
    cache.store(s, f, makeResult())

    c.set(ALLOW_TTL - 1)
    expect(cache.lookup(s, f)?.layer).toBe("L1")
    c.set(ALLOW_TTL)
    expect(cache.lookup(s, f)).toBeUndefined()
  })

  test("custom TTL options are honored", () => {
    const c = clock()
    const cache = createApprovalCache({ now: c.now, allowTtlMs: 100, denyTtlMs: 10 })
    const s = scope()
    cache.store(s, facts({ kind: "read", targets: [] }), makeResult())
    c.set(99)
    expect(cache.lookup(s, facts({ kind: "read", targets: [] }))?.layer).toBe("L1")
    c.set(100)
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
    const later = facts({ exactDigest: "digest-2", operation: "modify" })
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
    expect(cache.lookup(s, facts({ exactDigest: "digest-2", operation: "modify" }))).toBeUndefined()
  })
})

describe("scope and session isolation", () => {
  test("changing the security snapshot clears prior approvals", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope(), f, makeResult())

    expect(cache.lookup(scope({ securitySnapshot: "snapshot-b" }), f)).toBeUndefined()
    cache.store(scope({ securitySnapshot: "snapshot-b" }), facts({ kind: "read", targets: [], exactDigest: "other" }), makeResult())
    // The old snapshot is gone: a new scope discards, it does not branch.
    expect(cache.lookup(scope(), f)).toBeUndefined()
  })

  test("changing the user authorization digest clears prior approvals", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope(), f, makeResult())

    expect(cache.lookup(scope({ userAuthorizationDigest: "auth-b" }), f)).toBeUndefined()
    cache.store(scope({ userAuthorizationDigest: "auth-b" }), facts({ kind: "read", targets: [], exactDigest: "other" }), makeResult())
    expect(cache.lookup(scope(), f)).toBeUndefined()
  })

  test("a lookup under a stale scope misses without wiping the current scope", () => {
    const cache = createApprovalCache()
    const f = facts({ kind: "read", targets: [] })
    cache.store(scope({ userAuthorizationDigest: "auth-new" }), f, makeResult())

    expect(cache.lookup(scope({ userAuthorizationDigest: "auth-old" }), f)).toBeUndefined()
    cache.recordTargets(scope({ userAuthorizationDigest: "auth-old" }), facts(), [target({ ino: "777" })])
    expect(cache.lookup(scope({ userAuthorizationDigest: "auth-new" }), f)?.layer).toBe("L1")
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
      cache.store(s, facts({ kind: "read", targets: [], exactDigest: `d-${i}` }), makeResult())
    }
    expect(cache.lookup(s, facts({ kind: "read", targets: [], exactDigest: "d-0" }))).toBeUndefined()
    expect(cache.lookup(s, facts({ kind: "read", targets: [], exactDigest: "d-1" }))?.layer).toBe("L1")
    expect(cache.lookup(s, facts({ kind: "read", targets: [], exactDigest: "d-256" }))?.layer).toBe("L1")
  })

  test("a hit refreshes recency without extending TTL", () => {
    const cache = createApprovalCache({ maxPerSession: 2 })
    const s = scope()
    const a = facts({ kind: "read", targets: [], exactDigest: "a" })
    const b = facts({ kind: "read", targets: [], exactDigest: "b" })
    const c = facts({ kind: "read", targets: [], exactDigest: "c" })
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
    cache.store(s, facts({ exactDigest: "before", targets: [existing] }), makeResult({ source: "coverage", coverage: "within_request" }))

    const hit = cache.lookup(s, facts({ exactDigest: "after", targets: [target()] }))
    expect(hit).toMatchObject({ layer: "L2", decision: "allow" })
    expect(hit!.result!.decision).toBe("allow")
  })

  test("normalizes open to the same write level as create", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    cache.store(s, facts({ operation: "create", targets: [missing] }), makeResult())

    const hit = cache.lookup(s, facts({ exactDigest: "open-again", operation: "open", targets: [missing] }))
    expect(hit?.layer).toBe("L2")
  })

  test("advances a create grant to modify after the outcome stat arrives", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    const authorized = facts({ operation: "create", targets: [missing] })
    cache.store(s, authorized, makeResult())

    const modify = facts({ exactDigest: "modify-after", operation: "modify", targets: [target()] })
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

    expect(cache.lookup(s, facts({ exactDigest: "other", operation: "modify", targets: [other] }))).toBeUndefined()
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

    expect(cache.lookup(s, facts({ exactDigest: "b-new", targets: [smuggled] }))).toBeUndefined()
    expect(cache.lookup(s, facts({ exactDigest: "b-old", targets: [target({ path: "/workspace/b.txt", ino: "2" })] }))?.layer).toBe("L2")
  })

  test("recordTargets refuses full-approval or non-write facts", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    cache.store(s, facts({ operation: "create", targets: [missing] }), makeResult())
    const actual = target({ exists: true, ino: "1001" })

    cache.recordTargets(s, facts({ operation: "create", targets: [missing], requiresFullApproval: true }), [actual])
    expect(cache.lookup(s, facts({ exactDigest: "after-full", operation: "modify", targets: [target()] }))).toBeUndefined()

    cache.recordTargets(s, facts({ operation: "create", targets: [missing], kind: "read" }), [actual])
    expect(cache.lookup(s, facts({ exactDigest: "after-read", operation: "modify", targets: [target()] }))).toBeUndefined()

    cache.recordTargets(s, facts({ operation: "create", targets: [missing] }), [actual])
    expect(cache.lookup(s, facts({ exactDigest: "after-write", operation: "modify", targets: [target()] }))?.layer).toBe("L2")
  })

  test("identity drift misses instead of reusing a neighboring object", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ targets: [target({ ino: "1001" })] }), makeResult())

    expect(cache.lookup(s, facts({ exactDigest: "drift", targets: [target({ ino: "2002" })] }))).toBeUndefined()
  })

  test("dev/ino are compared as opaque strings, never coerced to numbers", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ targets: [target({ ino: "1001" })] }), makeResult())

    expect(cache.lookup(s, facts({ exactDigest: "padded", targets: [target({ ino: "01001" })] }))).toBeUndefined()
  })

  test("delete and other non-write-level operations never hit L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ operation: "modify", targets: [target()] }), makeResult())

    for (const operation of ["delete", "rename", "metadata", "exec"]) {
      expect(cache.lookup(s, facts({ exactDigest: operation, operation, targets: [target()] }))).toBeUndefined()
    }
  })

  test("read/privilege/interop/opaque kinds never hit L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    for (const kind of ["read", "privilege", "interop", "opaque"] as const) {
      const store = facts({ kind, targets: [target()] })
      cache.store(s, store, makeResult())
      expect(cache.lookup(s, facts({ kind, exactDigest: `${kind}-again`, targets: [target()] }))).toBeUndefined()
    }
  })

  test("requiresFullApproval must be explicitly false for L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ requiresFullApproval: true, targets: [target()] }), makeResult())
    expect(cache.lookup(s, facts({ exactDigest: "full", requiresFullApproval: true, targets: [target()] }))).toBeUndefined()

    const cache2 = createApprovalCache()
    cache2.store(s, facts({ requiresFullApproval: undefined, targets: [target()] }), makeResult())
    expect(cache2.lookup(s, facts({ exactDigest: "unspecified", requiresFullApproval: undefined, targets: [target()] }))).toBeUndefined()
  })

  test("partial multi-target coverage misses", () => {
    const cache = createApprovalCache()
    const s = scope()
    const a = target()
    const b = target({ path: "/workspace/b.txt", ino: "2002" })
    cache.store(s, facts({ targets: [a] }), makeResult())

    expect(cache.lookup(s, facts({ exactDigest: "multi", targets: [a, b] }))).toBeUndefined()
  })

  test("drvfs with reliable string identities supports L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ targets: [target({ domain: "drvfs" })] }), makeResult())
    expect(cache.lookup(s, facts({ exactDigest: "drvfs-again", targets: [target({ domain: "drvfs" })] }))?.layer).toBe("L2")
  })

  test("a target missing any required identity disables L2 without guessing", () => {
    const cache = createApprovalCache()
    const s = scope()

    // drvfs without a reliable object identity: the initial write is still
    // eligible for L1, but no L2 grant is guessed.
    const drvfs = target({ domain: "drvfs", exists: true, dev: undefined, ino: undefined })
    cache.store(s, facts({ targets: [drvfs] }), makeResult())
    expect(cache.lookup(s, facts({ exactDigest: "drvfs-again", targets: [drvfs] }))).toBeUndefined()

    // A missing parent identity also disables L2.
    const noParent = target({ parentIno: undefined })
    cache.store(s, facts({ targets: [noParent] }), makeResult())
    expect(cache.lookup(s, facts({ exactDigest: "no-parent", targets: [noParent] }))).toBeUndefined()
  })

  test("a scope change also discards L2 grants", () => {
    const cache = createApprovalCache()
    cache.store(scope(), facts({ targets: [target()] }), makeResult())

    expect(cache.lookup(scope({ securitySnapshot: "snapshot-b" }), facts({ exactDigest: "b", targets: [target()] }))).toBeUndefined()
    cache.store(scope({ securitySnapshot: "snapshot-b" }), facts({ kind: "read", targets: [], exactDigest: "x" }), makeResult())
    expect(cache.lookup(scope(), facts({ exactDigest: "a", targets: [target()] }))).toBeUndefined()
  })

  test("a grant never widens the write effect", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ effect: "append", targets: [target()] }), makeResult())

    expect(cache.lookup(s, facts({ exactDigest: "append-2", effect: "append" }))?.layer).toBe("L2")
    expect(cache.lookup(s, facts({ exactDigest: "fd-write", effect: "fd-write" }))?.layer).toBe("L2")
    expect(cache.lookup(s, facts({ exactDigest: "overwrite", effect: "overwrite" }))).toBeUndefined()
    expect(cache.lookup(s, facts({ exactDigest: "truncate", effect: "replace" }))).toBeUndefined()
    expect(cache.lookup(s, facts({ exactDigest: "mkdir", effect: "mkdir" }))).toBeUndefined()
  })

  test("a replace grant covers narrower content writes, and a later narrower approval keeps it", () => {
    const cache = createApprovalCache()
    const s = scope()
    cache.store(s, facts({ effect: "replace", targets: [target()] }), makeResult())
    cache.store(s, facts({ exactDigest: "later-append", effect: "append", targets: [target()] }), makeResult())

    for (const effect of ["replace", "overwrite", "append", "fd-write"] as const) {
      expect(cache.lookup(s, facts({ exactDigest: `after-${effect}`, effect }))?.layer).toBe("L2")
    }
  })

  test("writes without a known effect (links, device nodes) never enter L2", () => {
    const cache = createApprovalCache()
    const s = scope()
    const missing = target({ exists: false, dev: undefined, ino: undefined })
    cache.store(s, facts({ operation: "create", effect: undefined, targets: [missing] }), makeResult())

    expect(cache.lookup(s, facts({ exactDigest: "symlink-2", operation: "create", effect: undefined, targets: [missing] }))).toBeUndefined()
    expect(cache.lookup(s, facts({ exactDigest: "file", operation: "create", effect: "overwrite", targets: [missing] }))).toBeUndefined()
  })
})

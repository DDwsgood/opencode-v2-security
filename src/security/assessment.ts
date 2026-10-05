// assessment.ts — the unified assessment report and its cache.
//
// Research findings (category-optimization waves, final-report/REPORT.md):
// risk attribution must be reported ONCE as a complete report and reused by
// later admission checks on the same facts — instead of re-classifying a
// command that was already judged (the allow_once → second dynamic review
// double-attribution). A report is keyed by its canonical inputs, so any
// change to the command body, referenced script fingerprints, cwd, session
// permission scope, bypass set, or policy version produces a NEW report
// rather than silently reusing a stale verdict under a shifted identity.
//
// EXTERNAL COMPATIBILITY: the wire/user category vocabulary stays the
// canonical 7 names (categories.ts). The owner-model mapping below is an
// internal semantic layer for report diagnostics only — it never renames
// what users, reviewers, or escalation requests see.
//
// No new hashes/signatures are introduced: keying reuses the same canonical
// inputs (script normalization + existing script fingerprints) as the legacy
// dynamic cache key.

import { STATIC_BYPASS_CATEGORIES } from "../categories"

// ---------------------------------------------------------------------------
// Owner-model semantics (internal diagnostic axis; the external contract is
// still the canonical 7-category vocabulary).
//
// An "owner class" is the C4/R3 finding that a row actually answers for —
// one of five classes each optionally scoped. The canonical names map onto
// owner space so a report can show why a category was billed without
// exposing the experiment's question names to agents or reviewers:
//
//   canonical name  owner class   default scope
//   filesystem      data          local        (remote data rides `remote`)
//   secret          credential    local        (off-host exfil adds `network`)
//   privilege       control       local        (real permission/isolation
//                                               boundary changes only —
//                                               network reachability or the
//                                               mere word "sudo" never bill
//                                               a control owner by itself)
//   host            runtime       local        (this machine's state)
//   remote          unknown→      remote       (remote data vs remote exec are
//                     resolved     resolved only via a structured reason's
//                     by kind      kind/domain — never a fixed default)
//   network         communication network
//   indirection     unknown       local        (uninspectable execution)
//
// Root/sudo CONTEXT is never an owner class by itself: it maps to a real
// boundary change (control) when the command actually crosses one, and stays
// a diagnostic otherwise.
// ---------------------------------------------------------------------------

export type OwnerScope = "local" | "remote" | "offhost" | "none" | "unknown"

export type OwnerClass =
  | "data"
  | "credential"
  | "control"
  | "communication"
  | "runtime"
  | "unknown"

export interface OwnerFinding {
  /** Owner class the finding belongs to (internal semantics). */
  owner: OwnerClass
  /** Where the owned effect lands. */
  scope: OwnerScope
  /** Canonical external category this finding is reported as. */
  canonical: string
}

const CATEGORY_OWNER: Record<string, { owner: OwnerClass; scope: OwnerScope }> = {
  filesystem: { owner: "data", scope: "local" },
  secret: { owner: "credential", scope: "local" },
  privilege: { owner: "control", scope: "local" },
  host: { owner: "runtime", scope: "local" },
  // `remote` maps to unknown here on purpose — ownerForReason disambiguates
  // remote-data vs remote-exec from the structured kind/domain.
  remote: { owner: "unknown", scope: "remote" },
  network: { owner: "communication", scope: "offhost" },
  indirection: { owner: "unknown", scope: "local" },
}

/** Map a canonical category name onto the internal owner class/scope pair.
 *  `remote` is deliberately NOT assigned a fixed owner: the canonical name
 *  covers both remote-data and remote-execution rows, so the owner is only
 *  resolvable from a structured reason's kind/domain (see ownerForReason).
 *  Unknown names (sandbox/dynamic/slow layers, future additions) fall back to
 *  unknown/unknown instead of being dropped. */
export function ownerForCategory(category: string): { owner: OwnerClass; scope: OwnerScope } {
  return CATEGORY_OWNER[category] ?? { owner: "unknown", scope: "unknown" }
}

/** Owner diagnostic driven by a structured reason's kind/domain (the fields
 *  reviewer.py's RiskReason carries), never guessed from words like "SSH".
 *  Remote-data and remote-exec families stay distinct owner scopes;
 *  credential off-host additionally bills communication. */
export function ownerForReason(reason: {
  category: string
  kind?: string
  domain?: string
}): OwnerFinding {
  const base = ownerForCategory(reason.category)
  // Remote family split by domain/kind instead of a fixed default.
  if (reason.category === "remote") {
    const kind = reason.kind ?? ""
    const domain = reason.domain ?? ""
    if (/data|state|file|store/i.test(domain) || /remoteData|data/i.test(kind)) {
      return { canonical: "remote", owner: "data", scope: "remote" }
    }
    if (/exec|runtime|process|control/i.test(domain) || /exec|runtime|fetch/i.test(kind)) {
      return { canonical: "remote", owner: "runtime", scope: "remote" }
    }
    return { canonical: "remote", owner: "unknown", scope: "remote" }
  }
  // Secrets leaving the host additionally own the communication channel.
  if (reason.category === "secret" && /off.?host|egress|exfil/i.test(reason.domain ?? reason.kind ?? "")) {
    return { canonical: "secret", owner: "communication", scope: "offhost" }
  }
  return { canonical: reason.category, ...base }
}

/** Render the owner-model view of a canonical category list. Purely
 *  diagnostic — never feeds the bypass/escalation category vocabulary. */
export function ownersForCategories(categories: readonly string[]): OwnerFinding[] {
  return categories.map((canonical) => ({ canonical, ...ownerForCategory(canonical) }))
}

// ---------------------------------------------------------------------------
// Assessment report
// ---------------------------------------------------------------------------

/** Who produced the outcome. Model answers stay `model_decision`; every
 *  non-model stop names its own source so an infra/protocol/ceiling deny can
 *  never masquerade as a reviewer refusal. */
export type AssessmentSource =
  | "model_decision" // a reviewer actually returned this verdict
  | "program_floor" // unconditional native floor (isFloorRule)
  | "native_static" // ordinary static DENY the dynamic review completed —
  // the refusal is the native policy verdict, not a model outcome
  | "permission_ceiling" // permission.write / ceiling rules
  | "routing" // sandbox/host-direct routing constraints
  | "readonly" // read-only native judgment
  | "evidence_limited" // collectable evidence exhausted → named-limit deny
  | "protocol_error" // reviewer contract violation (fail-close)
  | "infrastructure_error" // reviewer transport/config failure
  | "replay" // cached report replayed on identical canonical inputs
  | "manual_authorization" // user-side /bypass lease (never produced here;
  // recorded for completeness when a lease arm is the admitting authority)

export type AssessmentDecision = "allow" | "deny"

export type CollectedEvidence = {
  /** What was collected: script body, directory listing, context slice. */
  kind: "script" | "directory" | "context"
  /** Path (or logical name) the evidence is about. */
  subject: string
  /** Bounded excerpt; never the raw file over caps. */
  excerpt: string
  /** True when the excerpt is truncated at a bound. */
  truncated: boolean
  /** Identity of the object actually read: resolved path + device/inode +
   *  size/mtime at read time. An admission path can re-stat the resolved
   *  path and compare — evidence collected for a different file (or version)
   *  can never stand in for what the reviewer saw. No hashing. */
  identity?: {
    resolvedPath: string
    dev: number
    ino: number
    size: number
    mtimeMs: number
  }
}

export interface AssessmentReport {
  /** Normalized command text this report judges (escalation headers stripped). */
  command: string
  /** Canonical execution cwd at assessment time. */
  cwd: string
  worktree: string
  shell: string
  /** Canonical input digest (see assessmentReportKey); replay requires the
   *  identical key — no fuzzy reuse. */
  key: string
  sessionID: string
  createdAt: number
  expiresAt: number
  decision: AssessmentDecision
  /** Primary categories the outcome is billed on — the complete, minimal set.
   *  Weak/secondary hints NEVER land here. */
  categories: string[]
  /** Lower-confidence families reported for diagnostics only. */
  secondaryCategories: string[]
  /** Owner-model view of `categories` (internal semantics). */
  owners: OwnerFinding[]
  source: AssessmentSource
  /** Deny reason verbatim from the model or the program stop. */
  reason?: string
  /** Named limitation when the deny came from exhausted/uncollectable
   *  evidence instead of a risk judgment. */
  limitation?: string
  /** Evidence collected for this report (bounded excerpts). */
  evidence: CollectedEvidence[]
  /** Evidence the reviewer asked for that could not be obtained. */
  missingEvidence: string[]
  /** "one_time" admits exactly the shell call that produced the report;
   *  "cached" reports may replay until expiresAt. */
  scope: "one_time" | "cached"
}

// ---------------------------------------------------------------------------
// Canonical report key — identical inputs mean the same report; ANY changed
// fact (command text, script fingerprint/mtime, cwd, permission scope,
// bypass set, endpoint/model, policy version) yields a different key, i.e.
// explicit invalidation by construction.
// ---------------------------------------------------------------------------

export type ReportKeyInputs = {
  /** Reports are session-partitioned: two sessions with identical
   *  command/cwd/perm/bypass NEVER share a cached judgment — an assessment
   *  is bound to the session that produced it, and `get` re-checks the
   *  session as defense-in-depth. */
  sessionID: string
  script: string
  cwd: string
  shell: string
  rules: readonly string[]
  fingerprints: readonly {
    path: string
    size: number
    mtimeMs: number
    sha256: string
    linkPath?: string
  }[]
  targetDirectories?: readonly unknown[]
  referencedPaths?: readonly string[]
  referencedPathsTruncated?: boolean
  strictness: string
  bypassCategories?: readonly string[]
  permission?: string
  endpoint: string
  model: string
  promptVersion: string
  /** Already-collected evidence feeds the identity too: same command with
   *  different script contents can never collide. */
  evidence?: readonly { subject: string; excerpt: string }[]
}

export function reportKeyPayload(inputs: ReportKeyInputs): Record<string, unknown> {
  return {
    sessionID: inputs.sessionID,
    script: inputs.script,
    cwd: inputs.cwd,
    shell: inputs.shell,
    rules: [...inputs.rules],
    fingerprints: inputs.fingerprints.map((f) => ({
      path: f.path,
      size: f.size,
      mtimeMs: f.mtimeMs,
      sha256: f.sha256,
      linkPath: f.linkPath ?? null,
    })),
    targetDirectories: inputs.targetDirectories ?? [],
    referencedPaths: inputs.referencedPaths ?? [],
    referencedPathsTruncated: inputs.referencedPathsTruncated ?? false,
    strictness: inputs.strictness,
    bypassCategories: inputs.bypassCategories ?? [],
    permission: inputs.permission,
    endpoint: inputs.endpoint,
    model: inputs.model,
    promptVersion: inputs.promptVersion,
    evidence: (inputs.evidence ?? []).map((e) => ({
      subject: e.subject,
      excerpt: e.excerpt,
    })),
  }
}

// ---------------------------------------------------------------------------
// AssessmentStore — session-scoped report cache with TTL + capacity bounds.
// ---------------------------------------------------------------------------

export const ASSESSMENT_ALLOW_TTL_MS = 15 * 60 * 1000
export const ASSESSMENT_DENY_TTL_MS = 90 * 1000
export const MAX_ASSESSMENT_REPORTS = 512

export class AssessmentStore {
  private readonly reports = new Map<string, AssessmentReport>()

  /** Look up a live report for a canonical key. Expired entries are evicted
   *  on access and never replayed. `sessionID` is re-checked even though the
   *  key already embeds it: no report ever serves a caller whose session did
   *  not produce it. */
  get(key: string, sessionID?: string): AssessmentReport | undefined {
    const report = this.reports.get(key)
    if (!report) return undefined
    if (report.expiresAt <= Date.now()) {
      this.reports.delete(key)
      return undefined
    }
    if (sessionID !== undefined && report.sessionID !== sessionID) return undefined
    return report
  }

  put(report: AssessmentReport): void {
    const now = Date.now()
    for (const [key, existing] of this.reports) {
      if (existing.expiresAt <= now) this.reports.delete(key)
    }
    while (this.reports.size >= MAX_ASSESSMENT_REPORTS) {
      const oldest = this.reports.keys().next().value
      if (typeof oldest !== "string") break
      this.reports.delete(oldest)
    }
    this.reports.set(report.key, report)
  }

  /** Explicit invalidation: dropping every report a session produced is the
   *  honest partner of key-based invalidation — a fact/perm/target change
   *  already yields a different key, but session teardown or a permission
   *  event may also want an eager drop. Never rewrites a report in place. */
  invalidateSession(sessionID: string): void {
    for (const [key, report] of this.reports) {
      if (report.sessionID === sessionID) this.reports.delete(key)
    }
  }

  get size(): number {
    return this.reports.size
  }
}

/** Build a report from a model verdict. `source` is the caller's choice —
 *  verdicts that came from a real reviewer response pass "model_decision";
 *  everything else names its program source. */
export function buildReport(input: {
  key: string
  sessionID: string
  command: string
  cwd: string
  worktree: string
  shell: string
  decision: AssessmentDecision
  categories: readonly string[]
  secondaryCategories?: readonly string[]
  source: AssessmentSource
  reason?: string
  limitation?: string
  evidence?: readonly CollectedEvidence[]
  missingEvidence?: readonly string[]
  scope?: "one_time" | "cached"
  now?: number
}): AssessmentReport {
  const now = input.now ?? Date.now()
  return {
    command: input.command,
    cwd: input.cwd,
    worktree: input.worktree,
    shell: input.shell,
    key: input.key,
    sessionID: input.sessionID,
    createdAt: now,
    expiresAt:
      now + (input.decision === "allow" ? ASSESSMENT_ALLOW_TTL_MS : ASSESSMENT_DENY_TTL_MS),
    decision: input.decision,
    categories: [...input.categories],
    secondaryCategories: [...(input.secondaryCategories ?? [])],
    owners: ownersForCategories(input.categories),
    source: input.source,
    reason: input.reason,
    limitation: input.limitation,
    evidence: [...(input.evidence ?? [])],
    missingEvidence: [...(input.missingEvidence ?? [])],
    scope: input.scope ?? "cached",
  }
}

/** Canonical category vocabulary guard for report construction (only the 7
 *  static risk names + layer names the external contract knows). */
export function isCanonicalRiskName(name: string): boolean {
  return (STATIC_BYPASS_CATEGORIES as readonly string[]).includes(name)
}

// Bypass-category escape hatches for the static classifier.
//
// A session's armed categories flow in as `bypassedCategories` on the classify
// input. Rules tagged with a category are skipped when that category is armed,
// EXCEPT for the unconditional floor: literal filesystem-root and
// system-critical-root destruction, disk-device destruction, fork bombs,
// kernel execution primitives, and reverse shells are always enforced
// regardless of any bypass.

import type { BypassCategory } from "../categories"

/** Rules that no bypass category may ever disable. */
const FLOOR_RULES = new Set([
  // Literal root and system-critical-root destruction (`rm -rf /`,
  // `rm -rf /etc`, brace-root deletes, root-glob deletes, `find / -delete`).
  "filesystem.root-delete",
  "filesystem.brace-root-delete",
  "filesystem.root-glob-delete",
  "filesystem.find-delete-root",
  // Whole-disk / device destruction.
  "filesystem.disk-destruction",
  // Process storms and kernel execution primitives.
  "execution.fork-bomb",
  "filesystem.kernel-trigger",
  "filesystem.kernel-core-pattern",
  // Remote-control primitives stay out of scope of every category (including
  // `web`, whose trust semantics cover HTTP destinations, not shells).
  "network.reverse-shell",
  "execution.literal-shell",
])

type RequiredCategories = readonly BypassCategory[]

const required = (...categories: BypassCategory[]): RequiredCategories => categories

/** Default rule → required bypass categories. Prefix keys cover every rule
 * whose id starts with them. Multiple categories are conjunctive: every one
 * must be armed. */
const RULE_PREFIXES: ReadonlyArray<readonly [string, RequiredCategories]> = [
  ["filesystem.", required("filesystem")],
  ["data.", required("filesystem")],
  ["git.irrecoverable-change", required("filesystem")],
  ["cleanup.", required("filesystem")],

  // `host` covers running-system state: processes, services, power,
  // persistence, and anti-forensics.
  ["system.", required("host")],
  ["process.", required("host")],
  ["persistence.", required("host")],
  ["forensic.", required("host")],

  // `privilege` covers crossing a permission/isolation boundary: ownership
  // and mode bits, kernel parameters, namespace escapes, kernel modules.
  ["permissions.", required("privilege")],
  ["kernel.", required("privilege")],
  ["namespace.", required("privilege")],
  ["execution.kernel-module-load", required("privilege")],

  ["git.remote-history-rewrite", required("remote")],
  ["infrastructure.", required("remote")],
  ["database.", required("remote")],

  ["credentials.", required("secret")],
  ["exfiltration.", required("secret", "network")],
  ["network.", required("network")],

  ["execution.unparseable-path", required("indirection")],
  ["execution.local-script", required("indirection")],
  ["execution.wrapper", required("indirection")],
  ["execution.encoded-shell", required("indirection")],
  ["execution.ambiguous-heredoc", required("indirection")],
]

/** Exact overrides for rules the prefix table cannot express precisely.
 * `undefined` marks a rule that is deliberately NOT bypassable.
 *
 * Owner semantics (policyVersion 1.5): a rule bills the categories that own
 * the PRIMITIVE's risk — never the mechanical side-effects of the object it
 * acts on. Credential/key-material rules own `secret` alone: deleting,
 * overwriting, weakening the protection of, or staging a copy of a
 * credential object is a secret judgment; the generic filesystem/privilege
 * repeat on the same object is not billed (an independent filesystem or
 * privilege segment in the same command still bills its own category).
 * Download-and-execute and destructive remote APIs own `remote`: the
 * network fetch is the remote execution's intrinsic channel, not a second
 * kind. Genuinely independent exfiltration keeps {secret, network}. */
const RULE_EXACT: ReadonlyArray<readonly [string, RequiredCategories | undefined]> = [
  // Credential objects: the data rule owns the secret judgment on read,
  // delete, and overwrite alike — the object's own filesystem mechanics are
  // not a second owner.
  ["data.critical-delete", required("secret")],
  ["data.critical-read", required("secret")],
  ["data.critical-write", required("secret")],
  // Staging a credential into a compressed or backup copy is a secret
  // judgment: the destination's ordinary filesystem effect stays its own
  // rule/category when it is a genuinely independent object.
  ["filesystem.compression-sensitive", required("secret")],
  ["filesystem.critical-backup", required("secret")],
  // Weakening a credential's own protection is a secret judgment, not a
  // privilege crossing.
  ["permissions.sensitive-mode", required("secret")],
  // Privilege/isolation-boundary crossings that would otherwise inherit the
  // broader remote/host families.
  ["infrastructure.privileged-container", required("privilege")],
  // Overwriting or deleting sensitive system files is a filesystem effect,
  // not a running-state one.
  ["system.file-override", required("filesystem")],
  ["system.sensitive-write", required("filesystem")],
  // Destructive SQL runs against a local database file: filesystem family,
  // not shared remote state.
  ["database.destructive-statement", required("filesystem")],
  // Nested-interpreter escapes are indirection, not an unconditional floor.
  ["execution.db-shell-escape", required("indirection")],
  ["execution.interop", required("indirection")],
  // Unscoped archive extraction is a filesystem-write question.
  ["operation.archive-extract", required("filesystem")],
  // Snapshot/recovery-data destruction is data destruction: filesystem family
  // (vssadmin delete shadows, zfs destroy tank/backup).
  ["filesystem.backup-destruction", required("filesystem")],
  // Filesystem-flavored execution rules.
  ["execution.script-one-liner-destructive", required("filesystem")],
  ["execution.xargs-destructive", required("filesystem")],
  // Web-flavored execution rule (download-and-execute).
  // Fetch-and-execute / destructive remote APIs own `remote`: the network
  // hop is the remote operation's intrinsic channel, not a second kind.
  ["execution.remote-pipe", required("remote")],
  ["network.destructive-api", required("remote")],
  // HARD-mode policy rules follow the filesystem category they enforce.
  ["hard.forced-recursive-delete", required("filesystem")],
  ["hard.temp-target-delete", required("filesystem")],
  ["hard.named-temp-delete", required("filesystem")],
  ["hard.backup-delete", required("filesystem")],
  ["hard.backup-target-delete", required("filesystem")],
  ["hard.local-temp-delete", required("filesystem")],
  // Recycle-bin permanent deletion is filesystem-destroying behavior and is
  // explicitly covered by the filesystem bypass (user spec: stop all
  // filesystem checks); classifier.ts gates it with the same category.
  ["filesystem.recycle-bin-permanent-delete", required("filesystem")],
  // Virtual ids used only by direct trigger gates in classifier.ts. The
  // emitted rule remains operation.context-required for compatibility.
  ["operation.context-required.network", required("network")],
  ["operation.context-required.process", required("host")],
  ["operation.context-required.privilege", required("privilege")],
  ["operation.context-required.overwrite", required("filesystem")],
  // Empty/opaque input is never bypassable (classifier.ts checks it before
  // consulting bypassedCategories).
  ["input.empty", undefined],
  ["input.opaque", undefined],
]

const EXACT_MAP = new Map<string, RequiredCategories | undefined>(RULE_EXACT)

/** True when `rule` is one of the unconditional floor rules no bypass category
 * (and no escalation) can ever clear. Use this instead of a bare
 * `ruleRequiredCategories(rule) === undefined` check: that returns undefined
 * for BOTH the floor and for ordinary rules that simply have no mapping, so
 * treating it as "floor" is unsafe. */
export function isFloorRule(rule: string): boolean {
  return FLOOR_RULES.has(rule)
}

/** Rule ids that no escalation or bypass may ever clear: the unconditional
 * floor plus verdicts emitted directly by the permission ceiling and input
 * guards. Provided for parent-side prechecks. */
export const TERMINAL_UNBYPASSABLE: ReadonlySet<string> = new Set([
  ...FLOOR_RULES,
  "permission.write",
  "input.empty",
  "input.opaque",
])

/** Returns every category required to bypass a rule, or undefined when the
 * rule is an unconditional floor or has no bypass mapping. */
export function ruleRequiredCategories(rule: string): RequiredCategories | undefined {
  if (FLOOR_RULES.has(rule)) return undefined
  if (EXACT_MAP.has(rule)) return EXACT_MAP.get(rule)
  for (const [prefix, categories] of RULE_PREFIXES) {
    if (rule.startsWith(prefix)) return categories
  }
  return undefined
}

/** Backwards-compatible helper for consumers that only understand a single
 * category. Conjunctive rules deliberately return undefined. */
export function ruleBypassCategory(rule: string): BypassCategory | undefined {
  const categories = ruleRequiredCategories(rule)
  return categories?.length === 1 ? categories[0] : undefined
}

/** Union of the bypass categories the given rules require. Floor rules and
 * rules with no bypass mapping contribute nothing — arming categories cannot
 * clear them, so they should never appear in an escalation hint. Conjunctive
 * rules contribute every required category (the union is still correct: the
 * escalation reviewer sees the full risk family). */
export function rulesHintCategories(rules: readonly string[]): BypassCategory[] {
  const out = new Set<BypassCategory>()
  for (const rule of rules) {
    for (const category of ruleRequiredCategories(rule) ?? []) out.add(category)
  }
  return [...out]
}

/** True when the rule is disabled by one of the armed bypass categories. */
export function ruleBypassed(rule: string, bypassed: ReadonlySet<BypassCategory> | undefined): boolean {
  if (!bypassed || bypassed.size === 0) return false
  const categories = ruleRequiredCategories(rule)
  return categories !== undefined && categories.every((category) => bypassed.has(category))
}

// opencode-v2-security — execution-boundary security for OpenCode V2.
//
// v1 was a function plugin (`{ id, server }`) that registered `config` /
// `shell.env` / `tool.execute.before` / `tool.execute.after` / `event` hooks, a
// custom `bash_classifier_confirm` tool backed by `context.ask`, and used
// `pluginContext.directory/worktree`. v2 has none of those — the plugin is an
// effect plugin `{ id, effect(ctx) }` whose `effect` returns an `Effect.Effect`
// (see packages/plugin/src/effect/plugin.ts). This file is the port. Every
// mapping below was verified against ~/src/opencode2 (branch v2):
//
//   1. Entry shape          v1 function plugin        -> { id, effect(ctx) } (Effect)
//   2. Static+LLM review    v1 "tool.execute.before"  -> ctx.tool.hook("execute.before")
//        tool names         "bash" -> "shell" ("bash" still accepted); "apply_patch" -> "patch"
//        args mutation      output.args.timeout/command -> ev.input.timeout/command
//   3. Failure recording    v1 "tool.execute.after"   -> ctx.tool.hook("execute.after")
//        exit info          output.metadata.exit/exitCode -> ev.result.metadata.exit/exitCode
//        (verified: v2 shell result metadata = { truncated, exit?, shellID?, timeout? })
//   4. Supervisor injection v1 config hook + "shell.env" -> ctx.shell.hook("create.before")
//        (ev.env.OPENCODE_REAL_BASH = ev.shell; ev.shell = supervisorPath; Windows only)
//   5. fail_ask             v1 confirm tool + context.ask -> REMOVED; normalized to fail_close
//        (Tool.Context has no `ask`; a denial is thrown as a Tool.Error-shaped error)
//   6. HARD session abort   v1 client.session.abort   -> ctx.session.interrupt({ sessionID })
//   7. Session cleanup      v1 event hook             -> ctx.event.subscribe() consumer loop
//        (session.deleted wire event: { type, data: { sessionID } }, verified in
//         packages/schema/src/session-event.ts)
//   8. Config source        v1 factory rawOptions     -> ctx.options (+ options.configFile)
//   9. Build                compiled dist             -> plain .ts (no build step)
//
// Rejection semantics (verified in packages/core/src/tool.ts + session/runner/llm.ts):
// `execute.before` is the only fallible tool hook (failure channel `Tool.Error`;
// `execute.after` is `never`). In the effect form the host runs each hook
// callback's returned `Effect`; a `Tool.Error`-tagged failure from
// `execute.before` is caught by the runner's `catchTag("Tool.Error")` and turned
// into THIS tool call's error (the model reads the message). Every block
// therefore surfaces as an `Effect` that fails with a `Tool.Error`-shaped value
// (a plain `Error` carrying `_tag: "Tool.Error"`), produced by `rejectionError`
// and routed through `Effect.tryPromise`'s `catch`. `catchTag` discriminates by
// `_tag`, so the fake object matches without being a real `Tool.Error` instance;
// `toSessionError` then falls through to its `{ type: "unknown", message }` branch
// (message preserved) — acceptable, since the block message is what matters.

import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import { access, appendFile, mkdir, readFile, realpath } from "node:fs/promises"
import { homedir, release as osRelease } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect, Schedule, Stream } from "effect"
import type { Plugin } from "@opencode-ai/plugin/effect/plugin"
import type { Scope } from "effect"
import { resolveClassifierShell } from "./shell-dialect"
import { BypassRpc } from "./bypass-rpc"
import {
  PERM_FULL,
  parsePerm,
  permIntersect,
  permLabel,
  permSubset,
  fallbackPermBit,
  requiredPermBit,
  tightenPerm,
  type Perm,
} from "./permissions"
import {
  BYPASS_CATEGORIES,
  STATIC_BYPASS_CATEGORIES,
  expandBypassCategoryToken,
  resolvePluginConfig,
  type BashClassifierOptions,
  type BypassCategory,
} from "./config"
import {
  classifyShellCommand,
  isolateDetachedStartCommand,
  verifyScriptFingerprints,
  type StaticSecurityDecision,
} from "./security/classifier"
import {
  reviewCommandWithAuditor,
  normalizeReviewRequest,
  requestForPolicy,
  ReviewError,
  type CloudReviewRequest,
  type CloudReviewResult,
  type PreviousFailedCommand,
  type PreviousRejectedCommand,
  type ReviewCommandOptions,
} from "./security/reviewer"
import { analyzeSlowCommand } from "./security/slow-command"
import { detectInjection } from "./security/injection-detector"
import { isFloorRule } from "./security/bypass"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_MARKER,
  JUSTIFICATION_HEADER_PREFIX,
  parseEscalation,
  type EscalationRequest,
} from "./security/escalation"
import {
  escalationContextFromMessages,
  findSimilarFailedEscalation,
  type FailedEscalationRecord,
} from "./security/escalation-state"
import {
  reviewEscalation,
  EscalationReviewError,
  DEFAULT_ESCALATION_REVIEW_TIMEOUT_MS,
  type EscalationReviewRequest,
} from "./security/escalation-reviewer"
import {
  applySandboxCreateBefore,
  commandNeedsOsPrivilege,
  createSandboxMarkers,
  extractSandboxMarker,
  insertSandboxMarker,
  profileForPerm,
  probeLinuxSandbox,
  assertSandboxAvailable,
  stripSandboxMarker,
  type SandboxProbeResult,
  type SandboxProfile,
} from "./sandbox"

// Package root, derived from this module's own URL so relative paths (native
// supervisor, auditor) resolve no matter where the plugin is installed from.
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const DYNAMIC_ALLOW_CACHE_TTL_MS = 15 * 60 * 1000
const DYNAMIC_DENY_CACHE_TTL_MS = 90 * 1000
const MAX_DYNAMIC_ALLOW_CACHE_ENTRIES = 512
const PROMPT_VERSION = "v6"
const SESSION_STATE_TTL_MS = 30 * 60 * 1000
const MAX_SESSION_STATES = 512
const MAX_OUTPUT_TAIL_CHARS = 2000

const BLOCK_SUFFIX =
  "Skip the step (if unnecessary) or ask for escalation instead of trying alternative methods to bypass the check."

// The escalation-disabled ending: identical guidance minus the escalation
// pointer — the blocked call ends the same way a terminal refusal does,
// without ever referencing the header protocol.
const BLOCK_SUFFIX_NO_ESCALATION =
  "Skip the step (if unnecessary) or ask the user to authorize it with /bypass or /perm instead of trying alternative methods to bypass the check."

// Terminal ending for denials that cannot be resolved by submitting another
// escalation request (pending/history saturated/similar denied/unavailable/
// context failure/session ended/reviewer ask_user|deny/infra error). Unlike
// BLOCK_SUFFIX it never says "ask for escalation": the only remaining routes
// are skipping the step or user-side authorization via /bypass or /perm.
const TERMINAL_NO_BYPASS =
  "do not try to reach the same effect through other commands, wrappers, or scripts."

// permission.write denials are a hard refuse from the permission ceiling —
// an independent layer that comment-based escalation can never relax. They
// carry neither BLOCK_SUFFIX (which points at escalation) nor the full guide.
const PERM_WRITE_SUFFIX =
  "This is the session permission ceiling, an independent check that escalation cannot override. " +
  "Ask the user to grant write access with /perm +w or /perm rw, or skip the step."
const PERM_WRITE_SUFFIX_NO_ESCALATION =
  "This is the session permission ceiling, an independent check that cannot be overridden per call. " +
  "Ask the user to grant write access with /perm +w or /perm rw, or skip the step."

/** Rules that make an escalation request terminally unrunnable regardless of
 * any reviewer verdict, beyond the unconditional floor (isFloorRule): the
 * permission ceiling and the two unreviewable input states. `input.opaque`
 * arrives with an ASK verdict — the command is exactly what cannot be
 * reviewed locally — so these are checked on the rules, not the verdict. */
const TERMINAL_ESCALATION_RULES = new Set(["permission.write", "input.empty", "input.opaque"])

function terminalAuthorize(categories: readonly string[], options: { skip?: boolean } = {}): string {
  const bypass =
    categories.length > 0
      ? ` with /bypass ${categories.join(" ")}`
      : " with /bypass or /perm"
  const lead = options.skip === false ? " ask the user" : " Skip this step if it is not required, or ask the user"
  return `${lead} to authorize it themselves${bypass}; ${TERMINAL_NO_BYPASS}`
}

// Categories a `# - REQUIRE_ESCALATION` request may ask the reviewer to
// grant (fix F1): `dynamic` and `slow` are deliberately absent — a grant
// that disables the review layer itself (or the slow-command layer) is not
// something the reviewer may ever authorize. `sandbox` stays grantable.
const ESCALATION_GRANTABLE_CATEGORIES = BYPASS_CATEGORIES.filter(
  (category) => category !== "dynamic" && category !== "slow",
)

const ESCALATION_GUIDANCE =
  ` To escalate for one execution, resubmit the command once with this exact prefix:\n` +
  `${ESCALATION_MARKER}\n` +
  `${CATEGORY_HEADER_PREFIX} <category>[,<category>...]\n` +
  `${JUSTIFICATION_HEADER_PREFIX} <one-line reason>\n` +
  `<real command starting on line 4>\n` +
  `A single call is reviewed by an independent reviewer: allow_once runs the command once ` +
  `(no session state is armed); ask_user or deny records the outcome, and a similar command ` +
  `cannot be escalated again in this session — the user must authorize it with /bypass instead.\n` +
  `Categories: filesystem (local file changes), host (processes, services, and running-system state), ` +
  `privilege (crossing permission or isolation boundaries: sudo/doas/su/pkexec/sudoedit, ownership and capability changes, ` +
  `kernel parameters, namespaces, privileged containers — a call that needs privilege runs without the OS ` +
  `sandbox for that call, or is refused loudly when the sandbox cannot be removed), ` +
  `secret (credentials and sensitive files), network (network access and transfers), ` +
  `remote (remote code and remote-state changes), indirection (scripts, wrappers, encoded or ` +
  `dynamic execution), sandbox (skip the OS sandbox for this call). ` +
  `Only these categories are grantable. Request only the categories the command actually needs.`

type SessionState = {
  version: number
  touchedAt: number
  lastRejected?: { value: PreviousRejectedCommand; generation: number }
  lastFailed?: { value: PreviousFailedCommand; generation: number; consumedBy?: string }
}

// --- v2 hook event shapes ---------------------------------------------------
// Local mirrors of the promise shapes in @opencode-ai/plugin/promise/*. The
// plugin must not import host packages at runtime (V2-PLUGIN-API.md §8.7), so
// these stay as plain structural types.

type ExecuteBeforeEvent = {
  readonly tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  input: unknown
}

// v2's shell `result.output` is a structured object ({ output, cursor, size,
// truncated }), not a bare string — fields are optional/loose so the after-hook
// can extract text defensively (see runAfter) and so this type stays a supertype
// of ExecuteBeforeEvent (after = before + optional fields).
type ExecuteAfterEvent = ExecuteBeforeEvent & {
  readonly status?: "completed" | "error"
  readonly result?: {
    readonly output?: unknown
    readonly content?: unknown
    readonly metadata?: Record<string, unknown>
  }
  readonly error?: unknown
}

// ctx.shell.hook("create.before"): all fields mutable, fired before spawn.
type ShellCreateBeforeEvent = {
  command: string
  cwd: string
  timeout: number
  shell: string
  env: Record<string, string | undefined>
}

// --- blocking helpers -------------------------------------------------------

// A Tool.Error-shaped failure (see the header note on rejection semantics).
function rejectionError(message: string): Error & { readonly _tag: "Tool.Error" } {
  return Object.assign(new Error(message), { _tag: "Tool.Error", _op: "TaggedError" })
}

// `Effect.tryPromise`'s `catch` must always return the same shape. The
// execute.before body already throws `rejectionError` for every block, so a
// thrown Tool.Error-shaped error is passed through unchanged; any other thrown
// value (an unexpected non-block exception) is normalized into one so the host's
// `catchTag("Tool.Error")` still routes it to a tool-call error instead of a
// step-killing defect.
function toRejection(error: unknown): Error & { readonly _tag: "Tool.Error" } {
  if (error instanceof Error && (error as { _tag?: string })._tag === "Tool.Error") {
    return error as Error & { readonly _tag: "Tool.Error" }
  }
  return rejectionError(error instanceof Error ? error.message : String(error))
}

// Agent-facing reason for a failed dynamic review: configuration defects are
// folded to a generic phrase (internal field names mean nothing to the model;
// the verbatim message is already in the reviewer trace). Runtime errors —
// timeouts, exits, protocol violations — pass through unchanged.
function agentFacingReviewReason(reason: string): string {
  if (/\b(?:dynamicReview|apiKeyEnv|api key)\b|is not configured/i.test(reason)) {
    return "dynamic review unavailable or invalid review configuration"
  }
  return reason
}

function conciseReason(reason: string, limit = 160) {
  const value = reason
    .replace(/\b(?:HARD|LOOSE)\b/gi, "policy")
    .replace(/\bdynamicReview(?:\.[A-Za-z][A-Za-z0-9]*)?\b/g, "review setting")
    .replace(/\b(?:strictness|failPolicy|reviewCommand|allowFullReadAccess|maxRounds)\b/g, "review setting")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[.!?]+$/, "")
  return (value || "Blocked by policy").slice(0, limit)
}

// `guidance` is the escalation-usage text appended after BLOCK_SUFFIX. The
// plugin passes a per-session, per-context-cycle claim so the full format is
// shown only on the first classifier block of a cycle (see
// claimEscalationGuidance); the default keeps standalone callers on the full
// text.
function blockMessage(
  type: "static" | "dynamic" | "policy",
  reason: string,
  strict: boolean,
  rules: string[] = [],
  command = "",
  guidance: string = ESCALATION_GUIDANCE,
  escalationEnabled = true,
) {
  // A static permission.write deny comes from the permission ceiling, not a
  // bypassable classifier rule: it must not point at escalation nor consume
  // the per-cycle guide slot (the caller's claim helper skips it too).
  if (type === "static" && rules.includes("permission.write")) {
    const suffix = escalationEnabled ? PERM_WRITE_SUFFIX : PERM_WRITE_SUFFIX_NO_ESCALATION
    return rejectionError(`Blocked by static classifier: ${conciseReason(reason, 120)}. ${suffix}`)
  }
  const suffix = escalationEnabled ? BLOCK_SUFFIX : BLOCK_SUFFIX_NO_ESCALATION
  return rejectionError(
    `Blocked by ${type} classifier: ${conciseReason(reason, type === "dynamic" ? 80 : 120)}. ${suffix}${guidance}`,
  )
}

function softSlowMessage(reason: string) {
  // Soft interception for high-cost but optimizable commands: no BLOCK_SUFFIX, no DO NOT retry
  return rejectionError(conciseReason(reason, 300))
}

// failPolicy "fail_ask" normalized to "fail_close" (v2 cannot ask the user, so
// a reviewer outage is always a denial). `normalizedFromAsk` adds an explicit
// note to the message explaining that interactive confirmation is unavailable.
function failClosedBlock(
  reason: string,
  normalizedFromAsk: boolean,
  strict: boolean,
  rules: string[] = [],
  command = "",
  guidance: string = ESCALATION_GUIDANCE,
  escalationEnabled = true,
) {
  const note = normalizedFromAsk
    ? " Interactive user confirmation is unavailable in this environment, so the command is denied instead of asked."
    : ""
  const suffix = escalationEnabled ? BLOCK_SUFFIX : BLOCK_SUFFIX_NO_ESCALATION
  return rejectionError(
    `Blocked by policy classifier: ${conciseReason(reason, 120)}.${note} ${suffix}${guidance}`,
  )
}

function applyPatchDeleteBlock() {
  return rejectionError(
    "patch cannot delete files. Use a shell command so the classifier and OpenCode permission layer can review the deletion.",
  )
}

// --- small helpers (ported unchanged) ---------------------------------------

async function canonicalOrResolved(value: string) {
  const resolved = path.resolve(value)
  try {
    return await realpath(resolved)
  } catch {
    return resolved
  }
}

function commandFromArgs(args: unknown) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return
  const command = (args as Record<string, unknown>).command
  return typeof command === "string" ? command : undefined
}

function workdirFromArgs(args: unknown) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return
  const workdir = (args as Record<string, unknown>).workdir
  return typeof workdir === "string" ? workdir : undefined
}

function sanitizeOutputTail(output: string) {
  const trimmed = (output ?? "").replace(/\0/g, "").trim()
  if (!trimmed) return ""
  return trimmed.slice(-MAX_OUTPUT_TAIL_CHARS).replace(/\s+/g, " ").trim()
}

/**
 * §4.10 (F36/F37): normalizes the variable identifiers of known read-only
 * parametrized commands so repeated inspections share a dynamic-ALLOW cache
 * entry. Only patterns whose parameters do NOT change security semantics are
 * rewritten; the dynamic reviewer always sees the RAW script.
 *
 * `kill <pid>` is deliberately NOT normalized: a cached ALLOW for an ordinary
 * PID could otherwise be reused for a critical system PID without review.
 * `sed -e '…'` (semantics-changing) is not normalized either.
 *
 * SQL payloads collapse to `<query>` only for provably read-only leading
 * verbs (select/show/describe/explain/vacuum/analyze) whose payload carries
 * no write keyword and no known side-effecting function. `begin`/`prepare`/
 * `values`/`with` are no longer collapsed: they wrap data-modifying
 * statements that would otherwise inherit a benign query's cached ALLOW.
 */
const SQL_WRITE_HINT =
  /\b(?:insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|call|do|set|reset|listen|notify|import|refresh|reindex|cluster|lock|comment|security\s+label)\b/i
const SQL_SIDE_EFFECT_FUNCTIONS =
  /\b(?:pg_terminate_backend|pg_reload_conf|pg_rotate_logfile|pg_create_restore_point|pg_logical_emit_message|lo_import|lo_export|lo_unlink|dblink|dblink_exec|setval|nextval|read_file|read_binary_file|pg_ls_dir|pg_sleep)\b/i

export function normalizeCacheKeyScript(script: string): string {
  const text = script
    // bare reads only: `docker logs/inspect/top/stats [flags] <container>`
    // (bounded read-only flag whitelist; -f streams and is slow-blocked upstream)
    .replace(
      /^docker\s+(logs|inspect|top|stats)(?:\s+(?:--tail|-n|--since|-q)\s+\S+|\s+-f)*\s+([A-Za-z0-9_.][A-Za-z0-9_.-]*)$/gi,
      "docker $1 <id>",
    )
    // `kubectl logs/top [-f] [-c container] <pod>`
    .replace(/^kubectl\s+(logs|top)(?:\s+-f)?(?:\s+-c\s+\S+)?\s+([A-Za-z0-9_./-]+)$/gi, "kubectl $1 <id>")
    // `kubectl get|describe <type> <name>` (secrets excluded: different security class)
    .replace(
      /^kubectl\s+(get|describe)\s+(?!(?:secret|secrets)\b)([A-Za-z0-9_.-]+)\s+([A-Za-z0-9_.-]+)$/gi,
      "kubectl $1 $2 <id>",
    )
    // psql … -c "SELECT…" / -c 'SELECT…' (read-only SQL payload)
    .replace(
      /(^|[\s;])(-c|--command)\s+(["'])((?:select|show|describe|explain|vacuum|analyze)[\s\S]*?)\3/gi,
      (match, lead: string, flag: string, quote: string, payload: string) =>
        SQL_WRITE_HINT.test(payload) || SQL_SIDE_EFFECT_FUNCTIONS.test(payload)
          ? match
          : `${lead}${flag} ${quote}<query>${quote}`,
    )
  return text
}

/**
 * Cache keys are GLOBAL (no session component): the payload already carries
 * every security-relevant context (script, cwd, shell, static rules, script
 * fingerprints, target-directory listings, referenced paths, strictness,
 * endpoint, model, prompt version, bypass categories), and cached entries are
 * only written for non-forced LOOSE reviews, so a verdict from another session
 * for the exact same context is sound to reuse. A shorter TTL bounds staleness.
 */
export function dynamicAllowCacheKey(
  script: string,
  cwd: string,
  shell: string,
  decision: StaticSecurityDecision,
  endpoint: string,
  model: string,
  strictness: string,
  bypassedCategories?: string[],
  permScope?: Perm,
) {
  const context = decision.reviewContext
  if (
    context?.uninspectedLocalScripts?.length ||
    context?.uninspectedTargetDirectories?.length ||
    context?.targetDirectories?.some((directory) => directory.truncated)
  ) {
    return undefined
  }

  const payload = {
    script: normalizeCacheKeyScript(script),
    cwd,
    shell,
    rules: decision.rules,
    fingerprints: decision.fingerprints.map((fingerprint) => ({
      path: fingerprint.path,
      size: fingerprint.size,
      mtimeMs: fingerprint.mtimeMs,
      sha256: fingerprint.sha256,
      linkPath: fingerprint.linkPath ?? null,
    })),
    targetDirectories: context?.targetDirectories ?? [],
    referencedPaths: context?.referencedPaths ?? [],
    referencedPathsTruncated: context?.referencedPathsTruncated ?? false,
    strictness,
    bypassCategories: bypassedCategories ?? [],
    // A reviewer ALLOW earned under a write-capable session must not replay
    // after the session is tightened to read-only.
    permission: permScope ? permLabel(permScope) : undefined,
    endpoint,
    model,
    promptVersion: PROMPT_VERSION,
  }
  const digest = createHash("sha256").update(JSON.stringify(payload)).digest("hex")
  return digest
}

function hasCachedDynamicAllow(cache: Map<string, number>, key: string, now: number) {
  const expiresAt = cache.get(key)
  if (expiresAt === undefined) return false
  if (expiresAt <= now) {
    cache.delete(key)
    return false
  }
  return true
}

function cacheDynamicAllow(cache: Map<string, number>, key: string, now: number) {
  for (const [cachedKey, expiresAt] of cache) {
    if (expiresAt <= now) cache.delete(cachedKey)
  }
  while (cache.size >= MAX_DYNAMIC_ALLOW_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value
    if (typeof oldest !== "string") break
    cache.delete(oldest)
  }
  cache.set(key, now + DYNAMIC_ALLOW_CACHE_TTL_MS)
}

// Short-lived negative cache: a stubborn model retrying an identical denied
// command re-burns a review call every attempt. Replaying the same DENY for
// 90s throttles that without meaningfully delaying legitimate state changes.
type DenyCacheEntry = { expiresAt: number; reason: string }

function cachedDynamicDenyReason(cache: Map<string, DenyCacheEntry>, key: string, now: number): string | undefined {
  const entry = cache.get(key)
  if (!entry) return undefined
  if (entry.expiresAt <= now) {
    cache.delete(key)
    return undefined
  }
  return entry.reason
}

function cacheDynamicDeny(cache: Map<string, DenyCacheEntry>, key: string, reason: string, now: number) {
  for (const [cachedKey, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(cachedKey)
  }
  while (cache.size >= MAX_DYNAMIC_ALLOW_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value
    if (typeof oldest !== "string") break
    cache.delete(oldest)
  }
  cache.set(key, { expiresAt: now + DYNAMIC_DENY_CACHE_TTL_MS, reason })
}

function isValidReviewResult(value: unknown, strict: boolean): value is CloudReviewResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  const expected = strict ? ["bypassing", "decision", "reason"] : ["decision", "reason"]
  const keys = Object.keys(record).sort()
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return false
  if (record.decision !== "ALLOW" && record.decision !== "DENY") return false
  if (typeof record.reason !== "string") return false
  return !strict || typeof record.bypassing === "boolean"
}

// --- effect plugin context (local structural mirror) -----------------------
// The plugin must not import host packages at runtime (V2-PLUGIN-API.md §8.7),
// so the effect Context is mirrored as a plain structural interface — the same
// approach the promise port used for the hook event shapes. `ctx.session.*`
// return Effects here; they are run against the host-provided runtime captured
// inside `effect` (see `run`), not a bare `Effect.runPromise`, so the host
// services backing them stay available.
interface EffectPluginContext {
  readonly options: unknown
  readonly tool: {
    readonly hook: (
      name: "execute.before" | "execute.after",
      callback: (event: ExecuteBeforeEvent) => Effect.Effect<void, unknown>,
    ) => Effect.Effect<unknown, never, Scope.Scope>
    /** Tool registry transform (packages/plugin/src/effect/tool.ts ToolEditor). */
    readonly transform?: (
      callback: (draft: ToolEditorMirror) => void,
    ) => Effect.Effect<unknown, never, Scope.Scope>
  }
  readonly shell: {
    readonly hook: (
      name: "create.before",
      callback: (event: ShellCreateBeforeEvent) => Effect.Effect<void, never>,
    ) => Effect.Effect<unknown, never, Scope.Scope>
  }
  readonly command: {
    readonly transform: (callback: (draft: CommandDraft) => void) => Effect.Effect<unknown, never, Scope.Scope>
  }
  /** Permission evaluation hook (packages/plugin/src/effect/permission.ts).
   * `effect`/`message` on the event are mutable; hooks may only tighten the
   * computed effect here. Optional so older hosts still load the plugin. */
  readonly permission?: {
    readonly hook: (
      name: "evaluate",
      callback: (event: PermissionEvalEvent) => Effect.Effect<void, unknown>,
    ) => Effect.Effect<unknown, never, Scope.Scope>
  }
  readonly session: {
    readonly get: (input: { sessionID: string }) => Effect.Effect<unknown, unknown>
    readonly interrupt: (input: { sessionID: string; continue?: boolean }) => Effect.Effect<unknown, unknown>
    /** Durable session transcript (`{ data: SessionMessage.Info[] }`, everything
     *  since the last compaction). Used to extract the reviewer-facing user
     *  context for escalation requests. Optional so older hosts still load the
     *  plugin — escalation then fails closed instead of allowing blind. */
    readonly context?: (input: { sessionID: string }) => Effect.Effect<unknown, unknown>
    readonly synthetic: (input: {
      sessionID: string
      text: string
      /** Shown as the transcript row; without it the TUI hides the message. */
      description?: string
      metadata?: Record<string, unknown>
      resume?: boolean
      /** "steer" = appended at the history tail for the next turn without
       * waking the session. Matches the host's current default; kept explicit
       * so a host default change cannot silently alter notification semantics. */
      delivery?: "steer" | "queue"
    }) => Effect.Effect<unknown, unknown>
  }
  // Event-only RPC used to push bypass state changes to the TUI companion.
  // See src/bypass-rpc.ts for why a session message cannot carry this.
  // Optional so the plugin still loads on hosts that predate the RPC domain;
  // user toasts are then simply unavailable.
  readonly rpc?: {
    readonly register: (
      definition: unknown,
      handlers: Record<string, unknown>,
    ) => Effect.Effect<
      { readonly events: { readonly emit: (...args: unknown[]) => Effect.Effect<void, unknown> } },
      unknown,
      Scope.Scope
    >
  }
  readonly event: { readonly subscribe: () => Stream.Stream<unknown> }
}

// v2 ctx.command.transform draft (packages/plugin/src/effect/command.ts).
type CommandDraft = {
  add(definition: {
    name: string
    description?: string
    execute: (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
  }): void
}

// v2 ctx.tool.transform draft (packages/plugin/src/effect/tool.ts ToolEditor).
// The plugin must not import host packages at runtime, so the editor is
// mirrored structurally: `add` takes a Tool.Info-shaped record whose `execute`
// returns an Effect, `update` mutates an existing tool in place.
type ToolInfoMirror = {
  name?: string
  description?: string
  input?: unknown
  options?: Record<string, unknown>
  execute?: (input: unknown, context: { sessionID: string }) => Effect.Effect<unknown, unknown>
}
type ToolEditorMirror = {
  add(tool: ToolInfoMirror): void
  update(id: string, update: (tool: ToolInfoMirror) => void): void
  get?(id: string): ToolInfoMirror | undefined
  list?(): ToolInfoMirror[]
}

// v2 ctx.permission.hook("evaluate") event (packages/plugin/src/effect/permission.ts).
type PermissionEvalEvent = {
  readonly sessionID: string
  readonly agent?: string
  readonly action: string
  readonly resources: readonly string[]
  effect: "allow" | "deny" | "ask"
  message?: string
}

// Async preamble (config discovery + fail_ask normalization + supervisor probe)
// extracted so the effect body can bridge it with one `Effect.promise`. A setup
// failure dies the plugin load (acceptable: a misconfigured plugin should not
// silently run with defaults).
//
// config.json (package root) is a BASE layer: when it exists it is always read
// and every field it defines is overridden by the corresponding explicit
// `options` field, so live installs that pass options can still own permanent
// settings (like BypassClassifier) in config.json.
async function resolveStartup(rawOptions: unknown) {
  const options = (rawOptions ?? {}) as Record<string, unknown>
  // Base layer: package-root config.json is ALWAYS read when present, so
  // permanent settings (BypassClassifier, reviewer credentials) live there even
  // when the host passes explicit options or a configFile directive.
  let source: Record<string, unknown> = {}
  try {
    source = JSON.parse(await readFile(path.join(PACKAGE_ROOT, "config.json"), "utf8")) as Record<string, unknown>
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code
    if (code !== "ENOENT") {
      // A malformed config must be loud: silently ignoring it would leave the
      // user believing safety settings (reviewer, fail-close) are active.
      console.warn(
        `[opencode-v2-security] fallback config.json could not be read (${code ?? "invalid JSON"}); defaults apply`,
      )
      source = {}
    }
    // ENOENT: no fallback config file; defaults apply silently.
  }
  // Overlay 1: explicit configFile (highest-priority file source).
  if (typeof options.configFile === "string") {
    const configPath = path.isAbsolute(options.configFile)
      ? options.configFile
      : path.resolve(process.cwd(), options.configFile)
    const overlay = JSON.parse(await readFile(configPath, "utf8")) as Record<string, unknown>
    source = { ...source, ...overlay }
  }
  // Overlay 2: explicit options win field by field.
  for (const [key, value] of Object.entries(options)) {
    if (key !== "configFile") source[key] = value
  }
  // `configFile` is a loader directive, not a plugin option — strip it before
  // resolvePluginConfig (whose whitelist rejects unknown fields).
  const { configFile: _ignored, ...pluginOptions } = source
  const resolved = resolvePluginConfig(pluginOptions as BashClassifierOptions | undefined)
  for (const warning of resolved.bypassWarnings) {
    console.warn(`[opencode-v2-security] ${warning}`)
  }
  // v2's Tool.Context has no `ask`, so human-in-the-loop approval cannot be
  // implemented. `fail_ask` is normalized to `fail_close`: an unavailable or
  // failed reviewer becomes a denial, never a question.
  const failAskNormalized = resolved.failPolicy === "fail_ask"
  const effectiveFailPolicy = failAskNormalized ? "fail_close" : resolved.failPolicy
  if (failAskNormalized) {
    console.warn(
      '[opencode-v2-security] failPolicy "fail_ask" is not available in v2 and was normalized to "fail_close" (interactive confirmation unavailable)',
    )
  }
  const configuredShell = resolved.shell
  const strictPolicy = resolved.strictness === "HARD"
  let supervisorActive = false
  if (resolved.supervisorEnabled && process.platform === "win32") {
    try {
      await access(resolved.supervisorPath)
      supervisorActive = true
    } catch {
      supervisorActive = false
    }
  }
  // P4: Linux sandbox probe. Skipped entirely when the sandbox is disabled or
  // forced "full" (no helper exec needed); a missing/failed helper reports
  // unavailable with a sanitized reason — the §4.3 fail mode is applied per
  // spawn, not here, so a probe failure never blocks plugin load.
  let sandboxProbe: SandboxProbeResult | undefined
  if (process.platform === "linux" && resolved.sandbox.enabled && resolved.sandbox.mode !== "full") {
    sandboxProbe = await probeLinuxSandbox(resolved.sandbox)
    if (!sandboxProbe.available) {
      console.warn(
        `[opencode-v2-security] OS sandbox unavailable (${sandboxProbe.reason ?? "unknown reason"}) — ` +
          (resolved.sandbox.onUnavailable === "degrade"
            ? "onUnavailable=degrade: running classifier-only"
            : "onUnavailable=fail_close: non-full shell profiles will be denied"),
      )
    }
  }
  return {
    resolved,
    failAskNormalized,
    effectiveFailPolicy,
    configuredShell,
    strictPolicy,
    supervisorActive,
    sandboxProbe,
  }
}

const plugin: Plugin = {
  id: "opencode-v2-security",
  effect: (ctx: EffectPluginContext) => Effect.gen(function* () {
    // Capture the ambient context so `ctx.session.*` Effects (which need host
    // services despite their narrowed plugin-facing type) run with those
    // services — a bare `Effect.runPromise` would lose them. Mirrors the
    // promise adapter's `Effect.runPromiseWith(context)` bridge. effect 4 has
    // no `Effect.runtime`/`Runtime.runPromise`; context capture is the beta
    // API for this.
    const context = yield* Effect.context<never>()
    const run = <A>(effect: Effect.Effect<A, unknown>): Promise<A> =>
      Effect.runPromiseWith(context)(effect as Effect.Effect<A, unknown, never>)

    const {
      resolved,
      failAskNormalized,
      effectiveFailPolicy,
      configuredShell,
      strictPolicy,
      supervisorActive,
      sandboxProbe,
    } = yield* Effect.promise(() => resolveStartup(ctx.options))

    // v2 ctx has no `directory`/`worktree`; resolve them per session from
    // ctx.session.get(...).location.directory (cached, bounded, TTL-bounded),
    // falling back to process.cwd().
    const sessions = new Map<string, SessionState>()
    const dynamicAllowCache = new Map<string, number>()
    const dynamicDenyCache = new Map<string, DenyCacheEntry>()
    const inflightReviews = new Map<string, Promise<CloudReviewResult>>()
    const sessionDirectories = new Map<string, { directory: string; worktree: string; at: number }>()
    let consecutiveDynamicFailures = 0
    let lastDynamicFailureToastAt = 0

    // --- temporary bypass state (activity-renewed lease) --------------------
    // In-memory by design: a service restart clears every lease, and a lease
    // expires when the session stays quiet for bypassLeaseTtlMs (TUI closed
    // → no user activity → no renewal). Subagent children inherit the armed
    // categories so a bypass armed on the root session covers its spawned
    // subagents doing the actual shell work.
    type BypassLease = { categories: Set<BypassCategory>; expiresAt: number; all?: boolean }
    const bypassLeases = new Map<string, BypassLease>()
    // child → parent links (session lifetime, NOT lease lifetime): written on
    // session.created, cleared on session.deleted only.
    const bypassParent = new Map<string, string>()
    // Last effective category set announced to the agent per session. Comparing
    // against this (rather than recomputing "before" from activeBypass) is
    // essential for expiry: by the time the sweep runs, the lease is already
    // expired, so activeBypass would exclude it and report "no change".
    const announcedBypass = new Map<string, Set<BypassCategory>>()
    // Whether the ALL-OFF kill-switch reminder is the last thing the agent
    // heard for this session (transitions only, same rule as categories).
    const announcedAll = new Map<string, boolean>()
    // Assigned once the RPC in section 8b is registered.
    let bypassRpc:
      | { readonly events: { readonly emit: (...args: unknown[]) => Effect.Effect<void, unknown> } }
      | undefined

    // --- single-call escalation memory (ask_user / deny) --------------------
    // Session-lifetime record of escalation requests the dedicated reviewer
    // turned down. A later semantically similar request in the same session is
    // denied outright without another reviewer call. Deliberately NOT cleared
    // by /bypass: the user arming categories directly is the escape route, and
    // "no similar re-request in this session" must survive it. Cleared on
    // session.deleted and plugin unload; bounded per session and globally.
    const MAX_ESCALATION_FAILURES_PER_SESSION = 8
    const MAX_ESCALATION_FAILURE_SESSIONS = 512
    const escalationFailures = new Map<string, FailedEscalationRecord[]>()
    const escalationPending = new Map<string, object>()

    // --- per-context-cycle full escalation guidance ------------------------
    // The full escalation format is attached only to the FIRST classifier
    // block (static/dynamic/policy) a session receives in the current context
    // cycle; later blocks carry only BLOCK_SUFFIX because the full text is
    // already in the visible context. A completed compaction starts a new
    // cycle (the compacted context no longer contains the earlier guide);
    // session.deleted and plugin unload clear the state, so a plugin reload
    // naturally starts fresh. The claim is a synchronous check-and-set at
    // block-message construction, so it maps 1:1 to the Tool.Error the agent
    // actually receives, an allowed command never consumes it, and two
    // concurrent blocks of the same session cannot both claim. Paths that
    // block without guidance (soft slow, permission deny, patch delete)
    // never touch this state.
    const escalationGuideShown = new Set<string>()
    function claimEscalationGuidance(sessionID: string, rules?: readonly string[]): string {
      // When the escalation channel is configured off the agent never learns
      // it exists: no format guide, no claim slot consumed.
      if (!resolved.escalationEnabled) return ""
      // permission.write is a permission-ceiling hard refuse, independent of
      // escalation: it must not consume the cycle's one full-guide slot.
      if (rules?.includes("permission.write")) return ""
      if (escalationGuideShown.has(sessionID)) return ""
      escalationGuideShown.add(sessionID)
      return ESCALATION_GUIDANCE
    }

    function recordEscalationFailure(sessionID: string, record: FailedEscalationRecord) {
      const failures = escalationFailures.get(sessionID)
      if (failures && failures.length < MAX_ESCALATION_FAILURES_PER_SESSION) failures.push(record)
    }

    // --- session rwx permission layer ---------------------------------------
    // Tighten-only capability ceiling: a session's baseline {r,w,x} intersects
    // with every ancestor baseline (missing = configured default = rwx). All
    // mutation paths except the user-side /perm clamp the new
    // baseline to the session's effective set, so sessions can only lose
    // capability. State is server-memory only; nothing enters model context.
    const sessionPerms = new Map<string, Perm>()
    // Immutable ancestry, hydrated at execution boundaries or via events.
    const permParent = new Map<string, string>()
    // Declared permission waiting for an authoritative execute.after childID.
    const permStash = new Map<string, { parentSessionID: string; perm: Perm; at: number }>()
    const permBoundChildren = new Set<string>()
    const permKnownRoots = new Set<string>()
    const permUnresolved = new Set<string>()

    // Session.get reads the durable record, unlike the asynchronous event
    // consumer. Cache immutable ancestry only; failed reads are retried on the
    // next boundary. An incomplete/cyclic chain loses writes, not RO reads.
    async function hydratePermAncestry(sessionID: string): Promise<void> {
      const seen = new Set<string>()
      let cursor: string | undefined = sessionID
      try {
        while (cursor) {
          if (seen.has(cursor) || seen.size >= 64) throw new Error("Invalid session ancestry")
          seen.add(cursor)
          if (permKnownRoots.has(cursor)) break
          let parent = permParent.get(cursor)
          if (!parent) {
            const info = await run(ctx.session.get({ sessionID: cursor }).pipe(Effect.timeout("2 seconds")))
            if (!info || typeof info !== "object") throw new Error("Missing session record")
            const value = (info as { parentID?: unknown }).parentID
            if (value != null && (typeof value !== "string" || !value)) throw new Error("Invalid parentID")
            parent = typeof value === "string" ? value : undefined
            if (parent) permParent.set(cursor, parent)
            else permKnownRoots.add(cursor)
          }
          cursor = parent
        }
        for (const id of seen) permUnresolved.delete(id)
      } catch {
        permUnresolved.add(sessionID)
      }
    }
    // Last effective perm announced to the agent (transition-only reminders).
    const announcedPerm = new Map<string, Perm>()

    /** Effective permission includes ancestor baselines and temporary spawn
     * declarations. Boundaries hydrate ancestry before relying on this value. */
    function effectivePerm(sessionID: string): Perm {
      let perm = { ...resolved.permission.defaultPerm }
      const seen = new Set<string>()
      let cursor: string | undefined = sessionID
      while (cursor && !seen.has(cursor)) {
        seen.add(cursor)
        const baseline = sessionPerms.get(cursor)
        if (baseline) perm = permIntersect(perm, baseline)
        if (permUnresolved.has(cursor)) perm.w = false
        const parent = permParent.get(cursor)
        // Do not guess which concurrent spawn produced this child. These
        // temporary ceilings disappear when its own call binds authoritatively.
        if (parent && !permBoundChildren.has(cursor)) {
          for (const entry of permStash.values()) {
            if (entry.parentSessionID === parent) perm = permIntersect(perm, entry.perm)
          }
        }
        cursor = parent
      }
      return perm
    }

    function permAncestors(sessionID: string): string[] {
      const chain: string[] = []
      const seen = new Set<string>([sessionID])
      let cursor = permParent.get(sessionID)
      // Same 64-node bound as hydratePermAncestry: ancestry beyond it is
      // treated as unresolved there, so consumers (incl. the escalation
      // failure union) must not see a deeper chain either.
      while (cursor && !seen.has(cursor) && chain.length < 64) {
        seen.add(cursor)
        chain.push(cursor)
        cursor = permParent.get(cursor)
      }
      return chain
    }

    function isPermDescendant(ancestorID: string, sessionID: string): boolean {
      return permAncestors(sessionID).includes(ancestorID)
    }

    const PERM_ACTIVE_REMINDER = (perm: Perm) => {
      const label = permLabel(perm)
      // Describe the concrete label instead of one fixed gloss: e.g. under
      // --x there is no read-only shell exemption to promise, and under rwx
      // nothing is restricted.
      const detail =
        !perm.r && !perm.w
          ? "all tool actions that require r or w are denied; only the shell tool remains usable for read-only commands"
          : perm.r && perm.w
            ? "no plugin permission restriction is active"
            : perm.w
              ? "write actions are available but actions that require r are denied"
              : "read actions are available but write actions are denied; the shell tool remains usable for read-only commands"
      return [
        "This session's permission ceiling changed.",
        `Current permission: ${label} (r=read actions, w=write/edit/delete actions; ${detail}; x cannot be set; it is always on and only shown in the label).`,
        "If a required action lacks permission, ask the user to grant it with /perm rather than attempting another route.",
      ].join("\n")
    }

    /** Notify the agent (synthetic user message) on effective-set transitions
     * and the user (RPC event) every time — both channels stay out of model
     * context semantics: reminders only fire on transitions. */
    function syncPermReminder(sessionID: string) {
      // While the ALL kill switch is armed the agent hears NOTHING but the
      // [ALL OFF] notices — permission reminders stay silent until restore,
      // which re-announces the current state once.
      if (allBypassed(sessionID)) return
      const effective = effectivePerm(sessionID)
      const announced = announcedPerm.get(sessionID)
      if (announced && announced.r === effective.r && announced.w === effective.w && announced.x === effective.x) {
        return
      }
      announcedPerm.set(sessionID, effective)
      // First announce at the configured default is a no-op baseline write
      // (e.g. /perm rw on a session whose configured default is rw) — not worth a
      // reminder; every later transition notifies.
      const isDefault =
        effective.r === resolved.permission.defaultPerm.r &&
        effective.w === resolved.permission.defaultPerm.w &&
        effective.x === resolved.permission.defaultPerm.x
      if (!announced && isDefault) return
      appendAgentReminder(sessionID, PERM_ACTIVE_REMINDER(effective))
    }

    function emitPermChanged(sessionID: string, reason: string) {
      if (!bypassRpc) return
      const effective = effectivePerm(sessionID)
      void run(
        bypassRpc.events.emit("permission", {
          sessionID,
          reason,
          permission: permLabel(effective),
        }),
      ).catch(() => {})
    }

    /** Re-announce descendants whose effective set moved with an ancestor
     * baseline change (links are child→parent, so scan the map). */
    function syncPermDescendants(parentID: string, seen: Set<string> = new Set([parentID])) {
      for (const [child, parent] of permParent) {
        if (parent !== parentID || seen.has(child)) continue
        seen.add(child)
        syncPermReminder(child)
        syncPermDescendants(child, seen)
      }
    }

    /** Tighten `target`'s baseline. `bypass` (the user escape hatch) skips the
     * effective-subset clamp; every other path may only shrink capability. */
    function writeSessionPerm(target: string, next: Perm, bypass: boolean): { ok: boolean; error?: string } {
      if (!bypass) {
        const effective = effectivePerm(target)
        const clamped = tightenPerm(effective, next)
        if (!clamped) {
          return {
            ok: false,
            error: `Permission ${permLabel(next)} would widen the effective ceiling ${permLabel(effective)}; tighten-only is enforced`,
          }
        }
        sessionPerms.set(target, clamped)
      } else {
        sessionPerms.set(target, { ...next })
      }
      syncPermReminder(target)
      syncPermDescendants(target)
      emitPermChanged(target, "set")
      return { ok: true }
    }

    // Agent-facing reminders are appended to the session as synthetic inputs,
    // which the runner lowers to an ordinary **user** message
    // (`runner/to-llm-message.ts`: synthetic -> { role: "user" }). A user
    // message appended at the end of history leaves the cached prefix intact —
    // unlike a system-prompt part, which sits near the front and invalidates the
    // message cache — and is more salient to the agent than a system hint. They
    // are emitted only on state transitions (arm / change / end), never per
    // step, and carry no `description`, so they do not clutter the user's chat
    // transcript (the user is notified separately over RPC).
    /** Exact per-category layer notes (kept compact — reminders enter the
     *  model context). Every note states that the non-bypassed layers —
     *  other classifier categories, the permission ceiling, and the
     *  unconditional safety floor — still apply. `slow` never reaches the
     *  agent channel. */
    const BYPASS_LAYER_NOTES: Record<string, string> = {
      filesystem:
        "filesystem checks are uninspected and unblocked; the permission ceiling, the unconditional safety floor, and all other layers still apply",
      host: "processes, services, and other running-system state are uninspected and unblocked; the OS sandbox and separate permission ceiling still apply",
      privilege:
        "privilege-boundary checks (sudo or ownership/capability changes, kernel parameters, namespaces, privileged containers) are uninspected and unblocked; a call that needs OS privilege runs host-direct without the OS sandbox, or is refused loudly when the sandbox cannot be removed; the permission ceiling and unconditional floor still apply",
      secret:
        "sensitive-file and credential-use checks are uninspected and unblocked; moving secret data off-host still requires the network category, and the permission ceiling, the unconditional safety floor, and all other layers still apply",
      network: "network destinations and transfers are treated as user-trusted; secret and remote-state checks still apply",
      remote:
        "remote code and destructive remote-service, database, infrastructure, or repository changes are uninspected and unblocked; all other layers still apply",
      indirection:
        "local scripts, wrappers, encoded payloads, and dynamic execution are allowed without static inspection; their visible effects remain subject to other categories",
      dynamic:
        "dynamic LLM command review is skipped and commands proceed as if the reviewer were unavailable under fail-open, regardless of the configured failure policy; static checks, sandboxing, and permissions still apply",
      sandbox: "the operating-system sandbox is removed for shell calls; classifier checks and permissions still apply",
      slow: "slow-command optimization checks are skipped; all other layers still apply",
    }

    const BYPASS_ACTIVE_REMINDER = (categories: string[]) =>
      [
        "The user temporarily allowed some sensitive commands.",
        "Categories:",
        ...categories.map((c) => `- ${c}: ${BYPASS_LAYER_NOTES[c] ?? "the corresponding checks are uninspected and unblocked"}.`),
        "You may retry your previous blocked command and continue because the user authorized these categories; be careful with your authorized scope and the changes you make.",
      ].join("\n")
    const BYPASS_ENDED_REMINDER = (ended: string[]) =>
      `The user's temporary security allowance ended: ${ended.join(", ")}. Normal checks are active again.`
    // The ALL kill switch is much broader than a category bypass, so its
    // notice is terse but explicit about enforcement being OFF.
    const BYPASS_ALL_REMINDER = () =>
      [
        "The user temporarily removed all opencode-v2-security enforcement for this session (/bypass ALL).",
        "You may retry the previously blocked command and continue within the user's authorization; be careful with your authorized scope and the changes you make.",
        "The user can restore enforcement with /bypass off; it also expires on its own.",
      ].join("\n")
    const BYPASS_ALL_RESTORED_REMINDER = () =>
      [
        "Enforcement restored: the user lifted the /bypass ALL kill switch.",
        "Plugin enforcement is active again; armed categories and the permission ceiling are re-announced below if set.",
      ].join("\n")

    function sameCategories(a: ReadonlySet<string>, b: ReadonlySet<string>) {
      if (a.size !== b.size) return false
      for (const value of a) if (!b.has(value)) return false
      return true
    }

    /** Ancestors of a session (nearest first), bounded by cycle guard. */
    function bypassAncestors(sessionID: string): string[] {
      const chain: string[] = []
      const seen = new Set<string>([sessionID])
      let cursor = resolved.bypassPropagateToSubagents ? bypassParent.get(sessionID) : undefined
      while (cursor && !seen.has(cursor)) {
        seen.add(cursor)
        chain.push(cursor)
        cursor = bypassParent.get(cursor)
      }
      return chain
    }

    /** Renew the session's own lease and every live ancestor lease: child
     * activity (a subagent doing the shell work) keeps the parent bypass the
     * child inherits from expiring mid-work. Expired leases are ignored (the
     * sweep owns removal + notification) so unrelated activity cannot revive a
     * stale lease. */
    function renewBypassLease(sessionID: string) {
      const now = Date.now()
      for (const target of [sessionID, ...bypassAncestors(sessionID)]) {
        const lease = bypassLeases.get(target)
        if (lease && lease.expiresAt > now) lease.expiresAt = now + resolved.bypassLeaseTtlMs
      }
    }

    /** Active bypass categories for a session: permanent config set ∪ the
     * union of every live lease along the ancestor chain (the session's own
     * lease plus inherited parent leases). Expired leases are skipped without
     * mutating the map; the sweep removes them. */
    function activeBypass(sessionID: string): Set<BypassCategory> {
      const now = Date.now()
      const active = new Set<BypassCategory>(resolved.bypassClassifier)
      for (const target of [sessionID, ...bypassAncestors(sessionID)]) {
        const lease = bypassLeases.get(target)
        if (lease && lease.expiresAt > now) for (const category of lease.categories) active.add(category)
      }
      return active
    }

    /** Whether the `all` kill switch is active for a session: any live lease
     * along the ancestor chain with the flag set (same lease + propagation
     * rules as categories; never armable via config). */
    function allBypassed(sessionID: string): boolean {
      const now = Date.now()
      return [sessionID, ...bypassAncestors(sessionID)].some((target) => {
        const lease = bypassLeases.get(target)
        return lease !== undefined && lease.all === true && lease.expiresAt > now
      })
    }

    /** RPC-facing active list: the real categories plus the literal "all"
     * while the kill switch is armed, so the TUI companion can render the
     * ALL-OFF badge from the same payload. */
    function activeForRpc(sessionID: string): string[] {
      const active = [...activeBypass(sessionID)].sort()
      if (allBypassed(sessionID)) active.push("ALL")
      return active
    }

    /** The session's sandbox profile: "full" (no wrap) when the `all` kill
     * switch or the `sandbox` category is armed — the kernel layer only;
     * classifier and permission layers keep running. */
    function sessionSandboxProfile(
      sessionID: string,
      callBypass?: ReadonlySet<BypassCategory>,
    ): SandboxProfile {
      if (allBypassed(sessionID) || callBypass?.has("sandbox") || activeBypass(sessionID).has("sandbox")) return "full"
      return profileForPerm(effectivePerm(sessionID), resolved.sandbox)
    }

    /** Whether the kernel sandbox will actually enforce the RO write
     * boundary for THIS call — the same inputs the wrap path uses: the
     * session's resolved profile is "ro" (which already folds in
     * mode:full, sandbox/`all` bypass, and the perm), and the probe
     * reported a usable route. fail_close with an unavailable probe
     * denies the call before it matters, and degrade runs bare — either
     * way the classifier must keep its static gates, so false. */
    function roKernelEnforcedForCall(
      sessionID: string,
      callBypass?: ReadonlySet<BypassCategory>,
    ): boolean {
      const perm = effectivePerm(sessionID)
      if (perm.w) return false
      if (sessionSandboxProfile(sessionID, callBypass) !== "ro") return false
      return sandboxProbe?.available === true
    }

    /** Push a bypass state change to the TUI companion (best effort). The TUI
     * is the only user-visible channel that does not enter the model context. */
    function emitBypassChanged(sessionID: string, reason: string) {
      if (!bypassRpc) return
      const permanent = [...resolved.bypassClassifier].sort()
      const active = activeForRpc(sessionID)
      const temporary = active.filter((category) => !resolved.bypassClassifier.has(category as BypassCategory))
      void run(bypassRpc.events.emit("changed", { sessionID, reason, active, temporary, permanent })).catch(
        () => {},
      )
    }

    /** Append a bypass reminder to the session as a synthetic (user-role)
     * input. `resume:false` keeps it from waking the session; no `description`
     * keeps it out of the user's chat transcript. Fire-and-forget: a failed
     * reminder must never affect command handling. */
    function appendAgentReminder(sessionID: string, text: string) {
      void run(
        ctx.session.synthetic({
          sessionID,
          // Natural sender prefix: the message lands as a plain user-role
          // line, so it names the plugin instead of looking injected.
          text: `opencode-v2-security: ${text}`,
          metadata: { source: "opencode-v2-security-bypass" },
          resume: false,
          delivery: "steer",
        }),
      ).catch(() => {})
    }

    /** Whether any live (unexpired) temporary lease applies to the session. */
    function hasLiveLease(sessionID: string): boolean {
      const now = Date.now()
      return [sessionID, ...bypassAncestors(sessionID)].some((target) => {
        const lease = bypassLeases.get(target)
        return lease !== undefined && lease.expiresAt > now
      })
    }

    /** Bring the agent's bypass reminder in line with the effective state:
     * append an ACTIVE reminder when the agent-facing set is non-empty, an
     * ENDED reminder when it emptied, and nothing when unchanged.
     *
     * `slow` is deliberately excluded from the agent-facing set: the
     * slow-command classifier is a soft deterrent, not a security boundary, so
     * arming/disarming it must not teach the model that a slow-bypass is an
     * escape hatch (the TUI indicator still shows it to the user). The `all`
     * kill switch gets its own loud ALL-OFF reminder. */
    function syncAgentReminder(sessionID: string) {
      const facing = new Set(activeBypass(sessionID))
      facing.delete("slow")
      const all = allBypassed(sessionID)
      const announced = announcedBypass.get(sessionID) ?? new Set<BypassCategory>()
      const wasAll = announcedAll.get(sessionID) === true
      if (all === wasAll && sameCategories(announced, facing)) return
      if (all) {
        // While the kill switch is armed the agent gets ONLY the [ALL OFF]
        // arm/restore notices: category transitions stay silent (the state is
        // still tracked so the restore re-announcement is accurate).
        if (!wasAll) appendAgentReminder(sessionID, BYPASS_ALL_REMINDER())
        if (facing.size > 0) announcedBypass.set(sessionID, new Set(facing))
        else announcedBypass.delete(sessionID)
        announcedAll.set(sessionID, true)
        return
      }
      if (wasAll && !all) {
        // Restore notice first; then the current state is re-announced below
        // (announcedBypass is cleared so still-armed categories emit a fresh
        // ACTIVE notice, and ended ones emit ENDED).
        appendAgentReminder(sessionID, BYPASS_ALL_RESTORED_REMINDER())
        announcedAll.delete(sessionID)
        announcedBypass.delete(sessionID)
      }
      const ended = [...announced].filter((c) => !facing.has(c))
      if (facing.size === 0) {
        // One ENDED reminder covers ended categories (after a restore, an
        // empty facing needs nothing more — the restore notice said it all).
        if (ended.length > 0 || (announced.size > 0 && !wasAll)) {
          appendAgentReminder(sessionID, BYPASS_ENDED_REMINDER(ended))
        }
        announcedBypass.delete(sessionID)
      } else if (!sameCategories(announced, facing) || (wasAll && !all)) {
        if (ended.length > 0) appendAgentReminder(sessionID, BYPASS_ENDED_REMINDER(ended))
        appendAgentReminder(sessionID, BYPASS_ACTIVE_REMINDER([...facing].sort()))
        announcedBypass.set(sessionID, new Set(facing))
      }
    }

    /** Remove leases whose TTL elapsed and re-sync the agent reminder. Called on
     * a timer because lease pruning is otherwise lazy, so the transition would
     * never be observed. */
    function sweepExpiredBypass() {
      const now = Date.now()
      for (const [sessionID, lease] of [...bypassLeases]) {
        if (lease.expiresAt > now) continue
        bypassLeases.delete(sessionID)
        syncAgentReminder(sessionID)
        // Lease expiry can lift the ALL kill switch too — re-announce the
        // permission ceiling if one was silenced while ALL was armed.
        if (!allBypassed(sessionID)) syncPermReminder(sessionID)
        if (activeBypass(sessionID).size === 0) emitBypassChanged(sessionID, "expired")
        else emitBypassChanged(sessionID, "updated")
      }
    }

    type BypassOp =
      | { kind: "clear" }
      | { kind: "categories"; action: "arm" | "disarm" | "toggle"; which: "allCategories" | readonly BypassCategory[] }
      | { kind: "killSwitch"; action: "arm" | "disarm" | "toggle" }

    /** Parses /bypass arguments into ordered operations. Case rules: the
     *  literal "ALL" (also +ALL/-ALL) is the kill switch; everything else is
     *  lowercased before matching. Explicit `+token` always arms, `-token`
     *  always disarms (never toggles); a bare token toggles against the
     *  pre-command snapshot. Aliases: fs→filesystem, 0→off, all→* (the
     *  complete category set — lowercase `all` is NOT the kill switch). */
    function parseBypassArguments(text: string): { ops: BypassOp[]; invalid: string[] } {
      const ops: BypassOp[] = []
      const invalid: string[] = []
      const rawTokens = text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean)
      for (const raw of rawTokens) {
        // Sign is checked on the RAW token so "+ALL" resolves like "ALL".
        let sign: "+" | "-" | undefined
        let body = raw
        if (body.startsWith("+") || body.startsWith("-")) {
          sign = body[0] as "+" | "-"
          body = body.slice(1)
        }
        // Kill switch: case-sensitive literal ALL.
        if (body === "ALL") {
          ops.push({ kind: "killSwitch", action: sign === "+" ? "arm" : sign === "-" ? "disarm" : "toggle" })
          continue
        }
        const token = body.toLowerCase()
        if (token === "off" || token === "clear" || token === "none" || token === "0") {
          ops.push({ kind: "clear" })
          continue
        }
        // The complete category set: `*` or lowercase `all`.
        if (token === "*" || token === "all") {
          ops.push({ kind: "categories", action: sign === "+" ? "arm" : sign === "-" ? "disarm" : "toggle", which: "allCategories" })
          continue
        }
        const categories = expandBypassCategoryToken(token)
        if (categories) {
          ops.push({ kind: "categories", action: sign === "+" ? "arm" : sign === "-" ? "disarm" : "toggle", which: categories })
          continue
        }
        invalid.push(raw)
      }
      return { ops, invalid }
    }

    function bypassUsage(invalid: string[]): string {
      return (
        `Unknown bypass categor${invalid.length > 1 ? "ies" : "y"}: ${invalid.join(", ")}.\n` +
        `Usage: /bypass <${[...BYPASS_CATEGORIES].join("|")}|fs|*|all|ALL|off> — ` +
        `categories space or comma separated; legacy aliases: fs=filesystem, os=host+privilege+indirection, web=network+remote; ` +
        `* or all = all ${BYPASS_CATEGORIES.length} categories; uppercase ALL = the kill switch (all plugin enforcement off) — prefer specific categories when possible; ` +
        `off/0 clears everything. +token arms, -token disarms, a bare token toggles.\n` +
        `host = running-system state (processes, services, power, persistence); privilege = crossing permission or ` +
        `isolation boundaries (sudo/doas/su/pkexec/sudoedit, chown, capabilities, kernel parameters, namespaces) — when privilege is ` +
        `armed and a call needs it, that call runs host-direct without the OS sandbox, or is refused loudly if the ` +
        `sandbox cannot be removed (ro profiles); arm the sandbox category as well to remove the OS sandbox entirely.`
      )
    }

    function armBypassLease(sessionID: string, categories: Set<BypassCategory>) {
      // A new arm keeps an already-armed `all` kill switch: narrowing the
      // category set must not silently re-enable the enforcement layers the
      // user turned off; only `off`/clear or lease expiry lifts `all`.
      const all = bypassLeases.get(sessionID)?.all === true
      bypassLeases.set(sessionID, {
        categories: new Set(categories),
        expiresAt: Date.now() + resolved.bypassLeaseTtlMs,
        all,
      })
      // Freshly armed session: prior rejection records would keep forcing
      // dynamic review (and HARD abort semantics) for a bypassed command.
      const state = sessions.get(sessionID)
      if (state) {
        state.lastRejected = undefined
        state.touchedAt = Date.now()
        state.version += 1
      }
    }

    function armBypassAll(sessionID: string) {
      bypassLeases.set(sessionID, {
        categories: new Set(activeBypass(sessionID)),
        expiresAt: Date.now() + resolved.bypassLeaseTtlMs,
        all: true,
      })
      const state = sessions.get(sessionID)
      if (state) {
        state.lastRejected = undefined
        state.touchedAt = Date.now()
        state.version += 1
      }
    }

    // Detect OS/shell context for the auditor's environment line (an
    // OS-level description like "Ubuntu 24.04 WSL", not a kernel release).
    let environmentLine: { system?: string; bash?: string } | undefined
    function detectEnvironment() {
      if (environmentLine) return environmentLine
      const platform = process.platform
      let system: string | undefined
      try {
        if (platform === "linux") {
          let pretty: string | undefined
          try {
            const osReleaseContent = readFileSync("/etc/os-release", "utf8")
            pretty = osReleaseContent.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1]
          } catch {
            pretty = undefined
          }
          const wslDistro = process.env.WSL_DISTRO_NAME
          const isWsl = process.env.WSL_INTEROP !== undefined || wslDistro !== undefined
          const base = pretty ?? "Linux"
          const endsWithWsl = /\bwsl$/i.test(base)
          if (!isWsl) system = base
          else if (endsWithWsl) system = base
          else if (pretty && wslDistro && base.toLowerCase().includes(wslDistro.toLowerCase()))
            system = `${base} WSL`
          else if (wslDistro) system = `${base} ${wslDistro} WSL`
          else system = `${base} WSL`
        } else if (platform === "win32") {
          system = `Windows ${osRelease()}`
        } else if (platform === "darwin") {
          system = `macOS ${osRelease()}`
        } else {
          system = `${platform} ${osRelease()}`.trim()
        }
      } catch {
        system = undefined
      }
      const bash = configuredShell ?? process.env.SHELL ?? (platform === "win32" ? "powershell" : "/bin/bash")
      environmentLine = { system, bash }
      return environmentLine
    }

    // Reviewer audit trail (logReviewerTrace): one JSONL line per dynamic
    // review verdict/error and per cache hit, appended to
    // ~/.opencode/reviewer-trace.jsonl. Fire-and-forget — a logging failure
    // must never alter the review outcome or block a command.
    const reviewerTraceFile = resolved.logReviewerTrace
      ? path.join(homedir(), ".opencode", "reviewer-trace.jsonl")
      : undefined
    function writeReviewerTrace(entry: Record<string, unknown>) {
      if (!reviewerTraceFile) return
      const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n"
      void mkdir(path.dirname(reviewerTraceFile), { recursive: true })
        .then(() => appendFile(reviewerTraceFile, line, "utf8"))
        .catch(() => {})
    }

    function deleteSessionState(sessionID: string) {
      sessions.delete(sessionID)
      sessionDirectories.delete(sessionID)
      // Review caches are global and context-addressed; TTL eviction covers them.
    }

    function pruneSessionStates(now: number) {
      for (const [sessionID, state] of sessions) {
        if (state.touchedAt + SESSION_STATE_TTL_MS <= now) deleteSessionState(sessionID)
      }
      for (const [sessionID, entry] of sessionDirectories) {
        if (entry.at + SESSION_STATE_TTL_MS <= now) sessionDirectories.delete(sessionID)
      }
      // Unbound declarations are security state, not a TTL cache. A failed
      // spawn may already have prompted a child; retain until parent deletion.
    }

    function getSessionState(sessionID: string): SessionState {
      const now = Date.now()
      pruneSessionStates(now)
      let state = sessions.get(sessionID)
      if (!state) {
        while (sessions.size >= MAX_SESSION_STATES) {
          const oldest = sessions.keys().next().value
          if (typeof oldest !== "string") break
          deleteSessionState(oldest)
        }
        state = { version: 0, touchedAt: now }
        sessions.set(sessionID, state)
      } else {
        state.touchedAt = now
        sessions.delete(sessionID)
        sessions.set(sessionID, state)
      }
      return state
    }

    async function sessionDirectory(sessionID: string): Promise<{ directory: string; worktree: string }> {
      const cached = sessionDirectories.get(sessionID)
      if (cached && cached.at + SESSION_STATE_TTL_MS > Date.now()) return cached
      try {
        const info = (await run(ctx.session.get({ sessionID }))) as { location?: { directory?: string } }
        const raw = info?.location?.directory
        if (typeof raw === "string" && raw) {
          const directory = await canonicalOrResolved(raw)
          while (sessionDirectories.size >= MAX_SESSION_STATES) {
            let oldestKey: string | undefined
            let oldestAt = Infinity
            for (const [key, entry] of sessionDirectories) {
              if (entry.at < oldestAt) {
                oldestAt = entry.at
                oldestKey = key
              }
            }
            if (oldestKey === undefined) break
            sessionDirectories.delete(oldestKey)
          }
          const entry = { directory, worktree: directory, at: Date.now() }
          sessionDirectories.set(sessionID, entry)
          return entry
        }
      } catch {
        // Session lookup failed (e.g. already deleted); fall through to cwd.
      }
      const directory = await canonicalOrResolved(process.cwd())
      return { directory, worktree: directory }
    }

    function reviewerAvailable() {
      return Boolean(resolved.reviewCommand)
    }

    function extractHttpStatus(message: string): string | undefined {
      const m = message.match(/HTTP\s*(\d{3})/i) ?? message.match(/\b(\d{3})\b/)
      if (m) {
        const code = m[1]
        if (code && /^4\d\d$|^5\d\d$/.test(code)) return code
      }
      return undefined
    }

    async function maybeNotifyDynamicConsecutiveFailures(sessionID: string, error: Error) {
      if (!reviewerAvailable()) return
      consecutiveDynamicFailures++
      if (consecutiveDynamicFailures < 3) return
      const now = Date.now()
      if (now - lastDynamicFailureToastAt < 60_000) return
      lastDynamicFailureToastAt = now
      const status = extractHttpStatus(error.message)
      const shortMsg = status
        ? `Dynamic review unavailable (HTTP ${status}), please check endpoint, network and auth`
        : `Dynamic review unavailable, please check endpoint, network and auth`
      console.error(`[opencode-v2-security] ${shortMsg}: ${error.message.slice(0, 300)}`)
      // Best-effort TUI toast via any available UI (server ctx has no ui, but try for future TUI companion)
      try {
        const anyCtx = ctx as unknown as { ui?: { toast?: { show?: (o: unknown) => void } } }
        anyCtx.ui?.toast?.show?.({ message: shortMsg, variant: "error", duration: 5000 })
      } catch {}
      // Also surface to the user: a synthetic needs a `description` to render
      // in the TUI chat. Without it the message would be hidden from the user
      // while still entering the model context.
      // resume:false (M11) — a reviewer-outage notice must never auto-resume the session.
      try {
        await run(
          ctx.session.synthetic({
            sessionID,
            text: `opencode-v2-security: ${shortMsg}`,
            description: shortMsg,
            metadata: { source: "opencode-v2-security-dynamic-review" },
            resume: false,
            delivery: "steer",
          }),
        )
      } catch {}
    }

    function resetDynamicFailureCounter() {
      consecutiveDynamicFailures = 0
    }

    function nextGeneration(state: SessionState) {
      state.touchedAt = Date.now()
      return ++state.version
    }

    function recordRejection(state: SessionState, value: PreviousRejectedCommand) {
      if (!strictPolicy) return undefined
      const generation = nextGeneration(state)
      state.lastRejected = { value, generation }
      return generation
    }

    function rejectStatic(
      sessionID: string,
      state: SessionState,
      command: string,
      reason: string,
      rules: string[] = [],
    ): never {
      recordRejection(state, { command, reason, classifier: "STATIC" })
      throw blockMessage(
        "static", reason, strictPolicy, rules, command,
        claimEscalationGuidance(sessionID, rules), resolved.escalationEnabled,
      )
    }

    async function performDynamicReview(request: CloudReviewRequest): Promise<CloudReviewResult> {
      const reviewFn = resolved.reviewCommand
      if (!reviewFn) throw new Error("Dynamic review is not configured")
      const options: ReviewCommandOptions = {
        endpoint: resolved.dynamicReview.endpoint ?? "",
        model: resolved.dynamicReview.model ?? "",
        apiKey: resolved.dynamicReview.apiKey ?? "",
        maxRounds: resolved.dynamicReview.maxRounds,
        policy: resolved.strictness,
        allowFullReadAccess: resolved.dynamicReview.allowFullReadAccess,
        python: resolved.dynamicReview.pythonPath,
        auditorPath: resolved.dynamicReview.auditorPath,
        timeout: resolved.dynamicReview.timeoutMs,
      }
      return reviewFn(request, options)
    }

    // --- 6. HARD session interrupt (v1 client.session.abort) ----------------
    async function abortSession(sessionID: string) {
      try {
        await run(ctx.session.interrupt({ sessionID }))
      } catch {
        // Interrupt failure must not allow the command — the caller still throws.
      }
    }

    // Fire-and-forget the interrupt ~100ms AFTER throwing the block. If the
    // interrupt lands first it rewrites the block reason to STEP_INTERRUPTED,
    // hiding why the command was denied; scheduling it after the throw keeps the
    // block message as the visible outcome.
    function scheduleAbort(sessionID: string) {
      setTimeout(() => void abortSession(sessionID), 100)
    }

    // S14: the four analyzeSlowCommand call sites share one helper so the
    // enabled/background/explicit-timeout gating stays in sync.
    function maybeBlockSlow(
      script: string,
      input: Record<string, unknown>,
      shell: string,
      cwd: string,
      worktree: string,
      bypassed?: ReadonlySet<BypassCategory>,
    ): void {
      if (!resolved.slowCommands.enabled) return
      // The `slow` bypass category skips the slow-command classifier for the
      // session (the `all` kill switch never reaches this helper at all).
      if (bypassed?.has("slow")) return
      if (input.background === true) return
      const explicitTimeout = input.timeout
      const hasExplicitTimeout =
        typeof explicitTimeout === "number" && Number.isFinite(explicitTimeout) && explicitTimeout > 0
      if (hasExplicitTimeout && resolved.slowCommands.allowExplicitTimeout) return
      const slow = analyzeSlowCommand(script, shell, {
        cwd,
        worktree,
        maxDepth: resolved.slowCommands.maxDepth,
        sleepThresholdSeconds: resolved.slowCommands.sleepThresholdSeconds,
      })
      if (slow) throw softSlowMessage(slow.reason)
    }

    // --- P4 sandbox spawn state ----------------------------------------------
    // The create.before event (19271 API) has no sessionID, so a one-shot
    // nonce marker prepended to input.command by runBefore carries the chosen
    // profile to spawn time (plan §1.3). The marker is the SOLE authority for
    // wrapping: user-initiated shells (`!cmd`, host-internal spawns) never
    // ran execute.before, carry no marker, and run completely untouched —
    // trusted authority, exactly as they were never classified.
    const sandboxMarkers = createSandboxMarkers()

    async function applyPostChecks(
      script: string,
      input: Record<string, unknown>,
      decision: StaticSecurityDecision,
      shell: string,
      sandboxContext?: {
        sessionID: string
        bypassedCategories?: ReadonlySet<BypassCategory>
        /** Per-call host-direct routing decided by the privilege gate in
         * runBefore: privilege is in the effective bypass set and the command
         * needs OS privilege, so the spawn must not be kernel-wrapped. */
        privilegeHostDirect?: boolean
      },
    ) {
      if (resolved.detachedStartIsolation && !supervisorActive) {
        const isolated = isolateDetachedStartCommand(script, shell)
        if (isolated !== script) {
          input.command = isolated
        }
      }

      // Host-direct observability: every runnable path (static ALLOW,
      // cached allow, dynamic ALLOW, fail_open) funnels through
      // applyPostChecks, and every upstream denial path (static DENY, the
      // ro-profile privilege refusal, the availability gate, dynamic DENY,
      // fail_close) returns or throws before reaching it. The fingerprint
      // check at the end is the last gate: the reminder and the
      // privilege_host_direct audit line are written only AFTER it
      // succeeds, so a call rejected with "Local script changed after
      // review" is never recorded as having run host-direct.
      const hostDirectObservability =
        sandboxContext?.privilegeHostDirect === true &&
        resolved.sandbox.enabled &&
        resolved.sandbox.mode !== "full"

      // Marker must wrap the FINAL command text (post detached-start
      // isolation), so it is inserted here — after isolation — rather than at
      // the availability gate. Inserting before dynamic review per the §5
      // table would be silently dropped by the isolation rewrite above.
      if (sandboxContext) {
        const profile = sessionSandboxProfile(sandboxContext.sessionID, sandboxContext.bypassedCategories)
        // The rw host-direct routes — the allowSudo config route, or the
        // privilege category routing one privilege-needing call out of the
        // sandbox — need no kernel probe result: the helper runs the payload
        // directly, so the marker must be inserted even when the probe
        // reported unavailable.
        const hostDirectRoute =
          profile === "rw" && (resolved.sandbox.allowSudo || sandboxContext.privilegeHostDirect === true)
        if (profile !== "full" && (sandboxProbe?.available || hostDirectRoute)) {
          const finalCommand = commandFromArgs(input) ?? script
          input.command = insertSandboxMarker(
            sandboxMarkers,
            finalCommand,
            profile,
            undefined,
            undefined,
            sandboxContext.privilegeHostDirect === true,
          )
        } else if (
          profile === "full" &&
          (allBypassed(sandboxContext.sessionID) ||
            sandboxContext.bypassedCategories?.has("sandbox") ||
            activeBypass(sandboxContext.sessionID).has("sandbox"))
        ) {
          // Explicit "full" marker: the sandbox bypass (or `all` kill switch)
          // is a deliberate unsandboxed claim — carried through the nonce so
          // create.before leaves this tool shell untouched (and, on Windows,
          // un-supervisor-wrapped).
          const finalCommand = commandFromArgs(input) ?? script
          input.command = insertSandboxMarker(sandboxMarkers, finalCommand, "full")
        }
      }

      // Last gate: the local-script fingerprint check. Only when it passes —
      // the call is finally allowed to run — do the host-direct reminder and
      // the privilege_host_direct audit line get written (exactly once each,
      // on the very spawn that takes the host-direct route).
      const ok = await verifyScriptFingerprints(decision.fingerprints)
      if (ok && hostDirectObservability && sandboxContext) {
        const profile = sessionSandboxProfile(sandboxContext.sessionID, sandboxContext.bypassedCategories)
        appendAgentReminder(
          sandboxContext.sessionID,
          `this command needs OS privilege and the privilege category is authorized, so this shell call runs ` +
            `host-direct without the OS sandbox wrap; classifier checks, the permission ceiling, and the ` +
            `unconditional safety floor still apply.`,
        )
        writeReviewerTrace({
          kind: "privilege_host_direct",
          sessionID: sandboxContext.sessionID,
          command: script,
          profile,
          categories: [...(sandboxContext.bypassedCategories ?? [])].sort(),
        })
      }
      return ok
    }

    // --- 2b. single-call escalation review ------------------------------------
    // A valid REQUIRE_ESCALATION request goes to the dedicated escalation
    // reviewer: a direct Python child (bundled escalation-reviewer.py — never
    // the ordinary auditorPath, never the reviewCommand injection hook). Only
    // allow_once proceeds, and its categories are merged into the bypass set
    // for THIS shell call alone. ask_user and deny are recorded for the
    // session lifetime, so a similar request never reaches the reviewer
    // again. Config/infra/protocol/timeout failures (and an unreadable session
    // context) fail closed WITHOUT a permanent record — the agent's remaining
    // route is asking the user to authorize directly (/bypass).

    /** Inputs the floor pre-check needs to run the static classifier with the
     * same arguments the post-grant classification in runBefore will use. */
    type EscalationClassifyContext = {
      cwd: string
      worktree: string
      shell: string
      runtimeWorkdir?: string
    }

    /** Floor pre-check, run before the escalation reviewer is consulted: it
     * simulates the best possible grant (the session's live bypasses plus
     * every requested category plus the full static category set — a
     * superset of anything the reviewer could ever allow) through the
     * ordinary static classifier. When the decision
     * still hits a rule no bypass category can ever clear — an unconditional
     * floor rule (isFloorRule), the permission ceiling, or unreviewable
     * input (input.empty/input.opaque) — no reviewer verdict could make the
     * call runnable. The request is refused terminally here, recorded as a
     * deny so a similar re-request cannot loop, and the reviewer is never
     * called. Ordinary rules that merely have no bypass mapping do NOT end
     * here (that was the pre-rework semantic and it also caught unmapped
     * ordinary rules); only the floor and the explicit terminal set do.
     * The rule check runs on the decision's rules regardless of verdict:
     * input.opaque is ASK, not DENY, and it must still short-circuit. */
    async function precheckEscalationFloor(
      sessionID: string,
      request: EscalationRequest,
      classifyContext: EscalationClassifyContext,
    ): Promise<void> {
      // Arm every static category, not just the requested ones: the floor is
      // immune to all categories, so a terminal rule that still fires under a
      // full arm can never be cleared by any grant. Arming only the requested
      // categories let an unrequested non-floor rule shadow a floor rule in
      // decision.rules (same segment), and let an earlier segment's
      // bypassable denial stop the walk before the floor segment was seen.
      const hypothetical = activeBypass(sessionID)
      for (const category of STATIC_BYPASS_CATEGORIES) hypothetical.add(category)
      for (const category of request.categories) hypothetical.add(category as BypassCategory)
      const decision = await classifyShellCommand({
        script: request.command,
        cwd: classifyContext.cwd,
        worktree: classifyContext.worktree,
        shell: classifyContext.shell,
        strictness: resolved.strictness,
        bypassedCategories: hypothetical.size > 0 ? hypothetical : undefined,
        permScope: effectivePerm(sessionID),
        roKernelEnforced: roKernelEnforcedForCall(sessionID, hypothetical),
        roWritableRoots: [resolved.sandbox.scratch],
        sandboxDenyWrite: resolved.sandbox.denyWrite,
        runtimeWorkdir: classifyContext.runtimeWorkdir,
      })
      const terminal = decision.rules.filter((rule) => isFloorRule(rule) || TERMINAL_ESCALATION_RULES.has(rule))
      if (terminal.length === 0) return
      // E3: a static floor refusal is NOT a reviewer denial — it is not
      // recorded in the reviewer/user-decision history, so a classifier
      // false positive cannot lock out similar requests. Every fresh request
      // still runs this precheck and execution still runs the normal checks,
      // so the floor itself is unchanged; only the inaccurate memory is gone.
      writeReviewerTrace({
        kind: "escalation_floor_precheck",
        sessionID,
        command: request.command,
        categories: [...request.categories],
        rules: decision.rules,
        reason: decision.reason,
      })
      const ending = decision.rules.includes("permission.write")
        ? ` ${PERM_WRITE_SUFFIX}`
        : `; ${TERMINAL_NO_BYPASS}`
      throw rejectionError(
        `Escalation refused: this command cannot be escalated — it is denied by rule(s) that no bypass category ` +
          `can ever override (${terminal.join(", ")}), so the escalation cannot go over the hard floor. The ` +
          `escalation reviewer was not consulted and the command was not run — any resubmission hits the ` +
          `same static check${ending}`,
      )
    }

    async function reviewEscalationRequest(
      sessionID: string,
      request: EscalationRequest,
      classifyContext: EscalationClassifyContext,
    ): Promise<readonly BypassCategory[]> {
      if (escalationPending.has(sessionID)) {
        // The in-flight review may still produce an allow_once: waiting is a
        // real option, so it is named before the user-authorization route.
        throw rejectionError(
          `Escalation already pending in this session; the command was not run. ` +
            `Wait for the pending request's result, or${terminalAuthorize(request.categories, { skip: false })}`,
        )
      }
      const failures = escalationFailures.get(sessionID) ?? []
      if (failures.length >= MAX_ESCALATION_FAILURES_PER_SESSION ||
          (!escalationFailures.has(sessionID) && escalationFailures.size >= MAX_ESCALATION_FAILURE_SESSIONS)) {
        throw rejectionError(
          `Escalation history capacity reached; the command was not run.${terminalAuthorize(request.categories)}`,
        )
      }
      // A denied request retried verbatim from a child (subagent) session
      // must hit the same memory: the similar check sees the read-only union
      // of the ancestor chain's failure lists. The session's own list stays
      // the write target and the capacity base — nothing is copied into it.
      const inherited: FailedEscalationRecord[] = []
      for (const ancestor of permAncestors(sessionID)) {
        const ancestorFailures = escalationFailures.get(ancestor)
        if (ancestorFailures) inherited.push(...ancestorFailures)
      }
      const similar = findSimilarFailedEscalation(request.command, [...failures, ...inherited])
      if (similar) {
        const earlier =
          similar.decision === "ask_user"
            ? "already required the user's explicit confirmation for a similar command"
            : "already denied a similar command"
        throw rejectionError(
          `Escalation denied: the escalation reviewer ${earlier} ` +
            `in this session (recorded command: ${similar.command.slice(0, 120)}). A similar escalation request cannot ` +
            `be submitted again in this session. The command was not run.${terminalAuthorize(request.categories)}`,
        )
      }

      // Reserve both review and history capacity before the first await. One
      // review per session also prevents dissimilar requests racing saturation.
      const pending = {}
      escalationPending.set(sessionID, pending)
      escalationFailures.set(sessionID, failures)
      try {
        // Floor pre-check: refuse terminally (recorded as a deny) before any
        // reviewer call when no grantable category set could ever let the
        // static layer pass this command.
        await precheckEscalationFloor(sessionID, request, classifyContext)
        return await performEscalationReview(sessionID, request, failures, pending)
      } finally {
        if (escalationPending.get(sessionID) === pending) {
          escalationPending.delete(sessionID)
          if (failures.length === 0) escalationFailures.delete(sessionID)
        }
      }
    }

    async function performEscalationReview(
      sessionID: string,
      request: EscalationRequest,
      failures: FailedEscalationRecord[],
      pending: object,
    ): Promise<readonly BypassCategory[]> {
      const dynamic = resolved.dynamicReview
      if (!dynamic.available || !dynamic.endpoint || !dynamic.model || !dynamic.apiKey) {
        // Config-field detail is logged, not shown: the agent cannot fix the
        // plugin config, so the agent-facing reason stays generic.
        if (dynamic.reason) console.error(`[opencode-v2-security] escalation review unavailable: ${dynamic.reason}`)
        throw rejectionError(
          `Escalation review is unavailable (dynamic review unavailable or invalid review configuration); ` +
            `the command was not run.${terminalAuthorize(request.categories)}`,
        )
      }

      // The reviewer must see what the user actually asked for. A context
      // read failure leaves the request without user intent — that can never
      // justify an escalation, so it fails closed (without a permanent
      // record).
      const perm = effectivePerm(sessionID)
      let reviewRequest: EscalationReviewRequest
      try {
        if (typeof ctx.session.context !== "function") {
          throw new Error("session.context is not available on this host")
        }
        const payload = await run(ctx.session.context({ sessionID }))
        const messages = Array.isArray(payload)
          ? payload
          : payload && typeof payload === "object" && Array.isArray((payload as { data?: unknown }).data)
            ? (payload as { data: unknown[] }).data
            : undefined
        if (!messages) throw new Error("session context payload has no message array")
        const { currentUserInput, recentContext } = escalationContextFromMessages(messages)
        reviewRequest = {
          command: request.command,
          categories: request.categories,
          justification: request.justification,
          currentUserInput,
          recentContext,
          permScope: { r: perm.r, w: perm.w, x: perm.x },
          previousFailedEscalations: failures,
        }
      } catch {
        throw rejectionError(
          "Escalation denied: the session context could not be read, so the escalation reviewer cannot see what " +
            `the user asked for. The command was not run.${terminalAuthorize(request.categories)}`,
        )
      }

      try {
        if (escalationPending.get(sessionID) !== pending) {
          throw rejectionError(
            `Escalation session ended before review; the command was not run.${terminalAuthorize(request.categories)}`,
          )
        }
        const decision = await reviewEscalation(reviewRequest, {
          endpoint: dynamic.endpoint,
          model: dynamic.model,
          apiKey: dynamic.apiKey,
          python: dynamic.pythonPath,
          // The escalation reviewer runs with thinking enabled and needs a
          // much larger budget than the ordinary dynamic reviewer: never let
          // a small configured dynamicReview.timeoutMs shrink it below the
          // thinking-sized default.
          timeout: Math.max(dynamic.timeoutMs, DEFAULT_ESCALATION_REVIEW_TIMEOUT_MS),
        })
        if (escalationPending.get(sessionID) !== pending) {
          throw rejectionError(
            `Escalation session ended during review; the command was not run.${terminalAuthorize(request.categories)}`,
          )
        }
        writeReviewerTrace({
          kind: "escalation_review_verdict",
          sessionID,
          command: request.command,
          categories: [...request.categories],
          justification: request.justification,
          endpoint: dynamic.endpoint,
          model: dynamic.model,
          decision,
        })
        if (decision === "allow_once") {
          // The parser validated every category against BYPASS_CATEGORIES;
          // filter() narrows the parsed strings back to the canonical union.
          return BYPASS_CATEGORIES.filter((category) => request.categories.includes(category))
        }
        recordEscalationFailure(sessionID, {
          command: request.command,
          categories: request.categories,
          justification: request.justification,
          decision,
        })
        // The internal decision name never reaches the agent: the refusal is
        // phrased as a natural outcome. Both outcomes are terminal — a similar
        // command cannot request escalation again, so the message points at
        // user-side authorization only.
        const outcome =
          decision === "ask_user"
            ? "The escalation reviewer requires the user's explicit confirmation for this command"
            : "The escalation reviewer denied this one-time request"
        throw rejectionError(
          `${outcome}; the command was not run. A similar command cannot request ` +
            `escalation again in this session.${terminalAuthorize(request.categories)}`,
        )
      } catch (error) {
        if (error instanceof EscalationReviewError) {
          writeReviewerTrace({
            kind: "escalation_review_error",
            sessionID,
            command: request.command,
            categories: [...request.categories],
            endpoint: dynamic.endpoint,
            model: dynamic.model,
            error: error.message.slice(0, 1000),
          })
          throw rejectionError(
            `Escalation review failed (${error.kind}) and the command was not run: ${error.message.slice(0, 200)}. ` +
              `No escalation failure was recorded — you may retry the same escalation request later, ` +
              `or${terminalAuthorize(request.categories, { skip: false })}`,
          )
        }
        throw error
      }
    }

    // --- 4. shell wrap: Linux OS sandbox (P4) + Windows supervisor -----------
    // Mutually exclusive per platform. On Linux the nonce marker is the SOLE
    // authority for the wrap (see applySandboxCreateBefore): marker-less
    // spawns — user `!cmd` shells and host-internal spawns — are trusted
    // authority and are returned byte-identical. Marker present → strip,
    // wrap per profile; "full" returns untouched. On Windows the existing
    // supervisor wrap is unchanged, and an explicit "full" marker skips it.
    yield* ctx.shell.hook("create.before", (ev: ShellCreateBeforeEvent) =>
      Effect.sync(() => {
        // Marker extraction runs on every platform: an explicit "full" marker
        // is the per-call carrier for the `sandbox` bypass category and the
        // `all` kill switch, and must skip BOTH the bwrap wrap (Linux) and the
        // supervisor wrap (Windows).
        const marked = extractSandboxMarker(sandboxMarkers, ev.command)
        if (process.platform === "linux") {
          applySandboxCreateBefore(ev, marked, resolved.sandbox, sandboxProbe)
          return
        }
        if (marked.profile) ev.command = marked.command
        if (marked.profile === "full") return
        if (!supervisorActive) return
        // Idempotency: never wrap the supervisor with itself.
        if (path.resolve(ev.shell) === path.resolve(resolved.supervisorPath)) return
        ev.env.OPENCODE_REAL_BASH = ev.shell
        ev.shell = resolved.supervisorPath
      }),
    )

    // --- 2. static + LLM review pipeline (v1 tool.execute.before) -----------
    async function runBefore(ev: ExecuteBeforeEvent): Promise<void> {
      await hydratePermAncestry(ev.sessionID)
      // `/bypass all` kill switch: no plugin enforcement for this session.
      // Shell calls still get an explicit "full" marker so create.before
      // (which has no sessionID) skips the sandbox/supervisor wrap, and the
      // plugin-added `permission` arg is stripped so the host tool does not
      // see it. Everything else is untouched.
      if (allBypassed(ev.sessionID)) {
        if (ev.tool === "subagent" && resolved.permission.subagentPermission) {
          delete (ev.input as Record<string, unknown> | undefined)?.permission
        }
        if (ev.tool === "shell" || ev.tool === "bash") {
          renewBypassLease(ev.sessionID)
          const input = ev.input as Record<string, unknown>
          const command = commandFromArgs(input)
          if (command !== undefined) {
            input.command = insertSandboxMarker(sandboxMarkers, command, "full")
          }
        }
        return
      }

      // Subagent permission parameter: a declared ceiling for the spawned
      // child session, stripped here (the host tool doesn't know the arg) and
      // bound when session.created/execute.after identify the child.
      if (ev.tool === "subagent" && resolved.permission.subagentPermission) {
        const input = ev.input as Record<string, unknown> | undefined
        const declared = input?.permission
        if (typeof declared === "string" && declared.trim()) {
          const perm = parsePerm(declared)
          if (!perm) {
            throw rejectionError(
              `Invalid subagent permission "${declared}" (expected ro/4, rw/6, w/2, or none/0; x cannot be set; it is always on and only shown in the label)`,
            )
          }
          if (typeof input.sessionID === "string") {
            await hydratePermAncestry(input.sessionID)
            if (permParent.get(input.sessionID) !== ev.sessionID) throw rejectionError("Not a direct child session")
            sessionPerms.set(input.sessionID, permIntersect(sessionPerms.get(input.sessionID) ?? PERM_FULL, perm))
          } else {
            permStash.set(ev.id, { parentSessionID: ev.sessionID, perm, at: Date.now() })
          }
          delete input.permission
        } else if (declared !== undefined) {
          delete input.permission
        }
        if (!input?.sessionID && !permStash.has(ev.id)) {
          permStash.set(ev.id, { parentSessionID: ev.sessionID, perm: PERM_FULL, at: Date.now() })
        }
      }

      // apply_patch -> patch. Delete-file patches are blocked statically so the
      // deletion goes through the shell tool and its permission layer instead.
      if (ev.tool === "patch" || ev.tool === "apply_patch") {
        const input = ev.input as Record<string, unknown> | undefined
        const patchText = typeof input?.patchText === "string" ? input.patchText : undefined
        if (patchText && /^\*\*\* Delete File:/m.test(patchText)) {
          throw applyPatchDeleteBlock()
        }
        return
      }

      // bash -> shell (keep accepting "bash" for compatibility).
      if ((ev.tool !== "shell" && ev.tool !== "bash") || !resolved.securityEnabled) return

      const sessionID = ev.sessionID
      const sessionState = getSessionState(sessionID)
      const input = ev.input as Record<string, unknown>
      const rawScript = commandFromArgs(input)
      if (!rawScript?.trim()) {
        rejectStatic(sessionID, sessionState, "", "Empty command")
      }

      // Single-call escalation (strict three-line prefix). "none" leaves the
      // command exactly as it was; "malformed" fails closed with the exact
      // expected format; "valid" strips the three header lines and sends the
      // real command through the dedicated escalation reviewer. An allowed
      // request only adds its categories to THIS call's bypass set.
      // escalationEnabled=false removes the channel entirely: a leading
      // `# - REQUIRE_ESCALATION` block parses as an ordinary shell comment
      // and is classified as a normal command — it never reaches the
      // reviewer and is never recorded as a reviewer decision.
      const escalationParsed = resolved.escalationEnabled
        ? parseEscalation(rawScript, ESCALATION_GRANTABLE_CATEGORIES)
        : { status: "none" as const, command: rawScript }
      let script = rawScript
      let escalationGranted: readonly BypassCategory[] | undefined
      if (escalationParsed.status === "malformed") {
        rejectStatic(sessionID, sessionState, rawScript, `Malformed escalation request: ${escalationParsed.reason}`)
      }
      // Session directory/cwd/shell resolution is hoisted above the escalation
      // branch so the floor pre-check inside reviewEscalationRequest can run
      // the static classifier with the same inputs the post-grant
      // classification below uses. cwd stays the verified session directory;
      // the tool's workdir argument is handed to the classifier as an
      // unverified runtime base claim.
      const requestedWorkdir = workdirFromArgs(input)
      const { directory, worktree } = await sessionDirectory(sessionID)
      const cwd = await canonicalOrResolved(directory)
      const shell = resolveClassifierShell(configuredShell)
      if (escalationParsed.status === "valid") {
        const request = escalationParsed.request
        // From here on every consumer (classifier, reviewers, caches, the
        // tool call itself) sees only the real command.
        script = request.command
        input.command = request.command
        escalationGranted = await reviewEscalationRequest(sessionID, request, {
          cwd,
          worktree,
          shell,
          runtimeWorkdir: requestedWorkdir,
        })
      }

      const bypassed = activeBypass(sessionID)
      // An allow_once escalation adds its categories for THIS shell call only:
      // no lease is written, no reminder is sent, nothing survives the call.
      if (escalationGranted) for (const category of escalationGranted) bypassed.add(category)
      const bypassedCategories = bypassed.size > 0 ? bypassed : undefined
      // Executing a command in this session is activity: renew its lease so an
      // actively worked session keeps its bypass while the TUI stays open.
      renewBypassLease(sessionID)

      const staticDecision: StaticSecurityDecision = await classifyShellCommand({
        script,
        cwd,
        worktree,
        shell,
        strictness: resolved.strictness,
        bypassedCategories,
        permScope: effectivePerm(sessionID),
        roKernelEnforced: roKernelEnforcedForCall(sessionID, bypassed),
        roWritableRoots: [resolved.sandbox.scratch],
        sandboxDenyWrite: resolved.sandbox.denyWrite,
        runtimeWorkdir: requestedWorkdir,
      })
      if (bypassedCategories && resolved.logReviewerTrace) {
        writeReviewerTrace({
          kind: "bypass_active",
          sessionID,
          command: script,
          categories: [...bypassedCategories].sort(),
        })
      }

      // Static DENY is absolute — cannot be overridden by approval or dynamic review.
      if (staticDecision.verdict === "DENY") {
        rejectStatic(sessionID, sessionState, script, staticDecision.reason, staticDecision.rules)
      }

      // host/privilege ↔ OS sandbox consistency: when the effective bypass
      // set (session lease ∪ this call's escalation grant) contains
      // `privilege` and the command needs OS privilege, the call must run
      // host-direct — bwrap's unconditional NO_NEW_PRIVS and cap-drop would
      // otherwise make sudo/chown/setcap fail silently at runtime even
      // though the user authorized exactly that. rw profiles reuse the
      // existing allowSudo host-direct helper route (the nonce marker carries
      // the per-call flag); a profile that cannot lose the sandbox (ro
      // ignores allowSudo) fails loudly instead of running into a
      // guaranteed silent runtime failure. "full" is already host-direct.
      const callSandboxProfile = sessionSandboxProfile(sessionID, bypassed)
      const needsOsPrivilege = commandNeedsOsPrivilege(script, shell)
      const privilegeHostDirect = bypassed.has("privilege") && needsOsPrivilege
      // A privilege-needing command must never silently run inside the OS
      // sandbox: without `privilege` there is no host-direct route (except
      // the config allowSudo route, which is already host-direct), so refuse
      // terminally rather than let the call hit bwrap's NO_NEW_PRIVS floor
      // and die with a confusing runtime error.
      const rwAllowSudoRoute = callSandboxProfile === "rw" && resolved.sandbox.allowSudo
      if (needsOsPrivilege && callSandboxProfile !== "full" && !rwAllowSudoRoute) {
        if (!bypassed.has("privilege")) {
          const escalationRoute = resolved.escalationEnabled
            ? `, or to include the privilege category when escalating this command`
            : ""
          throw rejectionError(
            `Blocked by policy classifier: this command needs OS privilege but the privilege category is not ` +
              `bypassed for this call, so the OS sandbox's no_new_privs floor would make the privilege step ` +
              `fail silently at runtime — the command was not run. Ask the user to arm the privilege bypass ` +
              `category (/bypass privilege)${escalationRoute} ` +
              `(a rw profile host-direct route also requires sandbox.allowSudo).`,
          )
        }
        if (callSandboxProfile === "ro") {
          const escalationRoute = resolved.escalationEnabled
            ? `to include the sandbox category when escalating privileged commands, or `
            : ""
          throw rejectionError(
            `Blocked by policy classifier: this command needs OS privilege and the privilege category is bypassed ` +
              `for this call, but this call's OS sandbox profile is read-only and cannot run it host-direct — the ` +
              `sandbox's no_new_privs floor would make the privilege step fail silently at runtime, so the command ` +
              `was not run. Ask the user to arm the sandbox bypass category (/bypass sandbox), ${escalationRoute}` +
              `or to enable sandbox.allowSudo in the plugin config for read-write sessions.`,
          )
        }
      }
      // The host-direct agent reminder and the privilege_host_direct audit
      // line are written in applyPostChecks — at the final-allow point,
      // after every denial path (static DENY, the ro-profile refusal above,
      // the sandbox availability gate, dynamic DENY, fail_close) and after
      // the local-script fingerprint check passes — so they never claim a
      // host-direct run for a call that was never allowed to run.

      // P4 sandbox availability gate: after the static classifier (a static
      // DENY reports its own reason) and before dynamic review (denying here
      // saves a reviewer call). Any userspace DENY above short-circuits the
      // kernel layer; under fail_close a non-full profile with no sandbox
      // route denies the call outright. rw host-direct routes (allowSudo
      // config, or the privilege routing above) need no kernel probe result.
      assertSandboxAvailable(
        callSandboxProfile,
        sandboxProbe,
        resolved.sandbox.onUnavailable,
        resolved.sandbox.allowSudo || privilegeHostDirect,
      )

      // Slow-command soft interception for high-cost optimizable commands (S14).
      if (staticDecision.verdict === "ALLOW") maybeBlockSlow(script, input, shell, cwd, worktree, bypassed)

      // v1's approved-fingerprint path (confirm tool) is gone in v2: there is no
      // confirmation tool, so no approval can ever be recorded.

      const rejectionAtStart = strictPolicy ? sessionState.lastRejected : undefined
      const failureAtStart =
        strictPolicy && sessionState.lastFailed && !sessionState.lastFailed.consumedBy
          ? sessionState.lastFailed
          : undefined
      const forcedByRejection = Boolean(rejectionAtStart)
      const forcedByFailure = Boolean(failureAtStart)
      const forced = forcedByRejection || forcedByFailure

      if (staticDecision.verdict === "ALLOW" && !forced) {
        if (
          !(await applyPostChecks(script, input, staticDecision, shell, {
            sessionID,
            bypassedCategories: bypassed,
            privilegeHostDirect,
          }))
        ) {
          rejectStatic(sessionID, sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        return
      }

      const cacheable = !strictPolicy && !forcedByFailure
      let cacheKey: string | undefined
      if (cacheable) {
        cacheKey = dynamicAllowCacheKey(
          script,
          cwd,
          shell,
          staticDecision,
          resolved.dynamicReview.endpoint ?? "",
          resolved.dynamicReview.model ?? "",
          resolved.strictness,
          bypassedCategories ? [...bypassedCategories].sort() : undefined,
          effectivePerm(sessionID),
        )
        if (cacheKey && hasCachedDynamicAllow(dynamicAllowCache, cacheKey, Date.now())) {
          maybeBlockSlow(script, input, shell, cwd, worktree, bypassed)
          writeReviewerTrace({ kind: "cache_allow", sessionID, command: script, cacheKey })
          if (
            !(await applyPostChecks(script, input, staticDecision, shell, {
              sessionID,
              bypassedCategories: bypassed,
              privilegeHostDirect,
            }))
          ) {
            rejectStatic(sessionID, sessionState, script, "Local script changed after review", staticDecision.rules)
          }
          return
        }
        if (cacheKey) {
          const denyReason = cachedDynamicDenyReason(dynamicDenyCache, cacheKey, Date.now())
          if (denyReason !== undefined) {
            writeReviewerTrace({ kind: "cache_deny", sessionID, command: script, cacheKey, reason: denyReason })
            throw blockMessage(
              "dynamic",
              denyReason,
              strictPolicy,
              staticDecision.rules,
              script,
              claimEscalationGuidance(sessionID),
              resolved.escalationEnabled,
            )
          }
        }
      }

      // v2 tool call id replaces v1's input.callID for failure-consumption tracking.
      const callID = ev.id
      if (
        failureAtStart &&
        sessionState.lastFailed?.generation === failureAtStart.generation &&
        !sessionState.lastFailed.consumedBy
      ) {
        sessionState.lastFailed.consumedBy = callID
      }

      const reviewRequest: CloudReviewRequest = {
        command: script,
        localScripts: staticDecision.reviewContext?.localScripts ?? [],
        uninspectedLocalScripts: staticDecision.reviewContext?.uninspectedLocalScripts ?? [],
        targetDirectories: staticDecision.reviewContext?.targetDirectories ?? [],
        uninspectedTargetDirectories: staticDecision.reviewContext?.uninspectedTargetDirectories ?? [],
        referencedPaths: staticDecision.reviewContext?.referencedPaths ?? [],
        referencedPathsTruncated: staticDecision.reviewContext?.referencedPathsTruncated ?? false,
        worktree,
        cwd,
        permScope: effectivePerm(sessionID),
      }
      if (rejectionAtStart) {
        reviewRequest.previousRejectedCommand = rejectionAtStart.value
      }
      if (failureAtStart) {
        reviewRequest.previousFailedCommand = failureAtStart.value
      }
      if (bypassedCategories && bypassedCategories.size > 0) {
        // Sorted to match the dynamic cache key, so one key always means one
        // BYPASS_RULE prompt ordering. Only static-rule categories relax the
        // reviewer's prompt — `dynamic`, `sandbox`, and `slow` bypass layers
        // the reviewer never sees, so they stay out of `userBypass`.
        const promptCategories = [...bypassedCategories]
          .filter((category) => (STATIC_BYPASS_CATEGORIES as readonly string[]).includes(category))
          .sort()
        if (promptCategories.length > 0) reviewRequest.userBypass = promptCategories
      }
      // Environment awareness is part of every dynamic review, not only
      // bypassed ones.
      reviewRequest.environment = detectEnvironment()

      let cloudReview: CloudReviewResult | undefined
      let reviewError: Error | undefined
      // `dynamic` bypass: the reviewer is skipped for this session and the
      // fail-open route below always applies — the armed bypass overrides the
      // configured failPolicy (fix F2). A skipped reviewer must never count
      // as a reviewer "failure" for the consecutive-failure toast.
      const dynamicBypassed = bypassedCategories?.has("dynamic") === true
      if (!dynamicBypassed && reviewerAvailable()) {
        try {
          // Concurrent identical reviews share one in-flight call instead of
          // racing duplicate auditor processes at the endpoint.
          let pending = cacheKey ? inflightReviews.get(cacheKey) : undefined
          if (!pending) {
            pending = performDynamicReview(reviewRequest)
            if (cacheKey) {
              inflightReviews.set(cacheKey, pending)
              void pending
                .catch(() => {})
                .finally(() => {
                  if (inflightReviews.get(cacheKey) === pending) inflightReviews.delete(cacheKey)
                })
            }
          }
          const result: unknown = await pending
          if (!isValidReviewResult(result, strictPolicy)) {
            throw new Error("Dynamic review returned an invalid result")
          }
          cloudReview = result
        } catch (error) {
          reviewError = error instanceof Error ? error : new Error(String(error))
          writeReviewerTrace({
            kind: "review_error",
            sessionID,
            command: script,
            endpoint: resolved.dynamicReview.endpoint,
            model: resolved.dynamicReview.model,
            error: reviewError.message.slice(0, 1000),
          })
        }
      } else {
        reviewError = new Error(
          dynamicBypassed
            ? "Dynamic review is disabled for this session by a user-armed bypass"
            : (resolved.dynamicReview.reason ?? "Dynamic review is not configured"),
        )
      }

      if (cloudReview) {
        resetDynamicFailureCounter()
        writeReviewerTrace({
          kind: "review_verdict",
          sessionID,
          command: script,
          endpoint: resolved.dynamicReview.endpoint,
          model: resolved.dynamicReview.model,
          decision: cloudReview.decision,
          reason: cloudReview.reason,
          bypassing: cloudReview.bypassing,
        })
        if (strictPolicy && cloudReview.bypassing === true) {
          const reason =
            cloudReview.decision === "DENY"
              ? cloudReview.reason
              : "The command appears to bypass a previous rejection"
          recordRejection(sessionState, { command: script, reason, classifier: "DYNAMIC" })
          scheduleAbort(sessionID)
          throw blockMessage(
            "dynamic", reason, true, staticDecision.rules, script,
            claimEscalationGuidance(sessionID), resolved.escalationEnabled,
          )
        }

        if (cloudReview.decision === "DENY") {
          recordRejection(sessionState, {
            command: script,
            reason: cloudReview.reason,
            classifier: "DYNAMIC",
          })
          if (cacheKey) cacheDynamicDeny(dynamicDenyCache, cacheKey, cloudReview.reason, Date.now())
          throw blockMessage(
            "dynamic",
            cloudReview.reason,
            strictPolicy,
            staticDecision.rules,
            script,
            claimEscalationGuidance(sessionID),
            resolved.escalationEnabled,
          )
        }

        if (
          rejectionAtStart &&
          sessionState.lastRejected?.generation === rejectionAtStart.generation
        ) {
          sessionState.lastRejected = undefined
        }
        // Re-run slow-command soft check after dynamic ALLOW to avoid FN via static
        // ASK -> dynamic ALLOW path. Must run before caching so soft-blocked
        // commands do not pollute the ALLOW cache.
        maybeBlockSlow(script, input, shell, cwd, worktree, bypassed)
        if (
          !(await applyPostChecks(script, input, staticDecision, shell, {
            sessionID,
            bypassedCategories: bypassed,
            privilegeHostDirect,
          }))
        ) {
          rejectStatic(sessionID, sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        if (cacheKey) cacheDynamicAllow(dynamicAllowCache, cacheKey, Date.now())
        return
      }

      // Consecutive dynamic review failure tracking for TUI notification (3 times)
      if (!cloudReview && !dynamicBypassed && reviewerAvailable() && reviewError) {
        await maybeNotifyDynamicConsecutiveFailures(sessionID, reviewError)
      }

      const failReason = agentFacingReviewReason(reviewError?.message ?? "Dynamic review failed")

      // Fail routing (HARD only): a protocol-class ReviewError (oversized payload,
      // bad auditor shape/exit, mandatory-inspection violation) is an UNCONDITIONAL
      // fail-close — a defensive failure must close the gate regardless of
      // failPolicy. LOOSE performs no protocol special-casing: the auditor never
      // enforces mandatory inspection under LOOSE (auditor.py gates that check on
      // POLICY == "HARD"), and every review failure — protocol or infra — simply
      // honors the configured failPolicy. An infra-class error (HTTP/network) or
      // any unknown non-ReviewError honors the configured failPolicy in both modes.
      const protocolViolation = reviewError instanceof ReviewError && reviewError.kind === "protocol"
      if (protocolViolation && strictPolicy) {
        // HARD + protocol: trip the prompt-injection detector when a reviewer
        // endpoint is configured. The detector is a tripwire on top of the
        // unconditional deny, not a replacement for it.
        const endpoint = resolved.dynamicReview.endpoint ?? ""
        const model = resolved.dynamicReview.model ?? ""
        const apiKey = resolved.dynamicReview.apiKey ?? ""
        if (endpoint && model && apiKey) {
          // Reconstruct the exact JSON the auditor received so the detector judges
          // the real payload (reviewer.ts stringifies the same requestForPolicy
          // shape). The recovered transcript is added as secondary context.
          const reviewJson = JSON.stringify(
            requestForPolicy(normalizeReviewRequest(reviewRequest), resolved.strictness),
          )
          const transcript = reviewError instanceof ReviewError ? reviewError.transcript : undefined
          let detector: { injection: boolean; evidence?: string } | undefined
          try {
            detector = await detectInjection(
              { reviewJson, transcript },
              { endpoint, model, apiKey, timeoutMs: resolved.dynamicReview.timeoutMs },
            )
          } catch {
            // The detector never becomes a false allow: treat like fail_close.
            detector = undefined
          }
          if (detector && detector.injection === true) {
            recordRejection(sessionState, {
              command: script,
              reason: "Prompt injection detected in command or review data",
              classifier: "FAIL_POLICY",
            })
            scheduleAbort(sessionID)
            // Fire-and-forget the alert: awaiting it here could outlast the 100ms
            // abort delay, letting STEP_INTERRUPTED overwrite this block reason.
            void run(
              ctx.session.synthetic({
                sessionID,
                text: "opencode-v2-security: prompt injection detected in command or review data; command denied and session interrupted.",
                description: "Prompt injection detected; command denied and session interrupted.",
                metadata: { source: "opencode-v2-security-injection-detector" },
                resume: false,
                delivery: "steer",
              }),
            ).catch(() => {})
            throw blockMessage(
              "policy",
              "Prompt injection detected in command or review data",
              true,
              staticDecision.rules,
              script,
              claimEscalationGuidance(sessionID),
              resolved.escalationEnabled,
            )
          }
          if (detector === undefined) {
            recordRejection(sessionState, {
              command: script,
              reason: failReason,
              classifier: "FAIL_POLICY",
            })
            throw failClosedBlock(
              `${failReason} (injection detector unavailable; fail-close)`,
              failAskNormalized,
              strictPolicy,
              staticDecision.rules,
              script,
              claimEscalationGuidance(sessionID),
              resolved.escalationEnabled,
            )
          }
          // detector === { injection: false } → still unconditional fail-close.
        }
        recordRejection(sessionState, { command: script, reason: failReason, classifier: "FAIL_POLICY" })
        throw failClosedBlock(
          failReason,
          failAskNormalized,
          strictPolicy,
          staticDecision.rules,
          script,
          claimEscalationGuidance(sessionID),
          resolved.escalationEnabled,
        )
      }

      // infra ReviewError or unknown non-ReviewError → honor failPolicy.
      // An armed `dynamic` bypass always behaves as "reviewer unavailable +
      // fail_open" regardless of the configured failPolicy (fix F2): the
      // user asked for the layer to be off, so the command proceeds once the
      // static and permission layers have passed.
      if (effectiveFailPolicy === "fail_open" || dynamicBypassed) {
        // Even on fail_open, still soft-enforce slow-command for default-timeout high-resource commands.
        maybeBlockSlow(script, input, shell, cwd, worktree, bypassed)
        if (
          !(await applyPostChecks(script, input, staticDecision, shell, {
            sessionID,
            bypassedCategories: bypassed,
            privilegeHostDirect,
          }))
        ) {
          rejectStatic(sessionID, sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        return
      }
      // fail_close (including fail_ask normalized to fail_close).
      recordRejection(sessionState, {
        command: script,
        reason: failReason,
        classifier: "FAIL_POLICY",
      })
      throw failClosedBlock(
        failReason,
        failAskNormalized,
        strictPolicy,
        staticDecision.rules,
        script,
        claimEscalationGuidance(sessionID),
        resolved.escalationEnabled,
      )
    }

    yield* ctx.tool.hook("execute.before", (ev: ExecuteBeforeEvent) =>
      Effect.tryPromise({ try: () => runBefore(ev), catch: toRejection }),
    )

    // --- 3. failure recording (v1 tool.execute.after) -----------------------
    // execute.after failure channel is `never`: any exception is swallowed so a
    // post-check error never fails the tool step.
    async function runAfter(ev: ExecuteAfterEvent): Promise<void> {
      // Only the tool result identifies a spawn's child authoritatively.
      // Finish existing bookkeeping even if the user armed ALL mid-call.
      if (ev.tool === "subagent") {
        const stash = permStash.get(ev.id)
        if (ev.status === "completed" && stash) {
          const rawOutput = ev.result?.output
          const childID =
            (typeof ev.result?.metadata?.sessionID === "string" && ev.result.metadata.sessionID) ||
            (rawOutput && typeof rawOutput === "object" && typeof (rawOutput as Record<string, unknown>).sessionID === "string"
              ? ((rawOutput as Record<string, unknown>).sessionID as string)
              : undefined)
          if (childID) {
            // Keep real child restrictions, but never persist a speculative
            // intersection with a sibling's declaration. Ancestry caps live.
            const childPerm = permIntersect(sessionPerms.get(childID) ?? PERM_FULL, stash.perm)
            sessionPerms.set(childID, childPerm)
            permParent.set(childID, stash.parentSessionID)
            permBoundChildren.add(childID)
            permStash.delete(ev.id)
            syncPermReminder(childID)
            emitPermChanged(childID, "spawned")
          }
        }
      }
      if (allBypassed(ev.sessionID)) return
      if ((ev.tool !== "shell" && ev.tool !== "bash") || !resolved.securityEnabled) return
      // A failed tool call carries no result; v1 read undefined metadata and
      // returned early — same behavior.
      if (ev.status !== "completed") return

      const sessionID = ev.sessionID
      const sessionState = getSessionState(sessionID)
      const metadata = ev.result?.metadata

      // v2 shell result metadata = { truncated, exit?, shellID?, timeout? }
      // (verified in packages/core/src/tool/plugin/shell.ts). `exitCode` is
      // kept as a defensive fallback for other shells/v1-shaped metadata.
      const rawExit = metadata?.exit ?? metadata?.exitCode
      const exitCode = typeof rawExit === "number" ? rawExit : undefined
      if (exitCode === undefined) return

      if (exitCode === 0) {
        if (sessionState.lastFailed?.consumedBy === ev.id) {
          sessionState.lastFailed = undefined
        }
        return
      }

      if (!strictPolicy) return

      // Strip the sandbox marker (if any) so the stored/displayed command is
      // the real script, not the instrumented spawn payload.
      const command = stripSandboxMarker(commandFromArgs(ev.input) ?? "")
      // H2: v2's result.output is a structured object ({ output, cursor, size,
      // truncated }), not a bare string — extract the text defensively.
      const rawOutput = ev.result?.output
      const outputText =
        typeof rawOutput === "string"
          ? rawOutput
          : rawOutput &&
              typeof rawOutput === "object" &&
              typeof (rawOutput as Record<string, unknown>).output === "string"
            ? ((rawOutput as Record<string, unknown>).output as string)
            : ""
      sessionState.lastFailed = {
        value: {
          command,
          exitCode,
          outputTail: sanitizeOutputTail(outputText),
        },
        generation: nextGeneration(sessionState),
      }
    }

    yield* ctx.tool.hook("execute.after", (ev: ExecuteAfterEvent) =>
      Effect.tryPromise({ try: () => runAfter(ev), catch: (error: unknown) => error }).pipe(
        Effect.catch(() => Effect.void),
      ),
    )

    // --- 7. session cleanup + bypass lease maintenance (v1 event hook) -------
    // ctx.event.subscribe() returns a Stream of wire events; the durable
    // `session.deleted` payload is { type, data: { sessionID } } (verified in
    // packages/schema/src/session-event.ts). The consumer is forked onto the
    // plugin scope: unloading the plugin interrupts the fiber, replacing the old
    // manual `eventRunning`/iterator cleanup.
    //
    // The same consumer maintains the temporary-bypass lease:
    //  - `session.created` records parent→child links so subagents inherit an
    //    armed bypass (bypassPropagateToSubagents, default true);
    //  - activity events (viewed / inbox delivered / execution started) renew
    //    the lease of the session they name, approximating "TUI still open":
    //    with the TUI closed no user-visible activity flows and the lease
    //    expires after bypassLeaseTtlMs.
    const BYPASS_RENEWAL_EVENTS = new Set([
      "session.viewed",
      "session.inbox.delivered",
      "session.execution.started",
      "session.step.started",
      "session.shell.started",
    ])
    yield* ctx.event
      .subscribe()
      .pipe(
        Stream.runForEach((event: unknown) =>
          Effect.sync(() => {
            const e = event as {
              type?: string
              data?: { sessionID?: string; parentID?: string }
            }
            const sessionID = e?.data?.sessionID
            if (e?.type === "session.deleted") {
              if (typeof sessionID === "string") {
                deleteSessionState(sessionID)
                bypassLeases.delete(sessionID)
                bypassParent.delete(sessionID)
                announcedBypass.delete(sessionID)
                announcedAll.delete(sessionID)
                sessionPerms.delete(sessionID)
                permParent.delete(sessionID)
                permBoundChildren.delete(sessionID)
                permKnownRoots.delete(sessionID)
                permUnresolved.delete(sessionID)
                announcedPerm.delete(sessionID)
                escalationFailures.delete(sessionID)
                escalationPending.delete(sessionID)
                escalationGuideShown.delete(sessionID)
                for (const [child, parent] of permParent) {
                  if (parent === sessionID) permParent.delete(child)
                }
                for (const [callID, pending] of permStash) {
                  if (pending.parentSessionID === sessionID) permStash.delete(callID)
                }
                // Children still linking to the deleted parent would otherwise
                // dangle forever; the map stays bounded to live sessions.
                for (const [child, parent] of bypassParent) {
                  if (parent === sessionID) bypassParent.delete(child)
                }
              }
              return
            }
            // A completed compaction replaces the model-visible context, so
            // the next classifier block must be able to carry the full
            // escalation guide again. `session.compaction.ended` is the
            // durable completion event ({ type, data: { sessionID, reason,
            // text, recent } }, verified in
            // packages/schema/src/session-event.ts; published by core
            // session compaction). `session.compacted` is accepted as a
            // compatible alias declared in the schema manifest. A failed
            // compaction does NOT reset — the context was not replaced.
            if (e?.type === "session.compaction.ended" || e?.type === "session.compacted") {
              if (typeof sessionID === "string") escalationGuideShown.delete(sessionID)
              return
            }
            if (e?.type === "session.created") {
              const parentID = e.data?.parentID
              if (typeof sessionID === "string" && typeof parentID === "string" && parentID) {
                permParent.set(sessionID, parentID)
              }
              if (
                resolved.bypassPropagateToSubagents &&
                typeof sessionID === "string" &&
                typeof parentID === "string" &&
                parentID
              ) {
                bypassParent.set(sessionID, parentID)
                // The child is a fresh session without the parent's reminder in
                // its history; append one so a subagent doing the shell work is
                // warned too. Link is set first so activeBypass sees the parent.
                if (hasLiveLease(sessionID)) syncAgentReminder(sessionID)
              }
              return
            }
            if (typeof sessionID === "string" && BYPASS_RENEWAL_EVENTS.has(e?.type ?? "")) {
              renewBypassLease(sessionID)
            }
          }),
        ),
      )
      .pipe(Effect.forkScoped)

    // --- 8b. bypass notification RPC (server → TUI companion) ---------------
    // Event-only contract shared with src/tui.ts. Fire-and-forget: a missing or
    // failed TUI subscriber must never affect command handling. Hosts without
    // the RPC domain (older builds) simply skip user toasts.
    if (ctx.rpc)
      bypassRpc = yield* ctx.rpc.register(BypassRpc, {
        status: (input: { sessionID: string }) =>
          Effect.sync(() => {
            const active = activeForRpc(input.sessionID)
            return {
              sessionID: input.sessionID,
              permission: permLabel(effectivePerm(input.sessionID)),
              active,
              temporary: active.filter((category) => !resolved.bypassClassifier.has(category as BypassCategory)),
              permanent: [...resolved.bypassClassifier].sort(),
            }
          }),
      })

    // --- 8c. lease expiry sweep ---------------------------------------------
    // Lease pruning is otherwise lazy (activeBypass merely skips expired
    // entries), so without a timer the expiry transition — the agent reminder
    // and the user notification — would never fire.
    const BYPASS_SWEEP_INTERVAL_MS = 20_000
    yield* Effect.sync(() => sweepExpiredBypass()).pipe(
      Effect.repeat(Schedule.spaced(`${BYPASS_SWEEP_INTERVAL_MS} millis`)),
      Effect.forkScoped,
    )

    // --- 8e. session rwx permission layer -----------------------------------
    // Structural enforcement only: the permission.evaluate hook (primary
    // channel, every tool's action flows through it), the classifier's
    // permScope fallback for write-shaped shell segments, and the
    // set_permission native tool. All transitions are transitions-notified:
    // the agent sees a synthetic reminder, the user an RPC event.

    // Action → required bit. A missing bit hard-denies the action before the
    // tool runs; we never upgrade a computed effect, only tighten it. Actions
    // absent from the map (MCP tools assert composed `${server}_${tool}`
    // names) fall back to the write bit unless deliberately ungated — RO
    // sessions therefore deny the whole MCP class.
    if (ctx.permission) {
      yield* ctx.permission.hook("evaluate", (ev: PermissionEvalEvent) =>
        Effect.promise(async () => {
          await hydratePermAncestry(ev.sessionID)
          // Kill switch: the permission action gates are part of plugin
          // enforcement and stay silent while `all` is armed.
          if (allBypassed(ev.sessionID)) return
          const required =
            requiredPermBit(ev.action, resolved.permission.actionPerm) ??
            (resolved.permission.gateUnknownActions || permUnresolved.has(ev.sessionID)
              ? fallbackPermBit(ev.action, { ungated: resolved.permission.ungatedActions })
              : undefined)
          if (!required) return
          const perm = effectivePerm(ev.sessionID)
          if (perm[required]) return
          ev.effect = "deny"
          ev.message =
            `Session permission ${permLabel(perm)} lacks '${required}' (action: ${ev.action}). ` +
            `The user can restore it with /perm rw.`
        }),
      )
    }

    // `set_permission` native tool: the model may tighten a direct child
    // session's ceiling. Widening is rejected (clamp semantics); the caller's
    // own session, non-child sessions, and unknown sessions fail closed.
    if (ctx.tool.transform && resolved.permission.registerTool) {
      yield* ctx.tool.transform((draft) => {
        draft.add({
          name: "set_permission",
          options: { codemode: false },
          description: [
            "Restrict a direct subagent session's permission ceiling.",
            "The permission string is r/w only: 'ro'/'r--'/4, 'rw'/'rw-'/6, 'w'/2, or 'none'/'0'. x inputs (x/rx/wx/rwx, octal 1/3/5/7) are rejected — x cannot be set; it is always on and only shown in the label.",
            "The operation only tightens: the new set must be a subset of the child session's current effective set. Use it to lock a spawned subagent down when delegating risky work.",
            "sessionID must name a direct child session of this session.",
          ].join("\n"),
          input: {
            type: "object",
            properties: {
              permission: {
                type: "string",
                description: "Permission ceiling for the child session: 'ro'/4, 'rw'/6, 'w'/2, or 'none'/0.",
              },
              sessionID: {
                type: "string",
                description: "Direct child session ID (ses_...) of the subagent to restrict.",
              },
            },
            required: ["permission", "sessionID"],
          },
          execute: (input: unknown, context: { sessionID: string }) =>
            Effect.gen(function* () {
              const args = input as Record<string, unknown>
              const rawPerm = args.permission
              const perm = typeof rawPerm === "string" || typeof rawPerm === "number"
                ? parsePerm(String(rawPerm))
                : undefined
              if (!perm) {
                return yield* Effect.fail(
                  rejectionError(`Invalid permission "${String(rawPerm)}" (expected ro/4, rw/6, w/2, or none/0 — x cannot be set; it is always on and only shown in the label)`),
                )
              }
              const callerID = context.sessionID
              const targetID = typeof args.sessionID === "string" ? args.sessionID.trim() : ""
              if (!targetID) {
                return yield* Effect.fail(
                  rejectionError("sessionID is required: name the direct child session (ses_...) to restrict"),
                )
              }

              let failure: string | undefined
              // Structural direct-child check: the parent link recorded at
              // session.created, falling back to a live session lookup so a
              // child created before plugin load is still verifiable. Every
              // other target — the caller itself, grandchildren, unknown
              // sessions — fails closed.
              if (permParent.get(targetID) === callerID) {
                // verified child
              } else {
                const info = yield* Effect.tryPromise({
                  try: () => run(ctx.session.get({ sessionID: targetID })),
                  catch: () => undefined,
                }).pipe(Effect.orElseSucceed(() => undefined))
                const parentID =
                  info && typeof info === "object" && typeof (info as { parentID?: unknown }).parentID === "string"
                    ? (info as { parentID: string }).parentID
                    : undefined
                if (parentID !== callerID) {
                  failure = `Session ${targetID} is not a direct child of this session`
                } else {
                  permParent.set(targetID, callerID)
                }
              }
              if (failure === undefined) {
                const result = writeSessionPerm(targetID, perm, false)
                if (!result.ok) failure = result.error
              }
              if (failure) {
                return yield* Effect.fail(rejectionError(failure))
              }
              return {
                content: [
                  {
                    type: "text",
                    text: `Child session ${targetID} permission tightened to ${permLabel(effectivePerm(targetID))}.`,
                  },
                ],
                metadata: { sessionID: targetID, permission: permLabel(effectivePerm(targetID)) },
              }
            }),
        })
      })
    }

    // Extend the built-in subagent tool with an optional `permission` arg so
    // `subagent({ permission: "ro", ... })` spawns an already-clamped child.
    // Hosts whose editor lacks `update` or whose subagent tool is absent
    // degrade silently to stash-free operation (the execute.before parse
    // still rejects/guards anything the arg would have declared).
    if (ctx.tool.transform && resolved.permission.subagentPermission) {
      yield* ctx.tool.transform((draft) => {
        for (const id of ["subagent"]) {
          try {
            draft.update(id, (tool) => {
              tool.description =
                (tool.description ?? "") +
                "\nOptional `permission` argument ('ro'/4, 'rw'/6, 'w'/2, 'none'/0; x inputs rejected — x cannot be set; it is always on and only shown in the label): clamps the spawned subagent session's r/w ceiling; never widens past the caller's effective permission."
              const input = tool.input
              if (input && typeof input === "object" && !Array.isArray(input)) {
                const schema = input as { type?: string; properties?: Record<string, unknown> }
                if (schema.type === "object" && schema.properties && typeof schema.properties === "object") {
                  schema.properties.permission = {
                    type: "string",
                    description:
                      "Permission ceiling for the spawned session ('ro'/4, 'rw'/6, 'w'/2, 'none'/0; x inputs rejected — x cannot be set; it is always on and only shown in the label). Can only tighten.",
                  }
                }
              }
            })
          } catch {
            // update() may throw when the built-in tool is absent.
          }
        }
      })
    }

    // --- 8f. /perm server command --------------------------------------------
    // User authority: may tighten or widen the target's baseline; the
    // ancestor chain still caps the effective set, and an explicit sessionID
    // must name a descendant. Arguments never reach the model; invalid input
    // fails the command (the TUI turns it into a usage toast). Transitions
    // notify via the synthetic agent reminder and the RPC `permission` event.
    yield* ctx.command.transform((draft) => {
      draft.add({
        name: "perm",
        description:
          "Set this session's permission ceiling: /perm <r|ro|4|w|2|rw|6|none|0> or bit ops +r -r +w -w +rw -rw [sessionID] — user authority (may widen; ancestors still cap)",
        execute: (input) =>
          Effect.gen(function* () {
            const sessionID = input.sessionID
            const tokens = (input.prompt?.text ?? "").split(/\s+/).filter(Boolean)
            const usage =
              "Usage: /perm <r|ro|4|w|2|rw|6|none|0> or bit ops +r -r +w -w +rw -rw [sessionID] — x cannot be set; it is always on and only shown in the label; /perm rw restores full read/write."
            if (tokens.length === 0) {
              return yield* Effect.fail(new Error(usage))
            }
            // Bit ops start from the session's OWN baseline (entry or the
            // configured default), never the effective set: the ancestor cap
            // still applies on top, exactly like the absolute form.
            let target = sessionID
            let working: Perm | undefined
            let sawPerm = false
            for (const token of tokens) {
              const lower = token.toLowerCase()
              if (/^[+-][rwx]+$/.test(lower)) {
                if (lower.includes("x")) {
                  return yield* Effect.fail(
                    new Error("x cannot be set; it is always on and only shown in the label."),
                  )
                }
                if (working === undefined) working = { ...(sessionPerms.get(target) ?? resolved.permission.defaultPerm) }
                const set = lower[0] === "+"
                if (lower.includes("r")) working.r = set
                if (lower.includes("w")) working.w = set
                sawPerm = true
                continue
              }
              const absolute = parsePerm(token)
              if (absolute) {
                if (sawPerm && working !== undefined) {
                  // Mixed absolute+ops: the last operation wins, applied in order.
                  working = absolute
                } else {
                  working = absolute
                }
                sawPerm = true
                continue
              }
              if (/^[+-]?.*x.*$/i.test(token) && !sawPerm) {
                return yield* Effect.fail(
                  new Error("x cannot be set; it is always on and only shown in the label."),
                )
              }
              // Anything else is a candidate sessionID.
              target = token
            }
            if (!sawPerm || working === undefined) {
              return yield* Effect.fail(new Error(usage))
            }
            if (target !== sessionID && !isPermDescendant(sessionID, target)) {
              return yield* Effect.fail(new Error(`Session ${target} is not a descendant of this session`))
            }
            const result = writeSessionPerm(target, working, true)
            if (!result.ok) {
              return yield* Effect.fail(new Error(result.error ?? "Permission could not be applied"))
            }
          }),
      })
    })

    // --- 8d. /bypass server command (formerly /bypass-classifier) -----------
    // Server-registered slash command: the TUI autocomplete lists it and
    // submission routes through client.api.session.command, so the arguments
    // never reach the model. State changes live only in this plugin process
    // (see bypassLeases). Invalid input fails the command, which the TUI turns
    // into an error toast carrying the usage. The agent is told of effective-set
    // transitions via an appended synthetic user message (except the `slow`
    // category, which never notifies the agent); the user, via the RPC event.
    //   /bypass <cat...>  arm categories (additive; space or comma separated)
    //   /bypass *         arm every category in BYPASS_CATEGORIES
    //   /bypass all       session kill switch: ALL plugin enforcement off
    //   /bypass off       clear the session's lease, including the kill switch
    yield* ctx.command.transform((draft) => {
      draft.add({
        name: "bypass",
        description:
          `Toggle/arm bypass categories for this session (${BYPASS_CATEGORIES.join("|")}; legacy: fs=filesystem, os=host+privilege+indirection, web=network+remote; '*'|all=all categories, uppercase ALL=kill switch that disables all plugin enforcement — prefer specific categories when possible, off/0=clear; +token arms, -token disarms, bare token toggles)`,
        execute: (input) =>
          Effect.gen(function* () {
            const sessionID = input.sessionID
            const args = parseBypassArguments(input.prompt?.text ?? "")
            if (args.invalid.length > 0) {
              return yield* Effect.fail(new Error(bypassUsage(args.invalid)))
            }
            // Snapshot BEFORE mutating: bare tokens toggle against this state,
            // and the user toast's armed/updated label reflects it too.
            const snapshot = activeBypass(sessionID)
            const snapshotAll = allBypassed(sessionID)
            const wasActive = snapshot.size > 0 || snapshotAll
            let reason = "status"
            for (const op of args.ops) {
              if (op.kind === "clear") {
                // Clearing removes the whole lease: categories AND the ALL
                // kill switch.
                if (bypassLeases.delete(sessionID)) reason = "cleared"
                continue
              }
              if (op.kind === "killSwitch") {
                const act = op.action === "toggle" ? (snapshotAll ? "disarm" : "arm") : op.action
                if (act === "arm") armBypassAll(sessionID)
                else {
                  const lease = bypassLeases.get(sessionID)
                  if (lease) bypassLeases.set(sessionID, { ...lease, all: false })
                }
                reason = wasActive ? "updated" : "armed"
                continue
              }
              // Category op: the target set starts from the session's current
              // active set (own lease plus inherited parents) so a second
              // invocation keeps previously armed categories.
              const targets: BypassCategory[] = op.which === "allCategories" ? [...BYPASS_CATEGORIES] : [...op.which]
              const act = op.action === "toggle"
                ? (targets.every((t) => snapshot.has(t)) ? "disarm" : "arm")
                : op.action
              const next = activeBypass(sessionID)
              if (act === "arm") for (const c of targets) next.add(c)
              else for (const c of targets) next.delete(c)
              armBypassLease(sessionID, next)
              reason = wasActive ? "updated" : "armed"
            }
            syncAgentReminder(sessionID)
            if (!allBypassed(sessionID)) syncPermReminder(sessionID)
            emitBypassChanged(sessionID, reason)
          }),
      })
    })

    // Clear in-memory caches when the plugin scope finalizes (unload). The
    // forked event fiber is interrupted by the same scope close.
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        sessions.clear()
        dynamicAllowCache.clear()
        dynamicDenyCache.clear()
        inflightReviews.clear()
        sessionDirectories.clear()
        bypassLeases.clear()
        bypassParent.clear()
        announcedBypass.clear()
        announcedAll.clear()
        sessionPerms.clear()
        permParent.clear()
        permStash.clear()
        permBoundChildren.clear()
        permKnownRoots.clear()
        permUnresolved.clear()
        announcedPerm.clear()
        escalationFailures.clear()
        escalationPending.clear()
        escalationGuideShown.clear()
        sandboxMarkers.clear()
        bypassRpc = undefined
      }),
    )
  }),
}

export default plugin
export { classifyShellCommand, verifyScriptFingerprints } from "./security/classifier"
export { reviewCommandWithAuditor, reviewCommandWithAuditor as reviewCommandWithDeepSeek } from "./security/reviewer"
export { resolvePluginConfig, resolveSandbox } from "./config"
export {
  applySandboxCreateBefore,
  assertSandboxAvailable,
  buildSandboxSpawn,
  commandNeedsOsPrivilege,
  createSandboxMarkers,
  DEFAULT_SANDBOX_HELPER,
  extractSandboxMarker,
  insertSandboxMarker,
  parseSandboxProbe,
  probeLinuxSandbox,
  profileForPerm,
  sandboxDenyCommand,
  sandboxUnavailableMessage,
  stripSandboxMarker,
  wrapShellForSandbox,
} from "./sandbox"
export type {
  SandboxMarkers,
  SandboxProbeResult,
  SandboxProfile,
  SandboxSelection,
  SandboxSpawnSpec,
} from "./sandbox"
export {
  DEFAULT_ACTION_PERM,
  PERM_FULL,
  PERM_NONE,
  parsePerm,
  permIntersect,
  permLabel,
  permSubset,
  fallbackPermBit,
  requiredPermBit,
  tightenPerm,
} from "./permissions"
export type { Perm } from "./permissions"
export type {
  BashClassifierOptions,
  BypassCategory,
  FailPolicy,
  ResolvedDynamicReview,
  ResolvedPluginConfig,
  ResolvedSandbox,
  SandboxMode,
  SandboxOnUnavailable,
  SandboxOptions,
  Strictness,
} from "./config"
export type {
  ClassifyShellCommandInput,
  DirectoryEntryReviewContext,
  LocalScriptReviewContext,
  ScriptFingerprint,
  SecurityVerdict,
  StaticReviewContext,
  StaticSecurityDecision,
  TargetDirectoryReviewContext,
} from "./security/classifier"
export type {
  CloudReviewDecision,
  CloudReviewRequest,
  CloudReviewResult,
  PreviousFailedCommand,
  PreviousRejectedCommand,
  ReviewCommandOptions,
} from "./security/reviewer"
export {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_FORMAT_GUIDE,
  ESCALATION_MARKER,
  ESCALATION_RESERVED_PREFIX,
  JUSTIFICATION_HEADER_PREFIX,
  MAX_JUSTIFICATION_LENGTH,
  parseEscalation,
} from "./security/escalation"
export type {
  EscalationFailureCode,
  EscalationParseResult,
  EscalationRequest,
  EscalationStatus,
} from "./security/escalation"
export {
  escalationCommandsAreSimilar,
  escalationContextFromMessages,
  findSimilarFailedEscalation,
  normalizedEscalationTokens,
} from "./security/escalation-state"
export type { EscalationContextMessage, FailedEscalationRecord } from "./security/escalation-state"
export {
  bundledEscalationReviewerPath,
  createEscalationReviewLimiter,
  EscalationReviewError,
  parseEscalationReviewOutput,
  resetEscalationReviewLimiter,
  reviewEscalation,
  setEscalationReviewLimiter,
} from "./security/escalation-reviewer"
export type {
  EscalationReviewDecision,
  EscalationReviewErrorKind,
  EscalationReviewLimiter,
  EscalationReviewOptions,
  EscalationReviewPermissionScope,
  EscalationReviewRequest,
  PreviousFailedEscalation,
  RollingEscalationReviewLimiterOptions,
} from "./security/escalation-reviewer"

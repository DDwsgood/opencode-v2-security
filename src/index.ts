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
//   6. HARD policy + abort  v1 client.session.abort   -> REMOVED entirely: a single LOOSE
//        policy remains (config rejects strictness != "LOOSE"), so there is no
//        bypassing interrupt, no rejection-forcing state, and no legacy static
//        DENY/dynamic-review/escalation pipeline — admission is static ALLOW
//        (terminal) or JEV effects review inside the native tool wrapper only.
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
import { realpathSync } from "node:fs"
import { access, appendFile, lstat, mkdir, readFile } from "node:fs/promises"
import { homedir, release as osRelease } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect, Latch, Stream } from "effect"
import type { Plugin } from "@opencode-ai/plugin/effect/plugin"
import type { Scope } from "effect"
import { resolveClassifierShell } from "./shell-dialect"
import { failureOrPass, SecurityCheckFailure } from "./failure-policy"
import { BypassRpc } from "./bypass-rpc"
import {
  BoundaryPreparationError,
  boundarySessionContext,
  canonicalBoundaryPath,
  containsPath,
  isBoundaryTool,
  nativeAbsolutePath,
  planFileBoundary,
  planShellBoundary,
  verifyFileBoundaryPlan,
  type BoundaryInvocation,
  type FileBoundaryPlan,
  type NativeBoundaryTool,
  type ShellBoundaryPlan,
} from "./tool-boundary"
import {
  PERM_FULL,
  parsePerm,
  parseSecurityMode,
  permEqual,
  permForMode,
  permIntersect,
  permLabel,
  requiredPermBit,
  securityModeFor,
  securityModeLabel,
  tightenPerm,
  type Perm,
  type SecurityMode,
} from "./permissions"
import {
  BYPASS_CATEGORIES,
  STATIC_BYPASS_CATEGORIES,
  expandBypassCategoryToken,
  resolvePluginConfig,
  type BashClassifierOptions,
  type BypassCategory,
} from "./config"
import { classifyBoundaryCommand, classifyShellCommand, type StaticSecurityDecision } from "./security/classifier"
import { isFloorRule } from "./security/bypass"
import {
  adjudicateEffectAnswers,
  EFFECTS_POLICY_VERSION,
  EFFECTS_POLICY_VERSION_READONLY,
  EffectsReviewError,
  resolveUncollectableEffects,
  reviewEffects,
  type EffectReviewRequest,
  type EffectReviewResult,
} from "./security/effects-reviewer"
import type { CloudReviewResult } from "./security/reviewer"
import { analyzeSlowCommand } from "./security/slow-command"
import {
  applySandboxCreateBefore,
  DEFAULT_BOUNDARY_WATCH_HELPER,
  createSandboxMarkers,
  extractSandboxMarker,
  insertSandboxMarker,
  probeLinuxSandbox,
  type SandboxProbeResult,
} from "./sandbox"
import { createSessionStateNotices } from "./session-notifications"
import {
  getSharedSecurityState,
  securityLocationKey,
  type LocationSecurityPolicy,
  type BypassLease,
  type PermStashEntry,
  type SharedStateEvent,
} from "./security/shared-state"
import { linkedWorktreePrivateDir } from "./security/worktree-roots"
import { globalTempWriteRoots, incidentalWriteRoots, isIncidentalToolWrite, standardCacheWriteRoots } from "./security/automatic-write-roots"
import { checkPathSensitivity, credentialStoreReadPaths } from "./security/paths"
import { writeRootRejection, writeTargetExempt, type WriteRootPolicy } from "./security/write-root-policy"
import { createRootWidening, reviewRootWidening, L3_POLICY_VERSION, type L3Trace, type RootWideningContext, type RootWideningInput, type RootWideningScope } from "./security/root-widening"
import { boundaryCoreDigest, observedNetworkEndpoint, type ApprovalCacheFacts, type ApprovalCacheScope, type ApprovalCacheTarget } from "./security/approval-cache"
import { createRuntimeBoundaryBroker, currentCacheTargets, targetIdentitiesMatch, runtimeWriteEffect, staticCrossingReview, type RuntimeBoundaryBroker, type RuntimeBoundaryEvent } from "./runtime-boundary"
import { inspectRegularTextFileSync, inspectionErrorCode } from "./security/inspection"
import { createSingleFlight } from "./security/single-flight"
import {
  accessErrorNote,
  CANCEL_ADVICE,
  cancelledText,
  checkUnavailableReason,
  runtimeBlockedText,
  runtimeBoundaryTrigger,
  nativeActionTrigger,
  type RuntimeBlockDetails,
  actionBlockedText,
  actionBeforeText,
  blockedText,
  permissionChangeRejectedText,
  RECHECK,
  RETRY_LATER,
  reviewRefusal,
  reviewUnavailableReason,
  WITHIN_MODE,
  subagentBlockedText,
} from "./agent-messages"
import { reportKeyPayload } from "./security/assessment"
import { collectBoundedEvidence } from "./security/automatic"

// Package root, derived from this module's own URL so relative paths (native
// supervisor, auditor) resolve no matter where the plugin is installed from.
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const PROMPT_VERSION = "v7-execution-scope"

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
    // Mutable: the host reads it back after the hook (tool result channel).
    content?: unknown
    readonly metadata?: Record<string, unknown>
  }
  readonly error?: unknown
}

const notYetCreated = Symbol("session not yet created")

/** The content parts the host would derive from a completed result (its
 *  normalizeContent): an absent or empty content falls back to the output. */
function toolResultContent(result: NonNullable<ExecuteAfterEvent["result"]>): unknown[] {
  const { content, output } = result
  if (typeof content === "string") return [{ type: "text", text: content }]
  if (Array.isArray(content) && content.length > 0) return [...content]
  let text: string
  if (typeof output === "string") text = output
  else {
    try {
      text = JSON.stringify(output) ?? String(output)
    } catch {
      text = String(output)
    }
  }
  return [{ type: "text", text }]
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

// Pre-execution refusals share one envelope so the agent always learns two
// facts: the call was blocked, and nothing of it ran. This shape is ONLY for
// denials raised before the original executor starts (boundary preflight,
// permission hook, argument validation) — errors that surface after launch
// (OS access failures, tool-internal errors) keep their raw message and must
// never claim "the whole command was not run". The wording lives in
// agent-messages.ts (blockedText).
function blockedRejection(reason: string, advice?: string): Error & { readonly _tag: "Tool.Error" } {
  return rejectionError(blockedText(reason, advice))
}

// `Effect.tryPromise`'s `catch` must always return the same shape. The
// execute.before / wrapper bodies already throw a Tool.Error-shaped error for
// every deliberate block, so a thrown Tool.Error-shaped value is passed
// through unchanged; any other thrown value (an unexpected non-block
// exception raised during preflight) is normalized into the same "Command
// blocked" envelope so the host's `catchTag("Tool.Error")` still routes it to
// a tool-call error instead of a step-killing defect.
function toRejection(error: unknown): Error & { readonly _tag: "Tool.Error" } {
  if (error instanceof SecurityCheckFailure) return blockedRejection(checkUnavailableReason(error.code), RETRY_LATER)
  if (error instanceof Error && (error as { _tag?: string })._tag === "Tool.Error") {
    return error as Error & { readonly _tag: "Tool.Error" }
  }
  // Some pre-spawn helpers return the same centralized text as a plain
  // Error (their API is also used by create.before's deny-command rewrite).
  if (error instanceof Error && error.message.startsWith("Command blocked: ") &&
    error.message.includes("The whole command was not run.")) {
    return rejectionError(error.message)
  }
  // A boundary-prep drift is a typed source, not an internal failure: the
  // agent-facing reason comes from the error (changed → resubmit advice).
  if (error instanceof BoundaryPreparationError) {
    return blockedRejection(error.agentReason, error.changed ? RECHECK : undefined)
  }
  if (error instanceof EffectsReviewError) {
    if (error.kind === "aborted") return rejectionError(cancelledText())
    return blockedRejection(reviewUnavailableReason(error.kind), RETRY_LATER)
  }
  return blockedRejection(checkUnavailableReason("check_unavailable"), RETRY_LATER)
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

function softSlowMessage(reason: string) {
  // This interception happens before launch too. The reason may suggest a
  // cheaper equivalent, but must not imply the original command ran.
  return blockedRejection(conciseReason(reason, 300))
}

// --- small helpers ----------------------------------------------------------

function commandFromArgs(args: unknown) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return
  const command = (args as Record<string, unknown>).command
  return typeof command === "string" ? command : undefined
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
 * Cache keys are SESSION-PARTITIONED (the payload carries sessionID): the
 * payload also carries every security-relevant context (script, cwd, shell,
 * static rules, script fingerprints, target-directory listings, referenced
 * paths, strictness, endpoint, model, prompt version, bypass categories),
 * and cached entries are only written for non-forced LOOSE reviews. A report
 * authored in one session never admits a call in another — `get` re-checks
 * report.sessionID as defense-in-depth on top of the key partition. A
 * shorter TTL bounds staleness.
 */
export function dynamicAllowCacheKey(
  sessionID: string,
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

  const payload = reportKeyPayload({
    sessionID,
    script: normalizeCacheKeyScript(script),
    cwd,
    shell,
    rules: decision.rules,
    fingerprints: decision.fingerprints,
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
  })
  const digest = createHash("sha256").update(JSON.stringify(payload)).digest("hex")
  return digest
}

// Categories a reviewer may report: the seven static names plus the sandbox
// layer category (same set reviewer.ts accepts on the wire contract).
const REVIEW_RESULT_CATEGORIES = new Set<string>([...STATIC_BYPASS_CATEGORIES, "sandbox"])
const REVIEW_RESULT_KEYS = new Set([
  "decision",
  "categories",
  "secondary_categories",
  "bypassing",
  "reason",
  // Upgraded structured contract: `assessment` carries the strong-reason
  // footprint, needsEvidence and decision provenance; `needs_evidence` is
  // the tolerated legacy alias folded into it.
  "assessment",
  "needs_evidence",
  // The upgraded reviewer contract may carry an evidence list with a
  // collect_evidence decision; tolerate it here (the host resolves it
  // automatically) so the verdict isn't dropped as a protocol error.
  "evidence_requests",
])

function isValidCategoryList(value: unknown): value is string[] {
  return (
    value === undefined ||
    (Array.isArray(value) && value.every((item) => typeof item === "string"))
  )
}

// The 1.1.0 reviewer output contract: {decision, categories?,
// secondary_categories?, reason?(legacy)}. `reason` is
// tolerated for older auditors but is no longer required; a DENY without a
// usable category falls back to ["indirection"] (mutated onto the record).
// `collect_evidence` is the newer indecision verdict: it validates like a
// DENY shape (categories optional) and is resolved by the automatic
// collection path, never by asking a human.
export function isValidReviewResult(value: unknown, _legacyStrict = false): value is CloudReviewResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  for (const key of Object.keys(record)) {
    if (!REVIEW_RESULT_KEYS.has(key)) return false
  }
  const evidenceVerdict = record.decision === "collect_evidence"
  if (record.decision !== "ALLOW" && record.decision !== "DENY" && !evidenceVerdict) return false
  if (!isValidCategoryList(record.categories) || !isValidCategoryList(record.secondary_categories)) {
    return false
  }
  if (record.evidence_requests !== undefined) {
    const requests = record.evidence_requests
    const ok =
      Array.isArray(requests) &&
      requests.every(
        (item) =>
          typeof item === "string" ||
          (item !== null &&
            typeof item === "object" &&
            typeof (item as { subject?: unknown }).subject === "string"),
      )
    if (!ok) return false
  }
  if (record.reason !== undefined && typeof record.reason !== "string") return false
  // The former strict-policy field no longer selects or validates a policy.
  delete record.bypassing
  // `assessment` must be an object when present (reviewer.ts synthesizes a
  // default when absent); a non-object value is a protocol error.
  if (
    record.assessment !== undefined &&
    (typeof record.assessment !== "object" || record.assessment === null || Array.isArray(record.assessment))
  ) {
    return false
  }

  // Normalize: strip unknown/duplicate category names (a bad hint degrades
  // to "no hint" rather than invalidating the verdict).
  const sanitize = (list: unknown): string[] => {
    const out: string[] = []
    if (Array.isArray(list)) {
      for (const item of list) {
        if (typeof item === "string" && REVIEW_RESULT_CATEGORIES.has(item) && !out.includes(item)) {
          out.push(item)
        }
      }
    }
    return out
  }
  let categories = sanitize(record.categories)
  const secondary = sanitize(record.secondary_categories).filter((category) => !categories.includes(category))
  if ((record.decision === "DENY" || evidenceVerdict) && categories.length === 0) categories = ["indirection"]
  // ALLOW keeps its intrinsic footprint: approval and presence are separate
  // layers (reviewer.ts's parser preserves them too). An ordinary static DENY
  // completion needs the model's primary categories to bill the report's
  // full minimal owner set — wiping them here would silently shrink it.
  record.categories = categories
  if (secondary.length > 0) record.secondary_categories = secondary
  else delete record.secondary_categories
  if (typeof record.reason === "string") {
    const trimmed = record.reason.trim().replace(/\s+/g, " ").slice(0, 80)
    if (trimmed && record.decision === "DENY") record.reason = trimmed
    else delete record.reason
  }
  return true
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
     *  context for effects reviews. Optional so older hosts still load the
     *  plugin — the review then fails closed instead of allowing blind. */
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
    /** Session hooks (packages/plugin/src/effect/session.ts). Only "prompt"
     *  is used: it runs while the host prepares a real user prompt, before
     *  that prompt is admitted. Optional so older hosts still load. */
    readonly hook?: (
      name: "prompt",
      callback: (event: { readonly sessionID: string; readonly delivery?: string }) => Effect.Effect<void, never>,
    ) => Effect.Effect<unknown, never, Scope.Scope>
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
  id?: string
  name?: string
  description?: string
  input?: unknown
  options?: Record<string, unknown>
  execute?: (input: unknown, context: BoundaryInvocation) => Effect.Effect<unknown, unknown>
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
  readonly source?: { type: "tool"; messageID: string; id: string }
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
  for (const warning of resolved.dynamicReviewWarnings) {
    console.warn(`[opencode-v2-security] ${warning}`)
  }
  for (const warning of resolved.sandbox.allowWriteWarnings) {
    console.warn(`[opencode-v2-security] ${warning}`)
  }
  if (resolved.failPolicy === "fail_open" && resolved.sandbox.onUnavailable === "fail_close") {
    console.warn('[opencode-v2-security] failPolicy=fail_open overrides sandbox.onUnavailable=fail_close: unavailable checks run without the observer/sandbox (degrade).')
  }
  const configuredShell = resolved.shell
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
          (resolved.failPolicy === "fail_open" || resolved.sandbox.onUnavailable === "degrade"
            ? "onUnavailable=degrade: calls that still use the sandbox run classifier-only"
            : "onUnavailable=fail_close: read-only calls that still require the OS sandbox " +
              "will be denied; reviewed read-write calls run host-direct " +
              "and are unaffected"),
      )
    }
  }
  return {
    resolved,
    configuredShell,
    sandboxProbe,
  }
}

const plugin: Plugin = {
  id: "opencode-v2-security",
  effect: (ctx: EffectPluginContext) => Effect.gen(function* () {
    // This backend is deliberately Linux-only. Do not register hooks,
    // commands, permission tools, or Windows supervisor behavior elsewhere.
    if (process.platform !== "linux") return
    // Capture the ambient context so `ctx.session.*` Effects (which need host
    // services despite their narrowed plugin-facing type) run with those
    // services — a bare `Effect.runPromise` would lose them. Mirrors the
    // promise adapter's `Effect.runPromiseWith(context)` bridge. effect 4 has
    // no `Effect.runtime`/`Runtime.runPromise`; context capture is the beta
    // API for this.
    const context = yield* Effect.context<never>()
    const run = <A>(effect: Effect.Effect<A, unknown>, signal?: AbortSignal): Promise<A> =>
      Effect.runPromiseWith(context)(effect as Effect.Effect<A, unknown, never>, signal ? { signal } : undefined)

    // The ambient Scope may belong to a different effect build than the one
    // bundled here (the host ships its own): some builds keep a scope's first
    // finalizer as `{finalizerKey, finalizer}` and only promote to a
    // `finalizers` Map on the second add, while this build dereferences
    // `state.finalizers` unconditionally. Normalize once up front so every
    // addFinalizer/forkScoped/acquireRelease below (and inside the plugin SDK
    // helpers we yield*) sees the Map shape both builds understand.
    const ambientScope = yield* Effect.serviceOption(Effect.scope)
    if (ambientScope._tag === "Some") {
      const state = (ambientScope.value as Scope.Scope & { state?: Record<string, unknown> }).state
      if (state && state._tag === "Open" && !(state.finalizers instanceof Map)) {
        state.finalizers = state.finalizer !== undefined ? new Map([[state.finalizerKey, state.finalizer]]) : new Map()
        state.finalizerKey = state.finalizer = undefined
      }
    }

    const {
      resolved,
      configuredShell,
      sandboxProbe,
    } = yield* Effect.promise(() => resolveStartup(ctx.options))

    // --- process-wide shared security state ----------------------------------
    // The host loads one plugin instance per session location, all inside the
    // SAME server process. Every piece of USER-AUTHORITY / SESSION-SECURITY
    // state lives in one registry on globalThis (see security/shared-state.ts)
    // so a bypass armed in the main session reaches subagents served by other
    // instances, and a location re-boot reloads into the existing state.
    // Only genuinely instance-bound resources (ctx handles, brokers, RPC,
    // timers, in-flight review single-flights) stay in this closure.
    const shared = getSharedSecurityState()
    const instanceToken = Symbol("opencode-v2-security.instance")
    const instancePolicy: LocationSecurityPolicy = {
      defaultPerm: resolved.permission.defaultPerm,
      permanentBypass: [...resolved.bypassClassifier],
      propagateBypass: resolved.bypassPropagateToSubagents,
      failPolicy: resolved.failPolicy,
      sandboxEnabled: resolved.sandbox.enabled,
      sandboxFull: resolved.sandbox.mode === "full",
    }
    const instanceLocation = ctx.location
    const registerPolicy = (location: { directory: string; workspaceID?: unknown }) => {
      shared.registerLocationPolicy(securityLocationKey(location), instanceToken, instancePolicy, () => {
        console.warn("[opencode-v2-security] conflicting security policies for one location; the restrictive intersection is retained")
      })
    }
    if (instanceLocation?.directory) registerPolicy(instanceLocation)
    function policyForSession(sessionID: string): LocationSecurityPolicy {
      const home = shared.sessionLocations.get(sessionID)
      return home === undefined ? instancePolicy : shared.policyForLocation(home)
    }
    function bindSessionHome(sessionID: string, info: { location?: { directory?: unknown; workspaceID?: unknown } }) {
      if (typeof info.location?.directory !== "string") return
      const location = { directory: info.location.directory, workspaceID: info.location.workspaceID }
      shared.sessionLocations.set(sessionID, securityLocationKey(location))
      // Injected hosts may expose their location only on session records.
      if (!instanceLocation?.directory) registerPolicy(location)
    }
    yield* Effect.addFinalizer(() => Effect.sync(() => shared.unregisterLocationPolicy(instanceToken)))

    // --- append-only user-role state notices --------------------------------
    // No session.context hook and no system/history mutation. A mode change
    // is only recorded; it becomes a durable transcript item right before the
    // next real user prompt, so it never starts a model request of its own.
    // The snapshot store is shared across instances: whichever instance
    // handles the session's prompt hook / tool result delivers it once.
    const sessionNotices = createSessionStateNotices(
      (notice) => run(ctx.session.synthetic(notice)),
      shared.notices,
    )
    if (ctx.session.hook) {
      // Re-verify the ancestry first: an earlier lookup may have failed
      // transiently (or run before the session existed server-side), and its
      // stale "verification unavailable" notice must not ride this prompt.
      yield* ctx.session.hook("prompt", (event) =>
        Effect.promise(async () => {
          await hydratePermAncestry(event.sessionID)
          await sessionNotices.deliverWithPrompt(event.sessionID, event.delivery)
        }))
    }

    // --- temporary bypass state (fixed-expiry lease) ------------------------
    // In-memory by design: a service restart clears every lease. `expiresAt`
    // is an absolute deadline set at arm time — a user-supplied timeout of
    // 120 means the bypass lapses 120 seconds later; activity never extends
    // it. A timeout <= 0 arms a lease that never expires on its own (only
    // `/bypass off`, session deletion, or a service restart ends it).
    // Subagent children inherit the armed categories so a bypass armed on
    // the root session covers its spawned subagents doing the actual shell
    // work.
    const bypassLeases = shared.bypassLeases
    // child → parent links (session lifetime, NOT lease lifetime): written on
    // session.created, cleared on session.deleted only.
    const bypassParent = shared.bypassParent
    // Assigned once the RPC in section 8b is registered.
    let bypassRpc:
      | { readonly events: { readonly emit: (...args: unknown[]) => Effect.Effect<void, unknown> } }
      | undefined

    // --- session rwx permission layer ---------------------------------------
    // Tighten-only capability ceiling: a session's baseline {r,w,x} intersects
    // with every ancestor baseline (missing = configured default = rwx). All
    // mutation paths except the user-side /perm clamp the new
    // baseline to the session's effective set, so sessions can only lose
    // capability. State is server-memory only; nothing enters model context.
    const sessionPerms = shared.sessionPerms
    // Immutable ancestry, hydrated at execution boundaries or via events.
    const permParent = shared.permParent
    // Declared permission waiting for an authoritative execute.after childID.
    // `declared` marks a real agent-supplied ceiling (vs. the default
    // PERM_FULL bookkeeping entry) — a declared child may not inherit an
    // ancestor's Bypass mode.
    const permStash = shared.permStash
    // session.created observation times: a pending stash entry can only
    // belong to a child created after it was recorded (entry.at <=
    // createdAt). An unknown creation time applies every entry
    // (conservative tightening).
    const permCreatedAt = shared.permCreatedAt
    const permBoundChildren = shared.permBoundChildren
    const permKnownRoots = shared.permKnownRoots
    const permUnresolved = shared.permUnresolved
    /** Per-level inheritance barrier against Bypass mode: sessions whose
     *  non-Bypass surface was explicitly asserted — by an agent declaration
     *  (subagent `permission`, set_permission) OR by the user's own
     *  Auto/ReadOnly/perm selection. allBypassed walks the ancestor chain
     *  level by level; a barrier level stops the walk, so a barriered parent
     *  also shields its whole subtree from an armed grandparent kill switch.
     *  The user's own armed lease on the barriered session still wins (own
     *  lease is checked first) — the barrier is never deleted, so expiry
     *  falls back to the declared mode, never to an ancestor's Bypass. */
    const explicitNoBypass = shared.explicitNoBypass

    // --- cross-instance change propagation -----------------------------------
    // Every instance in this process shares the registry above. When ANY
    // instance changes a session's state, the others must react exactly as
    // the mutating instance does for its own descendants: refresh the merged
    // notice (which also revokes this instance's running monitored calls and
    // clears the shared approval cache when the security basis moved),
    // re-sync descendants, and re-emit the TUI snapshots through this
    // instance's own RPC channel. Reactions are idempotent — duplicated
    // events only re-derive the same state.
    const unsubscribeSharedState = shared.subscribe((event: SharedStateEvent) => {
      if (event.kind !== "session-state-changed" || event.origin === instanceToken) return
      syncSecurityNotice(event.sessionID)
      syncBypassDescendants(event.sessionID)
      syncPermDescendants(event.sessionID)
      emitBypassChanged(event.sessionID, "updated")
      emitPermChanged(event.sessionID, "updated")
    })

    /** Tell every other instance that this instance changed `sessionID`'s
     *  security state. Called AFTER the local sync, so the mutating
     *  instance's own transition is never reordered behind the bus. */
    function publishSharedStateChange(sessionID: string) {
      shared.publish({ kind: "session-state-changed", sessionID, origin: instanceToken })
    }

    // Session.get reads the durable record, unlike the asynchronous event
    // consumer. Cache immutable ancestry only; failed reads are retried on the
    // next boundary. An incomplete/cyclic chain loses writes, not RO reads.
    async function hydratePermAncestry(sessionID: string, now?: number): Promise<void> {
      const seen = new Set<string>()
      let cursor: string | undefined = sessionID
      try {
        while (cursor) {
          if (seen.has(cursor) || seen.size >= 64) throw new Error("Invalid session ancestry")
          seen.add(cursor)
          if (permKnownRoots.has(cursor) && shared.sessionLocations.has(cursor)) break
          let parent = permParent.get(cursor)
          if (!parent || !shared.sessionLocations.has(cursor)) {
            const lookup = cursor
            const info = await run(ctx.session.get({ sessionID: lookup }).pipe(Effect.timeout("2 seconds"))).catch((error) => {
              // The TUI creates sessions optimistically and pulls their status
              // before the server has the record. A session that does not
              // exist yet has no ancestry to fail: retry on the next boundary.
              if (lookup === sessionID && seen.size === 1 && (error as { _tag?: unknown })?._tag === "Session.NotFoundError") {
                return notYetCreated
              }
              throw error
            })
            if (info === notYetCreated) return
            if (!info || typeof info !== "object") throw new Error("Missing session record")
            bindSessionHome(cursor, info)
            const value = (info as { parentID?: unknown }).parentID
            if (value != null && (typeof value !== "string" || !value)) throw new Error("Invalid parentID")
            parent = typeof value === "string" ? value : undefined
            if (parent) permParent.set(cursor, parent)
            else permKnownRoots.add(cursor)
          }
          if (parent) bypassParent.set(cursor, parent)
          cursor = parent
        }
        for (const id of seen) permUnresolved.delete(id)
      } catch {
        permUnresolved.add(sessionID)
        failureOrPass(resolved.failPolicy, "session_ancestry", writeReviewerTrace)
      }
      // Discovering inheritance (or resolving a previously unknown chain) is
      // itself a state transition. Append its notice, never edit model context.
      syncSecurityNotice(sessionID, now)
    }

    /** Effective permission includes ancestor baselines and temporary spawn
     * declarations. Boundaries hydrate ancestry before relying on this value.
     * Expired bypass leases are pruned first: a lapsed Bypass lease must not
     * leave its lifted baseline in force until the next sweep. `now` is the
     * shared clock capture used by RPC snapshots — one payload always
     * describes one instant. */
    function effectivePerm(sessionID: string, now: number = Date.now()): Perm {
      pruneExpiredLeases(sessionID, now)
      let perm = { ...PERM_FULL }
      const seen = new Set<string>()
      let cursor: string | undefined = sessionID
      while (cursor && !seen.has(cursor)) {
        seen.add(cursor)
        const policy = policyForSession(cursor)
        perm = permIntersect(perm, policy.defaultPerm)
        // Expire leases along the PERMISSION chain too, not only the bypass
        // chain: with bypassPropagateToSubagents=false the two chains can
        // differ, and a dead ancestor lease's lifted baseline must be
        // restored before it is intersected — shared `now`, no extra reads.
        const lease = bypassLeases.get(cursor)
        if (lease && lease.expiresAt <= now) expireLease(cursor, lease, now)
        const baseline = sessionPerms.get(cursor)
        if (baseline) perm = permIntersect(perm, baseline)
        if (permUnresolved.has(cursor) && policy.failPolicy === "fail_close") perm.w = false
        const parent = permParent.get(cursor)
        // Do not guess which concurrent spawn produced this child. These
        // temporary ceilings disappear when its own call binds
        // authoritatively. Creation time gates applicability: a stash
        // recorded AFTER this child was created belongs to a different
        // spawn and must not tighten it; an unknown creation time
        // intersects every entry (conservative).
        if (parent && !permBoundChildren.has(cursor)) {
          const createdAt = permCreatedAt.get(cursor)
          for (const entry of permStash.values()) {
            if (entry.parentSessionID !== parent) continue
            if (createdAt !== undefined && entry.at > createdAt) continue
            perm = permIntersect(perm, entry.perm)
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
      // treated as unresolved there, so consumers must not see a deeper
      // chain either.
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

    /** Whether any link in the session's permission chain failed to
     *  hydrate (a parent session record the plugin could not verify).
     *  An unresolved chain fails closed — writes stay blocked — but the
     *  state is a temporary verification failure, not a user-selected
     *  [Read only] mode, so notices and denials must say so instead of
     *  claiming a persistent limit. */
    function ancestryUnresolved(sessionID: string): boolean {
      const seen = new Set<string>()
      let cursor: string | undefined = sessionID
      while (cursor && !seen.has(cursor)) {
        if (permUnresolved.has(cursor)) return true
        const home = shared.sessionLocations.get(cursor)
        if (home !== undefined && !shared.locationPolicies.get(home)?.owners.size) return true
        seen.add(cursor)
        cursor = permParent.get(cursor)
      }
      return false
    }

    /** Publish the current effective permission to the append-only notice
     * channel. Thin alias for the merged single-slot notice — see
     * syncSecurityNotice (kept so the many permission-mutation call sites
     * read naturally). */
    function syncPermReminder(sessionID: string) {
      syncSecurityNotice(sessionID)
    }

    /** Report a failed RPC event push. Only the error constructor name and a
     * whitelisted `rpc.<word>` error code are logged — never the raw message,
     * which can echo back arbitrary payload/config detail. */
    function reportRpcEmitFailure(kind: "changed" | "permission", error: unknown) {
      const type = error instanceof Error ? error.name : typeof error
      const code =
        error instanceof Error ? /\brpc\.[a-z0-9_.-]+/i.exec(error.message)?.[0] : undefined
      console.error(
        `[opencode-v2-security] bypass ${kind} event was not delivered (${type}${code ? `, ${code}` : ""})`,
      )
    }

    function emitPermChanged(sessionID: string, reason: string) {
      if (!bypassRpc) return
      // One shared clock capture per payload: mode, ceiling and lease state
      // must describe the same instant (same contract as emitBypassChanged).
      const now = Date.now()
      const effective = effectivePerm(sessionID, now)
      void run(
        bypassRpc.events.emit("permission", {
          sessionID,
          reason,
          permission: permLabel(effective),
          // The user-visible three-way mode; the raw triple stays only for
          // compatibility and is not what the TUI badge renders.
          mode: securityModeFor(effective, allBypassed(sessionID, now)),
        }),
      ).catch((error) => reportRpcEmitFailure("permission", error))
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
      publishSharedStateChange(target)
      return { ok: true }
    }

    // Agent-facing state changes append a user-role notice with resume:false;
    // earlier notices remain chronological history and are never rewritten.

    /** Ancestors of a session (nearest first), bounded by cycle guard. */
    function bypassAncestors(sessionID: string): string[] {
      const chain: string[] = []
      const seen = new Set<string>([sessionID])
      let cursor = policyForSession(sessionID).propagateBypass ? bypassParent.get(sessionID) : undefined
      while (cursor && !seen.has(cursor)) {
        seen.add(cursor)
        chain.push(cursor)
        cursor = policyForSession(cursor).propagateBypass ? bypassParent.get(cursor) : undefined
      }
      return chain
    }

    /** Absolute expiry for a new/updated lease. `timeoutSec` is the optional
     *  /bypass trailing argument in seconds: undefined → the configured
     *  bypassLeaseTtlMs default (0 = no expiry); <= 0 → never expires on its
     *  own (Infinity);
     *  a positive value → exactly now + timeoutSec seconds, clamped to the
     *  safe-integer range so huge values cannot overflow into the past. */
    function bypassExpiry(timeoutSec?: number): number {
      if (timeoutSec !== undefined && timeoutSec <= 0) return Infinity
      const ms = timeoutSec === undefined ? resolved.bypassLeaseTtlMs : timeoutSec * 1000
      if (ms <= 0) return Infinity
      const expiresAt = Date.now() + ms
      return Number.isSafeInteger(expiresAt) ? expiresAt : Number.MAX_SAFE_INTEGER
    }

    /** Effective expiry deadline for RPC payloads: the earliest FINITE live
     *  lease along the session's chain — the active set changes when its
     *  earliest bounded contributor expires, so a never-expiring ancestor
     *  lease must not hide a finite child deadline. null → live lease(s)
     *  exist but none expires on its own; undefined → no live lease.
     *  `now` defaults to the call instant; the RPC status/emit paths pass one
     *  shared capture so every field of a payload describes the same instant. */
    function leaseExpiryForRpc(sessionID: string, now: number = Date.now()): number | null | undefined {
      let earliest: number | undefined
      let unbounded = false
      for (const target of [sessionID, ...bypassAncestors(sessionID)]) {
        const lease = bypassLeases.get(target)
        if (!lease || lease.expiresAt <= now) continue
        if (lease.expiresAt === Infinity) {
          unbounded = true
          continue
        }
        earliest = Math.min(earliest ?? lease.expiresAt, lease.expiresAt)
      }
      if (earliest !== undefined) return earliest
      return unbounded ? null : undefined
    }

    /** Milliseconds until the soonest lease expiry (the next sweep deadline),
     *  capped so expiry is also detected after an unrelated wake. Never-
     *  expiring leases contribute only the cap. */
    const BYPASS_SWEEP_MAX_MS = 20_000
    function nextBypassSweepDelay(): number {
      const now = Date.now()
      let soonest = BYPASS_SWEEP_MAX_MS
      for (const lease of bypassLeases.values()) {
        if (lease.expiresAt === Infinity) continue
        soonest = Math.min(soonest, Math.max(50, lease.expiresAt - now))
      }
      return soonest
    }

    // Opened by lease mutations so the sweep loop re-computes its sleep
    // instead of waiting out the previous (possibly much longer) deadline.
    const bypassSweepWake = Latch.makeUnsafe(false)
    function wakeBypassSweep() {
      Latch.openUnsafe(bypassSweepWake)
    }

    /** Active bypass categories for a session: permanent config set ∪ the
     * union of every live lease along the ancestor chain (the session's own
     * lease plus inherited parent leases). Expired leases are skipped without
     * mutating the map; the sweep removes them. `now` defaults to the call
     * instant; the RPC status/emit paths share one capture across all lease
     * reads in a payload. */
    function activeBypass(sessionID: string, now: number = Date.now()): Set<BypassCategory> {
      const active = new Set<BypassCategory>(policyForSession(sessionID).permanentBypass)
      for (const target of [sessionID, ...bypassAncestors(sessionID)]) {
        const lease = bypassLeases.get(target)
        if (lease && lease.expiresAt > now) for (const category of lease.categories) active.add(category)
      }
      return active
    }

    function activeCustomBypass(sessionID: string, now: number = Date.now()): string[] {
      return [...new Set([sessionID, ...bypassAncestors(sessionID)].flatMap((target) => {
        const lease = bypassLeases.get(target)
        return lease && lease.expiresAt > now ? lease.custom ?? [] : []
      }))]
    }

    /** Whether this (unbound) child is still covered by a parent's pending
     *  declared spawn: a stash entry recorded before this child's creation
     *  is conservatively treated as its declaration until execute.after
     *  binds the authoritative childID. During that window the child must
     *  not inherit an ancestor's Bypass mode either — the pending
     *  declaration is already an inheritance barrier. */
    function pendingDeclaredSpawn(sessionID: string): boolean {
      if (permBoundChildren.has(sessionID)) return false
      const parent = permParent.get(sessionID)
      if (!parent) return false
      const createdAt = permCreatedAt.get(sessionID)
      for (const entry of permStash.values()) {
        if (entry.parentSessionID !== parent || !entry.declared) continue
        if (createdAt === undefined || entry.at <= createdAt) return true
      }
      return false
    }

    /** Whether Bypass mode (the kill switch) is active for a session —
     *  per-level inheritance barrier semantics: walk self → ancestors. A
     *  level's own live `all` lease wins immediately (the user's own arm
     *  always outranks a declared barrier, without deleting it — the
     *  barrier reasserts on expiry). Otherwise an explicit no-Bypass
     *  declaration or a pending declared spawn at that level stops the
     *  walk: nothing above it — a grandparent's armed Bypass included — is
     *  observable through it. Expired leases are pruned first so the
     *  deadline is never observed late. */
    function allBypassed(sessionID: string, now: number = Date.now()): boolean {
      pruneExpiredLeases(sessionID, now)
      for (const target of [sessionID, ...bypassAncestors(sessionID)]) {
        const lease = bypassLeases.get(target)
        if (lease !== undefined && lease.all === true && lease.expiresAt > now) return true
        if (explicitNoBypass.has(target) || pendingDeclaredSpawn(target)) return false
      }
      return false
    }

    /** RPC-facing active list: the real categories plus the literal "all"
     * while the kill switch is armed, so the TUI companion can render the
     * ALL-OFF badge from the same payload. */
    function activeForRpc(sessionID: string, now: number = Date.now()): string[] {
      const active = [...activeBypass(sessionID, now)].sort()
      if (allBypassed(sessionID, now)) active.push("ALL")
      return active
    }

    /** Push a bypass state change to the TUI companion (best effort). The TUI
     * is the only user-visible channel that does not enter the model context. */
    function emitBypassChanged(sessionID: string, reason: string) {
      if (!bypassRpc) return
      // ONE clock read per payload: if a lease crosses its deadline between
      // reads, an `active` list built at t and an `expiresAt` read at t+ε
      // could claim "armed with no lease" — the TUI trusts the snapshot and
      // would show a stale badge until the next event.
      const now = Date.now()
      const permanent = [...policyForSession(sessionID).permanentBypass].sort()
      const active = activeForRpc(sessionID, now)
      const temporary = active.filter((category) => !permanent.includes(category as BypassCategory))
      // expiresAt is optional on the wire: absent = no live lease, null =
      // armed without a natural expiry. Emitting the key with `undefined`
      // fails the host schema's optional-presence check, and the host then
      // drops the whole event — an "off"/"expired" transition would never
      // reach the TUI badge.
      const payload: Record<string, unknown> = {
        sessionID,
        reason,
        mode: securityModeFor(effectivePerm(sessionID, now), allBypassed(sessionID, now)),
        active,
        temporary,
        permanent,
      }
      const custom = activeCustomBypass(sessionID, now)
      if (custom.length > 0) payload.custom = custom
      const expiresAt = leaseExpiryForRpc(sessionID, now)
      if (expiresAt !== undefined) payload.expiresAt = expiresAt
      void run(bypassRpc.events.emit("changed", payload)).catch(
        // A dead TUI channel must not block command handling, but it must not
        // vanish silently either: log the error type/message only (the
        // never log the payload: a custom authorization can contain credentials).
        (error) => reportRpcEmitFailure("changed", error),
      )
    }

    /** The single merged security-state notice: ONE clock capture and ONE
     *  effective-mode computation produce the whole text (the previous
     *  two-slot pair could show ReadOnly and Auto/Bypass simultaneously).
     *
     *  Category handling: only the seven static risk categories are listed
     *  as review authorizations — `dynamic`/`sandbox`/`slow` are extra
     *  layer switches, not effects authorizations. `dynamic` gets its own
     *  line because it switches review off; `sandbox` changes no route
     *  worth announcing (and under an RO cap it is not removed at all);
     *  `slow` never reaches the agent channel. */
    function securityNotice(sessionID: string, now: number = Date.now(), includeDefault = false): string | undefined {
      const policy = policyForSession(sessionID)
      const effective = effectivePerm(sessionID, now)
      const all = allBypassed(sessionID, now)
      const mode = securityModeFor(effective, all)
      const active = activeBypass(sessionID, now)
      const categories = [...active]
        .filter((category) => (STATIC_BYPASS_CATEGORIES as readonly BypassCategory[]).includes(category))
        .sort()
      const dynamic = active.has("dynamic")
      const custom = activeCustomBypass(sessionID, now)
      const authorizationLines = [
        ...(categories.length
          ? [
              `The user authorized these categories for this session: ${categories.join(", ")}. ` +
                "The safety review treats effects in these categories as authorized; all other checks still apply.",
              "You may retry a previously blocked command if these authorizations cover it; " +
                "be careful with your authorized scope and the changes you make.",
            ]
          : []),
        ...(dynamic ? ["- dynamic: commands that are not proven safe run without the safety review."] : []),
        ...(custom.length
          ? [
              "The user also gave these custom authorizations, quoted exactly. They cover only what they state:",
              ...custom,
            ]
          : []),
      ]
      if (mode === "bypass") {
        // Full Bypass skips every check — category/custom authorization
        // notes would be noise (nothing is left for them to authorize).
        return [
          "Security mode: [Bypass mode].",
          "The user temporarily removed security review and OS sandboxing for this session.",
          "You may retry the previously blocked command and continue within the user's authorization; " +
            "be careful with your authorized scope and the changes you make.",
          "Positive timeouts expire at their deadline; zero or negative timeouts have no natural expiry.",
        ].join("\n")
      }
      if (mode === "readonly" && ancestryUnresolved(sessionID)) {
        // A w=false produced by an unverified ancestor chain is a temporary
        // verification failure, not the user's ReadOnly selection — the
        // notice must not claim a persistent limit.
        return [
          "Session permission verification is temporarily unavailable: this session's permission chain could not be verified.",
          "Write actions are blocked for now. This is not a mode the user selected. You may retry later.",
        ].join("\n")
      }
      if (mode === "readonly") {
        const lines = [
          "Security mode: [Read only].",
          effective.r
            ? "You may read files and run shell commands that only read. Do not write, edit, move, or delete " +
              "files with any tool; native write tools and shell commands that may write are blocked."
            : "Native file tools are blocked, including reads. Do not write, edit, move, or delete files " +
              "with any tool; shell commands that may write are blocked.",
          "You cannot change or work around this limit.",
        ]
        // An armed kill switch outranked by the read-only ceiling must say
        // so — otherwise the notice reads like a plain /perm ro.
        if (all) {
          lines.push("Bypass mode was selected, but it does not apply here because the read-only limit takes precedence.")
        }
        if (authorizationLines.length) {
          lines.push(...authorizationLines)
          lines.push("These authorizations do not lift the read-only limit.")
        }
        return lines.join("\n")
      }
      // Auto: a fully default surface stays silent (nothing restricted,
      // nothing bypassed). The default check compares r/w only — x is a
      // display bit no action maps to.
      const isDefault =
        effective.r === policy.defaultPerm.r &&
        effective.w === policy.defaultPerm.w
      if (isDefault && authorizationLines.length === 0 && !includeDefault) return undefined
      const parts = [
        `Security mode: ${securityModeLabel("auto", categories, custom.length > 0)}.`,
        !policy.sandboxEnabled || policy.sandboxFull
          ? "Shell commands run directly on the host."
          : dynamic
            ? "Shell commands run under a runtime observer; the automatic safety review is skipped."
            : "Shell commands run under a runtime observer. An operation that crosses the workspace boundary is checked " +
              "statically first; if that cannot prove it safe, it gets an automatic safety review with no manual approval step.",
        "OS errors such as permission denied are real results, not plugin blocks.",
      ]
      // The only non-default r/w combo that still reads Auto is a
      // write-only ceiling (r=false, w=true) — name the concrete block
      // instead of printing the rwx label.
      if (!effective.r) parts.push("Native file read tools are blocked in this session.")
      parts.push(...authorizationLines)
      return parts.join("\n")
    }

    /** Publish the merged notice into the single `perm` slot (the `bypass`
     *  slot stays cleared so the two slots can never disagree). The notice
     *  channel dedups identical text, so callers can refresh freely. */
    function syncSecurityNotice(sessionID: string, now: number = Date.now()) {
      // Once a restrictive/bypass notice is in history, returning to the
      // default must append an explicit Auto notice, not merely clear a map.
      const includeDefault = sessionNotices.snapshot(sessionID) !== undefined
      sessionNotices.setPerm(sessionID, securityNotice(sessionID, now, includeDefault))
      sessionNotices.setBypass(sessionID, undefined)
      const currentSnapshot = securitySnapshotFor(sessionID, now)
      // A mode/lease change revokes running calls, not only future permission
      // assertions. The broker sends explicit cancellation; unobserved
      // foreground calls use the original executor's interruption path.
      for (const authorization of boundaryCalls.values()) {
        if (authorization.sessionID !== sessionID) continue
        if (authorization.securitySnapshot === currentSnapshot) continue
        if (!authorization.runtimeBlocked) {
          authorization.runtimeBlocked = "Session permissions or authorization changed"
          authorization.runtimeBlockDetails = { advice: RECHECK }
        }
        if (authorization.runtimeBroker) void authorization.runtimeBroker.close()
        else authorization.cancelExecution?.()
      }
    }

    /** Refresh the merged agent notice in line with the effective state.
     *  Thin alias for syncSecurityNotice (kept so bypass-mutation call
     *  sites read naturally). */
    function syncAgentReminder(sessionID: string) {
      syncSecurityNotice(sessionID)
    }

    /** Remove leases whose TTL elapsed and re-sync the agent reminder. Called on
     * a timer because lease pruning is otherwise lazy, so the transition would
     * never be observed. */
    function sweepExpiredBypass() {
      const now = Date.now()
      for (const [sessionID, lease] of [...bypassLeases]) {
        if (lease.expiresAt > now) continue
        expireLease(sessionID, lease)
        // Lease expiry can lift Bypass mode (and restore a stashed RO
        // baseline) — one merged notice covers mode and ceiling together.
        syncSecurityNotice(sessionID)
        syncBypassDescendants(sessionID)
        syncPermDescendants(sessionID)
        if (activeBypass(sessionID).size === 0 && activeCustomBypass(sessionID).length === 0 && !allBypassed(sessionID))
          emitBypassChanged(sessionID, "expired")
        else emitBypassChanged(sessionID, "updated")
        publishSharedStateChange(sessionID)
      }
    }

    // --- user security-mode transitions -------------------------------------
    // One transition entry for /perm's mode tokens and the /bypass kill
    // switch (all/*/ALL/yolo). The Bypass transition stashes the session's
    // pre-mode baseline and lifts it to read-write; disarm/expiry/another
    // mode restores the stash so a lease timeout can never leave the earlier
    // read-only ceiling permanently widened. Ancestor baselines still cap
    // the effective set — an RO ancestor clamps Bypass to effective ReadOnly.

    /** The effective user-facing mode: an armed kill switch reads as Bypass
     *  only when the effective ceiling can actually write — an inherited or
     *  restored read-only cap reports ReadOnly (the RO ceiling outranks the
     *  mode selection). */
    function effectiveMode(sessionID: string, now: number = Date.now()): SecurityMode {
      return securityModeFor(effectivePerm(sessionID, now), allBypassed(sessionID, now))
    }

    /** Single canonical snapshot of everything an admitted call depends on:
     *  the effective r/w ceiling (ancestors included), the armed bypass set,
     *  verbatim custom scopes, the kill switch, and the derived mode. Review
     *  and admission bind to this exact string — a mid-review permission or
     *  mode change makes a stale admission fail instead of running under
     *  authority the user already revoked. Expired leases are pruned first so
     *  a lapsed Bypass lease cannot survive between its deadline and the
     *  next timer sweep. */
    function securitySnapshotFor(sessionID: string, now: number = Date.now()): string {
      pruneExpiredLeases(sessionID, now)
      const perm = effectivePerm(sessionID, now)
      const basis = JSON.stringify({
        r: perm.r,
        w: perm.w,
        mode: securityModeFor(perm, allBypassed(sessionID, now)),
        categories: [...activeBypass(sessionID, now)].sort(),
        custom: activeCustomBypass(sessionID, now),
        all: allBypassed(sessionID, now),
      })
      const previous = securityBases.get(sessionID)
      if (previous !== basis) {
        securityBases.set(sessionID, basis)
        securityEpochs.set(sessionID, (securityEpochs.get(sessionID) ?? 0) + 1)
        if (previous !== undefined) approvalCache.clear(sessionID)
      }
      // Auto→RO→Auto is a new authority generation, even when the final bits
      // equal their old values; a revoked approval cannot resurrect.
      return JSON.stringify([securityEpochs.get(sessionID), basis])
    }

    /** Restore the baseline recorded when Bypass mode was armed. Applied as
     *  an intersection with the current baseline so a concurrent tighten can
     *  never be widened back open. Emits the permission event when the
     *  baseline actually moved. */
    function restoreStashedBaseline(sessionID: string, lease: BypassLease | undefined) {
      const stashed = lease?.restoreBaseline
      if (!stashed) return
      const current = sessionPerms.get(sessionID) ?? { ...policyForSession(sessionID).defaultPerm }
      const restored = permIntersect(current, stashed)
      sessionPerms.set(sessionID, restored)
      if (!permEqual(restored, current)) emitPermChanged(sessionID, "restored")
    }

    /** End a lease: delete it and restore the stashed pre-bypass baseline
     *  (if the Bypass transition raised it). The stash is consumed either way
     *  so a later expiry can never resurrect an earlier ceiling.
     *  Idempotency claim: the lease map is shared by every plugin instance in
     *  this process and several of them may sweep or lazily prune the same
     *  deadline — only the call holding the exact lease object still in the
     *  map ends it, so double sweeps are harmless and a re-armed replacement
     *  lease is never expired by a stale sweep snapshot. */
    function expireLease(sessionID: string, lease: BypassLease, now?: number) {
      if (bypassLeases.get(sessionID) !== lease) return
      bypassLeases.delete(sessionID)
      restoreStashedBaseline(sessionID, lease)
      // Lazy expiry can happen on a status/permission read before the timer.
      // Announce after the current synchronous transition finishes, avoiding
      // recursive effective-state reads and intermediate contradictory notices.
      // A read-path expiry reuses its caller's clock capture.
      queueMicrotask(() => {
        syncSecurityNotice(sessionID, now)
        syncBypassDescendants(sessionID)
        syncPermDescendants(sessionID)
        publishSharedStateChange(sessionID)
      })
    }

    /** Arm/disarm the Bypass kill switch on the session's own lease.
     *  Arming stashes the current baseline so the (r,w) lift the Bypass
     *  transition performs can be rolled back exactly; an already-armed
     *  lease keeps its original stash (a second arm is not a new baseline). */
    function setBypassKillSwitch(sessionID: string, arm: boolean, timeoutSec?: number) {
      const existing = bypassLeases.get(sessionID)
      if (arm) {
        bypassLeases.set(sessionID, {
          categories: existing ? new Set(existing.categories) : new Set(),
          custom: existing?.custom,
          all: true,
          expiresAt: bypassExpiry(timeoutSec),
          // A repeated arm keeps the ORIGINAL stashed baseline — the stash
          // belongs to the first transition, not to the latest re-arm.
          restoreBaseline: existing?.all === true
            ? existing.restoreBaseline
            : sessionPerms.get(sessionID) ?? { ...policyForSession(sessionID).defaultPerm },
        })
        // Every arm channel (/perm bypass too, not only /bypass) must wake
        // the sweep so the new deadline is observed.
        wakeBypassSweep()
        return
      }
      if (!existing) return
      restoreStashedBaseline(sessionID, existing)
      const lease: BypassLease = { ...existing, all: false, restoreBaseline: undefined }
      if (lease.categories.size === 0 && !(lease.custom?.length)) {
        bypassLeases.delete(sessionID)
      } else {
        bypassLeases.set(sessionID, lease)
      }
      wakeBypassSweep()
    }

    /** Re-announce descendants whose effective bypass set moved with an
     *  ancestor lease (links are child→parent, so scan the map). */
    function syncBypassDescendants(parentID: string, seen: Set<string> = new Set([parentID])) {
      for (const [child, parent] of bypassParent) {
        if (parent !== parentID || seen.has(child)) continue
        seen.add(child)
        syncSecurityNotice(child)
        syncBypassDescendants(child, seen)
      }
    }

    /** Lazily end expired leases on this session's chain (the timer sweep
     *  covers idle sessions; every state read prunes first so a stale
     *  `all`-flag or stashed baseline is never observed). */
    function pruneExpiredLeases(sessionID: string, now: number = Date.now()) {
      for (const target of [sessionID, ...bypassAncestors(sessionID)]) {
        const lease = bypassLeases.get(target)
        if (lease && lease.expiresAt <= now) expireLease(target, lease, now)
      }
    }

    /** Refresh the state notices and emit both RPC snapshots after any
     *  user-side mutation (lease, baseline, or both). */
    function notifySecurityState(sessionID: string, bypassReason: string, permReason: string) {
      syncSecurityNotice(sessionID)
      syncBypassDescendants(sessionID)
      syncPermDescendants(sessionID)
      emitBypassChanged(sessionID, bypassReason)
      emitPermChanged(sessionID, permReason)
      publishSharedStateChange(sessionID)
    }

    /** The single user-side security-mode transition shared by /perm mode
     *  tokens and the /bypass kill switch. `bypass` stashes and lifts this
     *  session's own baseline to read-write (ancestors still cap the
     *  effective set) and arms the kill switch; `readonly`/`auto` disarm the
     *  local kill switch (restoring any stashed baseline) and assert the
     *  mode's baseline. Returns the resulting effective mode so callers can
     *  report a clamp. */
    function applyUserSecurityMode(target: string, mode: SecurityMode, timeoutSec?: number): SecurityMode {
      if (mode === "bypass") {
        setBypassKillSwitch(target, true, timeoutSec)
        // Bypass asserts read-write on the OWN baseline only; an ancestor
        // read-only ceiling still clamps the effective set. The no-Bypass
        // barrier (if any) is NOT deleted: the own lease wins while armed
        // and the declared surface returns on expiry — never an ancestor's
        // inherited Bypass.
        sessionPerms.set(target, { ...permForMode("bypass") })
        const result = effectiveMode(target)
        notifySecurityState(target, result === "bypass" ? "armed" : "clamped", "set")
        return result
      }
      setBypassKillSwitch(target, false)
      sessionPerms.set(target, { ...permForMode(mode) })
      // Selecting Auto/ReadOnly is itself an explicit no-Bypass assertion:
      // the barrier blocks any ancestor's armed kill switch for this
      // session and its descendants.
      explicitNoBypass.add(target)
      const result = effectiveMode(target)
      notifySecurityState(target, "set", "set")
      return result
    }

    type BypassOp =
      | { kind: "clear" }
      | { kind: "custom"; text: string }
      | { kind: "categories"; action: "arm" | "disarm" | "toggle"; which: readonly BypassCategory[] }
      | { kind: "killSwitch"; action: "arm" | "disarm" | "toggle" }

    /** Parses /bypass arguments into ordered operations plus an optional
     *  timeout. Explicit `+token` always arms, `-token` always disarms (never
     *  toggles); a bare token toggles against the pre-command snapshot.
     *  Aliases: fs→filesystem, 0→off (when it is the only token — see the
     *  timeout rule below). `all`, `*`, `ALL`, `yolo`/`YOLO`, and `bypass`
     *  are ALL the same user Bypass mode — the kill switch that skips every
     *  plugin check for the session; they no longer mean "every category".
     *
     *  Timeout: the LAST token may be a signed number, interpreted as
     *  seconds until the session's lease expires (`/bypass fs 120` arms fs
     *  for 120s; zero or a negative value arms it without a natural expiry). It is an
     *  absolute deadline: activity never extends it. A bare `0` ALONE stays
     *  the `off` alias for compatibility — the never-expire spelling is only
     *  read as a timeout when at least one other token precedes it. A
     *  number in any non-final position is an invalid
     *  token, so malformed input rejects atomically without touching the
     *  lease. */
    function parseBypassArguments(text: string): { ops: BypassOp[]; invalid: string[]; timeoutSec?: number } {
      // The remainder is verbatim. A final number is part of the scope, not a
      // hidden timeout; custom uses the existing configured lease TTL.
      const custom = /^\s*custom(?:[ \t]|\r?\n)/i.exec(text)
      if (custom) {
        const scope = text.slice(custom[0].length)
        return scope.trim() ? { ops: [{ kind: "custom", text: scope }], invalid: [] }
          : { ops: [], invalid: ["custom requires a nonempty scope"] }
      }
      const ops: BypassOp[] = []
      const invalid: string[] = []
      let timeoutSec: number | undefined
      const rawTokens = text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean)
      for (const [index, raw] of rawTokens.entries()) {
        // Timeout: a trailing signed number (non-integer seconds like 0.5
        // are accepted; "Infinity" and 1e5 spellings are not and reject).
        if (index === rawTokens.length - 1 && rawTokens.length > 1 && /^[+-]?\d+(\.\d+)?$/.test(raw)) {
          const value = Number(raw)
          if (Number.isFinite(value)) {
            timeoutSec = value
            continue
          }
        }
        // Sign is checked on the RAW token so "+ALL" resolves like "ALL".
        let sign: "+" | "-" | undefined
        let body = raw
        if (body.startsWith("+") || body.startsWith("-")) {
          sign = body[0] as "+" | "-"
          body = body.slice(1)
        }
        // Bypass mode (the kill switch): ALL/*/all/yolo/bypass all mean the
        // same user-selected mode — every plugin check skipped, the r/w
        // ceiling and OS-sandbox floor still apply where they cannot be
        // relaxed by a category.
        if (body === "ALL" || /^(?:yolo|all|\*|bypass)$/i.test(body)) {
          ops.push({ kind: "killSwitch", action: sign === "+" ? "arm" : sign === "-" ? "disarm" : "toggle" })
          continue
        }
        const token = body.toLowerCase()
        if (token === "off" || token === "clear" || token === "none" || token === "0") {
          ops.push({ kind: "clear" })
          continue
        }
        const categories = expandBypassCategoryToken(token)
        if (categories) {
          ops.push({ kind: "categories", action: sign === "+" ? "arm" : sign === "-" ? "disarm" : "toggle", which: categories })
          continue
        }
        invalid.push(raw)
      }
      // Reject before mutating state: a timeout cannot apply after clearing.
      if (timeoutSec !== undefined && ops.at(-1)?.kind === "clear") invalid.push("timeout after off")
      return { ops, invalid, timeoutSec }
    }

    function bypassUsage(invalid: string[]): string {
      return (
        `Unknown bypass categor${invalid.length > 1 ? "ies" : "y"}: ${invalid.join(", ")}.\n` +
        `Usage: /bypass <${[...BYPASS_CATEGORIES].join("|")}|fs|custom|all|*|ALL|yolo|off> — ` +
        `categories space or comma separated; legacy aliases: fs=filesystem, os=host+privilege+indirection, web=network+remote; ` +
        `all, *, ALL, yolo and bypass are the user Bypass mode (all plugin checks skipped for this session — ` +
        `prefer specific categories when possible); off/0 clears categories, custom scopes and the mode. ` +
        `/bypass custom <verbatim text> adds an authorization scope using the same lease TTL. +token arms, -token disarms, a bare token toggles. ` +
        `A trailing bare number is the timeout in seconds — an absolute deadline, never extended by activity; ` +
        `a zero or negative timeout (e.g. "/bypass fs -1") means no natural expiry until /bypass off.\n` +
        `Categories skip their static checks and are passed as authorization to the effects reviewer. ` +
        `Only the explicit sandbox switch removes OS isolation; privilege/filesystem categories do not imply full access.`
      )
    }

    function armBypassLease(sessionID: string, categories: Set<BypassCategory>, timeoutSec?: number) {
      // A new arm keeps an already-armed `all` kill switch: narrowing the
      // category set must not silently re-enable the enforcement layers the
      // user turned off; only `off`/clear or lease expiry lifts `all`. The
      // stashed baseline survives with it.
      const prior = bypassLeases.get(sessionID)
      bypassLeases.set(sessionID, {
        categories: new Set(categories),
        expiresAt: bypassExpiry(timeoutSec),
        all: prior?.all === true ? true : undefined,
        custom: prior?.custom,
        restoreBaseline: prior?.all === true ? prior.restoreBaseline : undefined,
      })
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
            const inspected = inspectRegularTextFileSync(realpathSync("/etc/os-release"), 64 * 1024)
            pretty = inspected.ok ? inspected.text.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1] : undefined
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

    // Reviewer audit trail (logReviewerTrace): request, result/error, and
    // final outcome are separate events, NOT separate JEV calls. Appended to
    // ~/.opencode/reviewer-trace.jsonl. Fire-and-forget — a logging failure
    // must never alter the review outcome or block a command.
    // Failure passes always have an audit sink. With verbose tracing disabled,
    // keep this minimal code-only trace in the configured scratch directory.
    const reviewerTraceFile = resolved.logReviewerTrace
      ? path.join(homedir(), ".opencode", "reviewer-trace.jsonl")
      : path.join(resolved.sandbox.scratch, "reviewer-trace.jsonl")
    function writeReviewerTrace(entry: Record<string, unknown>) {
      if (!resolved.logReviewerTrace && entry.kind !== "fail_open_pass") return
      const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n"
      void mkdir(path.dirname(reviewerTraceFile), { recursive: true })
        .then(() => appendFile(reviewerTraceFile, line, "utf8"))
        .catch(() => {})
    }

    function passFailure(code: string, call?: Pick<BoundaryInvocation, "sessionID" | "id">, authorization?: BoundaryAuthorization): boolean {
      return failureOrPass(resolved.failPolicy, code, (entry) => {
        writeReviewerTrace({ ...entry, ...(call ? { sessionID: call.sessionID, callID: call.id } : {}) })
        if (authorization) {
          authorization.failOpenPasses ??= []
          authorization.failOpenPasses.push(code)
        }
      })
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
    // nonce marker prepended to input.command by runBoundaryBefore carries the
    // chosen profile to spawn time (plan §1.3). The marker is the SOLE
    // authority for wrapping: user-initiated shells (`!cmd`, host-internal
    // spawns) never ran the boundary preflight, carry no marker, and run
    // completely untouched — trusted authority, exactly as they were never
    // classified.
    const sandboxMarkers = createSandboxMarkers()

    type BoundaryAuthorization = {
      token: object
      sessionID: string
      tool: NativeBoundaryTool
      cwd: string
      filePlan?: FileBoundaryPlan
      /** ReadOnly native file call whose every write lands in a global temp
       *  root: the permission gate does not require the write bit. */
      tempOnlyWrite?: boolean
      shellPlan?: ShellBoundaryPlan
      source: string
      /** The securitySnapshotFor() value this admission was computed under —
       *  re-verified before execution (end of preflight and at
       *  permission.evaluate) so a stale grant can never outlive the state
       *  that produced it. */
      securitySnapshot: string
      /** Spawn route chosen after the review layer admitted the call
       *  (observability only): "host_direct_reviewed" = the admitted call
       *  runs on the host without the plugin kernel sandbox;
       *  "readonly_sandbox"/"kernel_sandbox" = a kernel-isolated route
       *  (read-only sessions still using a kernel profile). */
      executionRoute?: "host_direct_reviewed" | "readonly_sandbox" | "kernel_sandbox" | "runtime_boundary_watch"
      runtimeBroker?: RuntimeBoundaryBroker
      cancelExecution?: () => void
      cacheUpdates?: Array<{ scope: ApprovalCacheScope; facts: ApprovalCacheFacts }>
      runtimeBlocked?: string
      runtimeBlockDetails?: RuntimeBlockDetails
      failOpenPasses?: string[]
      runtimeStats?: { crossings: number; reviewRequests: number; cacheHits: number; staticAllows: number }
      background?: boolean
      /** Set once permission.evaluate has allowed at least one assert of
       *  this call. Real tools may assert several times (external_directory
       *  + edit, multi-file patches): after the first allow, earlier steps
       *  may already have run, so a later denial must not claim the whole
       *  command never ran (see permissionBlockText). */
      asserted?: boolean
    }
    const boundaryCalls = new Map<string, BoundaryAuthorization>()
    // Security-snapshot bases/epochs, the approval cache and the L3 grants are
    // shared process-wide: a snapshot computed by one instance must be
    // byte-identical for every other instance (admissions re-verify against
    // it, and the approval cache keys on it), and a session's cached
    // approvals/grants must not split by which instance serves the call.
    const securityBases = shared.securityBases
    const securityEpochs = shared.securityEpochs
    const approvalCache = shared.approvalCache
    const sharedReviews = createSingleFlight<EffectReviewResult>()
    const digest = (value: string) => createHash("sha256").update(value).digest("hex")
    let boundaryWatchFingerprint: string | undefined
    let directSubagent = false
    const boundaryKey = (call: Pick<BoundaryInvocation, "sessionID" | "messageID" | "id">) =>
      JSON.stringify([call.sessionID, call.messageID, call.id])
    const injectedEffectsReview = ctx.options && typeof ctx.options === "object" &&
      typeof (ctx.options as { reviewCommand?: unknown }).reviewCommand === "function"
        ? (ctx.options as { reviewCommand: (request: EffectReviewRequest, options: { signal: AbortSignal }) => Promise<EffectReviewResult> }).reviewCommand
        : undefined

    const injectedRootReview = (injectedEffectsReview as typeof injectedEffectsReview & {
      rootWidening?: ((request: RootWideningInput) => Promise<unknown>) & { trace?: (entry: L3Trace) => void }
    })?.rootWidening
    const rootWidening = createRootWidening({
      state: shared.l3,
      trace: (entry) => {
        writeReviewerTrace({ ...entry })
        injectedRootReview?.trace?.(entry)
      },
      review: async (request) => {
        if (injectedRootReview) return injectedRootReview(request)
        const jev = resolved.dynamicReview.jev
        if (!jev?.available) throw new Error("L3 reviewer unavailable")
        return reviewRootWidening(request, { endpoint: jev.endpoint, apiKey: jev.apiKey ?? "", timeoutMs: resolved.dynamicReview.timeoutMs })
      },
    })
    async function rootWideningContext(sessionID: string): Promise<RootWideningContext> {
      if (!ctx.session.context) throw new Error("L3 context unavailable")
      const retained = boundarySessionContext(await run(ctx.session.context({ sessionID })))
      return { scope: { sessionID, canWrite: effectivePerm(sessionID).w,
        userMessageDigest: digest(retained.userRequest), securitySnapshot: securitySnapshotFor(sessionID) },
      user_request: retained.userRequest, session_context: retained.context }
    }

    async function callEffectsReviewer(request: EffectReviewRequest, signal: AbortSignal, readonly = false): Promise<EffectReviewResult> {
      if (signal.aborted) throw new EffectsReviewError("Effects review was cancelled", "aborted")
      if (injectedEffectsReview) {
        const supplied = await injectedEffectsReview(request, { signal })
        // Test injection still has to return the new complete answer contract.
        // Old ALLOW/DENY objects cannot bypass floor validation.
        return adjudicateEffectAnswers(supplied?.answers, readonly)
      }
      const jev = resolved.dynamicReview.jev
      if (!jev?.available) throw new EffectsReviewError("JEV effects review is not configured", "infrastructure")
      return reviewEffects(request, {
        endpoint: jev.endpoint,
        apiKey: jev.apiKey ?? "",
        timeoutMs: resolved.dynamicReview.timeoutMs,
        signal,
        readonly,
      })
    }

    /** Digest-only audit context for the effects-review trace events. Never
     *  carries the command text, user_request, custom bypass scopes, file
     *  contents, provider error bodies, or credentials — the trace is a
     *  user-readable verdict log, not a payload dump. */
    type BoundaryReviewAudit = {
      sessionID: string
      callID: string
      commandSha256: string
      tool: NativeBoundaryTool
      staticRules: readonly string[]
      eventID?: number
      /** Non-sensitive crossing shape so review volume can be attributed
       *  without replaying commands: no argv, paths or command text. */
      boundary?: { kind: string; syscall: string; operation: string; executable?: string }
      stats?: BoundaryAuthorization["runtimeStats"]
    }

    async function reviewBoundaryRequest(
      request: EffectReviewRequest,
      subjects: readonly string[],
      signal: AbortSignal,
      worktree: string,
      audit: BoundaryReviewAudit,
      readonly = false,
    ): Promise<EffectReviewResult> {
      const policyVersion = readonly ? EFFECTS_POLICY_VERSION_READONLY : EFFECTS_POLICY_VERSION
      let round = 0
      const invoke = async (payload: EffectReviewRequest): Promise<EffectReviewResult> => {
        round += 1
        if (audit.stats) audit.stats.reviewRequests++
        writeReviewerTrace({
          kind: "effects_review_request",
          sessionID: audit.sessionID,
          callID: audit.callID,
          commandSha256: audit.commandSha256,
          tool: audit.tool,
          staticRules: audit.staticRules,
          reviewer: injectedEffectsReview ? "test_injection" : "jev",
          ...(audit.eventID !== undefined ? { eventID: audit.eventID, phase: "runtime" } : { phase: "native_preflight" }),
          ...(audit.boundary ? { boundary: audit.boundary } : {}),
          round,
          policyVersion,
        })
        try {
          const verdict = await callEffectsReviewer(payload, signal, readonly)
          writeReviewerTrace({
            kind: "effects_review_result",
            sessionID: audit.sessionID,
            callID: audit.callID,
            commandSha256: audit.commandSha256,
            reviewer: injectedEffectsReview ? "test_injection" : "jev",
            ...(audit.eventID !== undefined ? { eventID: audit.eventID } : {}),
            round,
            decision: verdict.decision,
            source: verdict.source,
            floor: verdict.floor,
            uncoveredOwner: verdict.uncoveredOwner,
            policyVersion,
          })
          return verdict
        } catch (error) {
          // Provider error bodies are intentionally NOT traced: record only
          // the failure class (aborted/protocol/infrastructure/…).
          writeReviewerTrace({
            kind: "effects_review_error",
            sessionID: audit.sessionID,
            callID: audit.callID,
            commandSha256: audit.commandSha256,
            reviewer: injectedEffectsReview ? "test_injection" : "jev",
            ...(audit.eventID !== undefined ? { eventID: audit.eventID } : {}),
            round,
            errorKind: error instanceof EffectsReviewError ? error.kind : "unknown",
            policyVersion,
          })
          throw error
        }
      }
      let result = await invoke(request)
      if (result.decision !== "collect_evidence") return result
      const collected = await collectBoundedEvidence([...new Set(subjects)].map((subject) => ({ subject })), {
        cwd: request.cwd,
        worktree,
        allowFullReadAccess: resolved.dynamicReview.allowFullReadAccess,
      })
      if (signal.aborted) throw new EffectsReviewError("Effects review was cancelled", "aborted")
      if (collected.evidence.length > 0) {
        const retry: EffectReviewRequest = {
          ...request,
          input_facts: [
            ...request.input_facts,
            ...collected.evidence.map((item) => `Collected local evidence (not authorization): ${JSON.stringify({
              path: item.identity?.resolvedPath ?? item.subject,
              kind: item.kind,
              excerpt: item.excerpt,
              truncated: item.truncated,
            })}`),
            `Evidence collection is exhausted after this bounded pass; unavailable subjects: ${JSON.stringify(collected.missing)}`,
          ],
          files: [...request.files, ...collected.evidence.map((item) => ({
            path: item.identity?.resolvedPath ?? item.subject,
            kind: item.kind,
            role: "collected_evidence",
            bytes: Buffer.byteLength(item.excerpt, "utf8"),
          }))],
        }
        result = await invoke(retry)
      }
      return resolveUncollectableEffects(result, true, resolved.dynamicReview.onUncollectable)
    }

    function assertBoundaryDecision(result: EffectReviewResult, action?: string): void {
      if (result.decision === "allow") return
      // Refusal wording lives in agent-messages.ts (floor → evidence → deny
      // order preserved there); the frozen adjudication itself is untouched.
      const refusal = reviewRefusal(result)
      if (action) {
        throw rejectionError(actionBeforeText(refusal.reason, action, refusal.advice))
      }
      throw blockedRejection(refusal.reason, refusal.advice)
    }

    /** `tempOnly`: every write of this native file call lands in a ReadOnly
     *  temp root, so the write bit is not required. */
    function assertNativeCeiling(tool: NativeBoundaryTool, sessionID: string, writes: readonly string[], tempOnly = false): void {
      const perm = effectivePerm(sessionID)
      const bit = tool === "shell" ? (writes.length ? "w" : undefined)
        : tool === "write" || tool === "edit" || tool === "patch" ? (tempOnly ? undefined : "w") : "r"
      // NOTE: a shell call whose writes cannot be enumerated (variable,
      // opaque target) reports writes=[] here — the unconditional
      // runtime observer catches those writes before the actual syscall;
      // admission snapshots also re-check the ceiling at execution time.
      if (bit && !perm[bit]) {
        // An unverified ancestor chain fails closed but is NOT a
        // user-selected ReadOnly — say so, and let the call be retried once
        // the parent sessions hydrate.
        if (bit === "w" && ancestryUnresolved(sessionID)) {
          throw blockedRejection(
            "the plugin could not verify this session's parent sessions, so write actions are blocked for now",
            RETRY_LATER,
          )
        }
        // ReadOnly gets its own clear reason — the rwx label is not what the
        // user selected and reads like an internal detail.
        const mode = securityModeFor(perm, allBypassed(sessionID))
        throw blockedRejection(
          mode === "readonly"
            ? bit === "w"
              ? "this session is in [Read only] mode: writes outside temporary directories are blocked"
              : "this session is in [Read only] mode: native file reads are blocked"
            : `the session permission ceiling does not allow '${bit}' actions`,
        )
      }
    }

    async function recordCallCacheOutcome(authorization: BoundaryAuthorization, exit: number | undefined): Promise<void> {
      // A non-zero exit still finished under the approval (`grep` without a
      // match, `cmd; false`): the objects it wrote are the approved ones.
      if (exit === undefined || authorization.runtimeBlocked || !authorization.cacheUpdates?.length) return
      for (const update of authorization.cacheUpdates) {
        // Only the security epoch gates recording: positive entries are not
        // bound to the user message, so a newer message does not stop this
        // call's outcome from advancing its grants.
        if (securitySnapshotFor(authorization.sessionID) !== update.scope.securitySnapshot) continue
        approvalCache.recordTargets(update.scope, update.facts, await currentCacheTargets(update.facts.targets).catch(() => []))
      }
    }

    async function prepareRuntimeShell(
      command: string, raw: Record<string, unknown>, call: BoundaryInvocation,
      authorization: BoundaryAuthorization, cwd: string, roots: string[], preparationSignal: AbortSignal,
      additionalDenyWrite: readonly string[] = [], readOnlyDenyRead: readonly string[] = [],
      temporaryWriteRoots: readonly string[] = [],
      observedWriteRoots: readonly string[] = [],
    ): Promise<void> {
      await access(DEFAULT_BOUNDARY_WATCH_HELPER, 1).catch(() => {
        throw new SecurityCheckFailure("observer_unavailable", "the runtime boundary observer is unavailable, so this shell command cannot start")
      })
      // A helper image replaced after this process started must not be
      // silently executed under old approvals — require a plugin restart.
      const helperInfo = await lstat(DEFAULT_BOUNDARY_WATCH_HELPER, { bigint: true }).catch(() => undefined)
      if (!helperInfo?.isFile()) throw new SecurityCheckFailure("observer_unavailable", "the runtime boundary observer is unavailable, so this shell command cannot start")
      const helperFingerprint = `${helperInfo.dev}:${helperInfo.ino}:${helperInfo.size}:${helperInfo.mtimeNs}`
      if (boundaryWatchFingerprint === undefined) boundaryWatchFingerprint = helperFingerprint
      else if (boundaryWatchFingerprint !== helperFingerprint)
        throw new SecurityCheckFailure("observer_changed", "the runtime boundary observer binary changed on disk; restart the session before running more commands")
      const runtimeCwd = await canonicalBoundaryPath(typeof raw.workdir === "string" ? nativeAbsolutePath(cwd, raw.workdir) : cwd)
      if (typeof raw.workdir === "string") raw.workdir = runtimeCwd
      const deniedWritePaths = await Promise.all([...resolved.sandbox.denyWrite, ...additionalDenyWrite]
        .map((target) => canonicalBoundaryPath(target)))
      const incidentalRoots = [...incidentalWriteRoots(), ...observedWriteRoots]
      const currentWriteRoots = (scope: RootWideningScope) => [
        ...roots.filter((root) => !temporaryWriteRoots.includes(root)), ...rootWidening.activeRoots(scope),
      ]
      const writePolicy = (): WriteRootPolicy => ({
        home: homedir(), cwd: runtimeCwd, credentialPaths: credentialStoreReadPaths(homedir()),
        denyWrite: deniedWritePaths,
        protect: [DEFAULT_BOUNDARY_WATCH_HELPER, PACKAGE_ROOT, path.dirname(broker.socketPath)],
        brokerBase: "/tmp/opencode",
      })
      const rememberAllowedWrite = (event: RuntimeBoundaryEvent) => {
        if (event.kind !== "write" || !effectivePerm(call.sessionID).w) return
        void rootWideningContext(call.sessionID).then((retained) => {
          if (retained.scope.securitySnapshot !== authorization.securitySnapshot) return
          rootWidening.recordAllowedWrite({ scope: retained.scope, callID: boundaryKey(call), command, event,
            policy: writePolicy(), workspace: cwd, currentRoots: currentWriteRoots(retained.scope),
            context: () => rootWideningContext(call.sessionID) })
        }).catch(() => {
          writeReviewerTrace({ kind: "l3_root_error", sessionID: call.sessionID, commandSha256: digest(command), policyVersion: L3_POLICY_VERSION })
        })
      }
      let eventPhase: "entry" | "exit" | "unknown" = "unknown"
      // The whole-command static proof is computed at most once per call and
      // only when a crossing can use it. It never refuses: the two-state
      // boundary classifier reports DENY-class findings as ASK.
      let proof: Promise<{ verdict: "ALLOW" | "ASK"; rules: string[] }> | undefined
      let proofRules: readonly string[] = []
      const commandProof = () => proof ??= classifyBoundaryCommand({
        script: command, cwd, worktree: cwd, shell: resolveClassifierShell(configuredShell),
        ...(runtimeCwd !== cwd ? { runtimeWorkdir: runtimeCwd } : {}),
        strictness: resolved.strictness,
        bypassedCategories: activeBypass(call.sessionID),
        permScope: effectivePerm(call.sessionID),
        roWritableRoots: effectivePerm(call.sessionID).w ? [resolved.sandbox.scratch] : roots,
        sandboxDenyWrite: deniedWritePaths,
        trustedCommands: resolved.trustedCommands,
      }).then((decision) => {
        proofRules = decision.rules
        return { verdict: decision.verdict, rules: decision.rules }
      })
      const commandProofRules = () => proofRules
      const recordBlock = (reason: string, event?: RuntimeBoundaryEvent, advice?: string, cancelled = false) => {
        // First refusal reason wins: a downstream broker EOF/cancel must not
        // rewrite why the crossing was actually denied.
        if (!authorization.runtimeBlocked) {
          authorization.runtimeBlocked = reason
          authorization.runtimeBlockDetails = {
            ...(event ? { trigger: runtimeBoundaryTrigger(event) } : {}),
            ...(advice ? { advice } : {}),
            ...(cancelled ? { cancelled: true } : {}),
          }
        }
        return {
          action: "deny" as const,
          reason: authorization.runtimeBlocked,
          message: runtimeBlockedText(authorization.runtimeBlocked, authorization.runtimeBlockDetails),
        }
      }
      const failure = (code: string, event?: RuntimeBoundaryEvent) => {
        if (authorization.runtimeBlocked) return recordBlock(authorization.runtimeBlocked)
        if (preparationSignal.aborted) return recordBlock("Cancellation: the call was cancelled", undefined, CANCEL_ADVICE, true)
        if (securitySnapshotFor(call.sessionID) !== authorization.securitySnapshot) return recordBlock("Session permissions or authorization changed", undefined, RECHECK)
        return passFailure(code, call, authorization) ? { action: "allow" as const } : recordBlock(checkUnavailableReason(code), event, RETRY_LATER)
      }
      // Name-matched incidental writes (any `__pycache__`/`.pytest_cache`
      // component) bypass the boundary in EVERY mode — but never inside a
      // protected control-plane path, a configured denyWrite, or a credential
      // store: the helper reports protect hits as write events and a
      // `.pytest_cache` directory inside `~/.aws` must not be exempt. The
      // target path is already canonicalized by the observer.
      const incidentalWriteExempt = (target: string): boolean => {
        if (!isIncidentalToolWrite(target) && !incidentalRoots.some((root) => containsPath(root, target))) return false
        return writeTargetExempt(target, writePolicy())
      }
      const broker = await createRuntimeBoundaryBroker({
        directory: "/tmp/opencode",
        failPolicy: resolved.failPolicy,
        onError: () => { failure("broker_unavailable") },
        onFailure: (code) => { failure(code) },
        onCancelFailure: () => authorization.cancelExecution?.(),
        onBoundary: async (event: RuntimeBoundaryEvent, signal) => {
          const blocked = (reason: string, advice?: string) => recordBlock(reason, event, advice)
          const failed = (code: string) => failure(code, event)
          try {
          authorization.runtimeStats!.crossings++
          // The helper always emits atExit explicitly; an absent field is
          // genuinely unknown, never silently "entry".
          eventPhase = event.details.atExit === true ? "exit"
            : event.details.atExit === false ? "entry" : "unknown"
          await hydratePermAncestry(call.sessionID)
          if (preparationSignal.aborted) return recordBlock("Cancellation: the call was cancelled", undefined, CANCEL_ADVICE, true)
          if (signal.aborted) return failed("broker_unavailable")
          if (securitySnapshotFor(call.sessionID) !== authorization.securitySnapshot) {
            return recordBlock("Session permissions or authorization changed", undefined, RECHECK)
          }
          const permission = effectivePerm(call.sessionID)
          const canWrite = permission.w
          if (event.kind === "write" && event.targets.length > 0 &&
            event.targets.every((target) => incidentalWriteExempt(target.path))) {
            return { action: "continue" }
          }
          if (canWrite && event.kind === "write" && rootWidening.hasGrants(call.sessionID)) {
            try {
              const retained = await rootWideningContext(call.sessionID)
              if (rootWidening.targetsExempt(retained.scope, event.targets.map((target) => target.path), writePolicy())) return { action: "continue" }
            } catch {
              writeReviewerTrace({ kind: "l3_root_error", sessionID: call.sessionID, commandSha256: digest(command), policyVersion: L3_POLICY_VERSION })
            }
          }
          // Read-only hard denies: a non-exempt write or a privilege
          // crossing is an obvious write — refused without a reviewer.
          // interop/opaque/read/network crossings get the read-only review.
          if (!canWrite && ["write", "privilege"].includes(event.kind)) {
            return blocked(ancestryUnresolved(call.sessionID)
              ? "Permission check incomplete: the session's inherited permissions could not be verified"
              : "Read-only limit: this operation exceeds the session's permitted effects", ancestryUnresolved(call.sessionID) ? RETRY_LATER : WITHIN_MODE)
          }
          if (event.kind === "read" && !permission.r) return blocked("Read limit: this session does not permit file reads", WITHIN_MODE)
          if (event.kind === "write" && event.targets.some((target) =>
            deniedWritePaths.some((root) => containsPath(root, target.path)) ||
            [path.dirname(broker.socketPath), DEFAULT_BOUNDARY_WATCH_HELPER, PACKAGE_ROOT]
              .some((root) => containsPath(root, target.path) || containsPath(target.path, root)))) {
            return blocked("Write protection: the target is protected or explicitly denied", WITHIN_MODE)
          }
          const bypass = activeBypass(call.sessionID)
          // Disabling review layers cannot waive the independent RO
          // conformance check, especially before a full-tree detach.
          if (canWrite && (!resolved.securityEnabled || bypass.has("dynamic"))) {
            authorization.source = !resolved.securityEnabled ? "security_disabled" : "bypass_dynamic"
            if (canWrite) authorization.executionRoute = "host_direct_reviewed"
            return { action: canWrite ? "allow" : "continue" }
          }
          const executable = typeof event.details.executable === "string" ? event.details.executable : undefined
          const executableInfo = executable ? await lstat(executable, { bigint: true }).catch(() => undefined) : undefined
          const executableIdentity = executableInfo
            ? `${executableInfo.dev}:${executableInfo.ino}:${executableInfo.size}:${executableInfo.mtimeNs}`
            : undefined
          // argv can carry real secrets (passwords as flags are idiomatic):
          // the reviewer and every trace/log sees only its digest, count and
          // completeness — never the raw strings.
          const rawArgv = event.details.argv
          const argvDigest = Array.isArray(rawArgv)
            ? digest(JSON.stringify(rawArgv.map((arg) => typeof arg === "string" ? arg : "")))
            : undefined
          const argvIncomplete = event.details.argvIncomplete === true
          const eventDetails = {
            ...event.details,
            ...(argvDigest !== undefined
              ? { argvDigest, argc: (rawArgv as unknown[]).length }
              : {}),
          } as RuntimeBoundaryEvent["details"]
          delete eventDetails.argv
          const trustedGitReader = executable !== undefined && ["git", "git-remote-http", "git-remote-https"].includes(path.basename(executable)) &&
            executableInfo?.isFile() === true && executableInfo.uid === 0 && (executableInfo.mode & 0o022) === 0
          // Stage 2 of observe → static → dynamic: ALLOW or ASK only. In a
          // read-only session only the RO-scoped command proof may allow a
          // crossing statically — no workspaceNetwork/git-reader shortcuts.
          const staticVerdict = await staticCrossingReview({
            event, command, trustedGitReader,
            workspaceNetwork: resolved.sandbox.workspaceNetwork,
            readonly: !canWrite,
            commandVerdict: async () => (await commandProof()).verdict,
          })
          if (staticVerdict === "ALLOW") {
            rememberAllowedWrite(event)
            authorization.runtimeStats!.staticAllows++
            authorization.source = "runtime_static_allow"
            writeReviewerTrace({ kind: "effects_static_allow", sessionID: call.sessionID, callID: call.id,
              commandSha256: digest(command), eventID: event.eventID,
              boundary: { kind: event.kind, syscall: event.syscall, operation: event.operation,
                ...(executable ? { executable: path.basename(executable) } : {}) } })
            return { action: "continue" }
          }
          if (!ctx.session.context) return failed("session_context")
          const retained = boundarySessionContext(await run(ctx.session.context({ sessionID: call.sessionID }), signal))
          const observed = await currentCacheTargets(event.targets)
          if (!targetIdentitiesMatch(event.targets, observed)) return failed("target_changed")
          if (observed.some((target) => target.inspectionError) && resolved.failPolicy === "fail_open") {
            return failed("target_inspection")
          }
          const metadata = await Promise.all(observed.map(async (target) => {
            let inspectionError: string | undefined
            const info = await lstat(target.path, { bigint: true }).catch((error: unknown) => {
              inspectionError = inspectionErrorCode(error)
              return undefined
            })
            return { path: target.path, ...(info ? { size: String(info.size), mtimeNs: String(info.mtimeNs), ctimeNs: String(info.ctimeNs), mode: String(info.mode) } : { inspectionError }) }
          }))
          const custom = activeCustomBypass(call.sessionID)
          const request: EffectReviewRequest = {
            command, cwd: runtimeCwd, environment: JSON.stringify(detectEnvironment()),
            user_request: retained.userRequest, session_context: retained.context,
            input_facts: [
              eventPhase === "exit"
                ? "Runtime witness: the observer inspected this operation at its syscall-exit boundary check; the operation itself already ran. Earlier in-boundary steps may also have run."
                : eventPhase === "entry"
                  ? "Runtime witness: the observer paused this operation before its boundary effect. Earlier in-boundary steps may already have run."
                  : "Runtime witness: the observer could not confirm whether this operation had already produced its boundary effect when it was checked, so the operation may or may not have run. Earlier in-boundary steps may already have run.",
              `Observed boundary facts (data, not authorization): ${JSON.stringify({ syscall: event.syscall, kind: event.kind, operation: event.operation, targets: observed, details: eventDetails })}`,
              ...(canWrite ? [] : [
                "Session security mode: [Read only]",
                `Read-only session: writes are permitted only inside these roots and the exempt tool cache/history effects (any __pycache__ or .pytest_cache path component): ${JSON.stringify(roots)}`,
              ]),
              `Current allowed write roots: ${JSON.stringify(currentWriteRoots({
                sessionID: call.sessionID, canWrite, securitySnapshot: authorization.securitySnapshot, userMessageDigest: digest(retained.userRequest),
              }))}`,
              `Current boundary object metadata: ${JSON.stringify(metadata)}`,
              `Executing image identity (dev:ino:size:mtimeNs): ${JSON.stringify(executableIdentity ?? null)}`,
              `Independent session read/write ceiling: ${permLabel(permission)}`,
            ],
            files: observed.map((target) => ({ path: target.path, kind: "observed_boundary_target", role: event.kind, bytes: 0 })),
            sandbox: { trigger: `runtime ${event.kind} boundary`, resolved_writes: event.kind === "write" ? observed.map((target) => target.path) : [], domain: event.kind === "interop" ? "windows-interop" : null, error: null },
            bypass: { categories: STATIC_BYPASS_CATEGORIES.filter((category) => bypass.has(category)), custom: custom.length ? custom.join("\n") : null },
          }
          const scope: ApprovalCacheScope = { sessionID: call.sessionID, securitySnapshot: authorization.securitySnapshot, userAuthorizationDigest: digest(retained.userRequest) }
          const reviewPolicyVersion = canWrite ? EFFECTS_POLICY_VERSION : EFFECTS_POLICY_VERSION_READONLY
          const writeEffect = runtimeWriteEffect(event)
          const networkEndpoint = event.kind === "network" ? observedNetworkEndpoint(event.details) : undefined
          const requiresFullApproval = event.details.requiresFullApproval === true || event.kind === "network" && !networkEndpoint
          // L1 keys on the boundary core — crossing kind/syscall/operation/
          // effect, target identities, image identity and (non-shell) argv,
          // cwd, review policy and bypass surface — never the command text,
          // user_request or volatile metadata. A pipeline suffix or an
          // appended `; echo x` replays the same crossing's adjudication.
          const facts: ApprovalCacheFacts = {
            coreDigest: boundaryCoreDigest({
              kind: event.kind, syscall: event.syscall, operation: event.operation, effect: writeEffect,
              targets: observed, executable, executableIdentity,
              network: event.kind === "network" ? event.details : undefined,
              argv: Array.isArray(rawArgv) ? rawArgv : undefined, argvDigest,
              cwd: runtimeCwd, policyVersion: reviewPolicyVersion,
              bypassCategories: request.bypass.categories, customBypass: custom,
              requiresFullApproval,
            }),
            kind: event.kind, operation: event.operation, targets: observed,
            requiresFullApproval,
            networkEndpoint,
            effect: writeEffect,
          }
          const hit = approvalCache.lookup(scope, facts)
          let result: EffectReviewResult
          if (hit) {
            authorization.runtimeStats!.cacheHits++
            // The exact negative verdict has already been selected. A later
            // context/cache inspection failure must not turn it into a pass.
            if (hit.decision === "deny") {
              const refusal = hit.result ? reviewRefusal(hit.result) : { reason: "Cached denial: a pervious review denied the similar operation" }
              return blocked(refusal.reason, refusal.advice)
            }
            const currentTargets = await currentCacheTargets(observed)
            // Positive cache reuse is not bound to the user message: a new
            // message does not revoke an allowed verdict. (Deny hits already
            // returned above, still bound to their message by the lookup.)
            if (preparationSignal.aborted) return recordBlock("Cancellation: the call was cancelled", undefined, CANCEL_ADVICE, true)
            if (securitySnapshotFor(call.sessionID) !== authorization.securitySnapshot) {
              return recordBlock("Session permissions or authorization changed", undefined, RECHECK)
            }
            if (currentTargets.some((target) => target.inspectionError) || !targetIdentitiesMatch(observed, currentTargets)) {
              return failed("target_changed")
            }
            authorization.source = `cache:${hit.layer}`
            writeReviewerTrace({ kind: "effects_cache_hit", sessionID: call.sessionID, callID: call.id,
              commandSha256: digest(command), eventID: event.eventID, layer: hit.layer, decision: hit.decision })
            if (hit.layer === "L2" || !event.details.requiresFullApproval) {
              rememberAllowedWrite(event)
              authorization.cacheUpdates ??= []
              authorization.cacheUpdates.push({ scope, facts })
              return { action: "continue" }
            }
            result = hit.result!
          } else {
            try {
              result = await sharedReviews.run(digest(JSON.stringify([scope, facts.coreDigest])), signal,
                (sharedSignal) => reviewBoundaryRequest(request, observed.map((target) => target.path), sharedSignal, cwd, {
                  sessionID: call.sessionID, callID: call.id, commandSha256: digest(command), tool: "shell",
                  staticRules: commandProofRules(), eventID: event.eventID,
                  boundary: { kind: event.kind, syscall: event.syscall, operation: event.operation,
                    ...(executable ? { executable: path.basename(executable) } : {}) },
                  stats: authorization.runtimeStats,
                }, !canWrite))
            } catch (error) {
              if (preparationSignal.aborted) return recordBlock("Cancellation: the call was cancelled", undefined, CANCEL_ADVICE, true)
              if (error instanceof EffectsReviewError && error.kind === "aborted" && !signal.aborted) return recordBlock("Cancellation: the call was cancelled", undefined, CANCEL_ADVICE, true)
              return failed(error instanceof EffectsReviewError ? `review_${error.kind}` : "review_unavailable")
            }
            writeReviewerTrace({ kind: "effects_boundary_outcome", sessionID: call.sessionID, callID: call.id,
              commandSha256: digest(command), eventID: event.eventID, decision: result.decision, source: result.source,
              floor: result.floor, uncoveredOwner: result.uncoveredOwner, reviewer: injectedEffectsReview ? "test_injection" : "jev", policyVersion: reviewPolicyVersion })
          }
          // A completed deny remains final even if subsequent cache or
          // identity bookkeeping fails.
          if (result.decision !== "allow") {
            const review = reviewRefusal(result)
            const refusal = blocked(review.reason, review.advice)
            // Bookkeeping is best-effort after a real deny; its exception
            // must never erase or turn that completed decision into a pass.
            try { if (!hit) approvalCache.store(scope, facts, result) } catch {
              passFailure("cache_store", call, authorization)
            }
            return refusal
          }
          // A positive verdict stands on its own: it is stored unbound to
          // the user message, so a newer message mid-review does not block
          // it. (Denials returned above, still bound to their message.)
          if (preparationSignal.aborted) return recordBlock("Cancellation: the call was cancelled", undefined, CANCEL_ADVICE, true)
          if (securitySnapshotFor(call.sessionID) !== authorization.securitySnapshot) {
            return recordBlock("Session permissions or authorization changed", undefined, RECHECK)
          }
          const reviewedTargets = await currentCacheTargets(observed)
          if (!targetIdentitiesMatch(observed, reviewedTargets)) return failed("target_changed")
          if (reviewedTargets.some((target, index) => target.inspectionError && !observed[index]?.inspectionError)) {
            return failed("target_inspection")
          }
          // requiresFullApproval (opaque/exec-domain/capability) events never
          // get a positive cache entry: executable identity + argv still does
          // not bind the script's indirect, mutable inputs — an unchanged exe
          // does not make a later effect the same operation. Deny stays
          // cacheable (a negative verdict is a fact, not a grant). Every
          // future positive needs a fresh review, while non-opaque L1/L2 keep
          // their per-object monitoring ('continue', never a tree detach).
          const storable = result.decision !== "allow" ||
            !(facts.requiresFullApproval ?? false)
          if (!hit && storable) approvalCache.store(scope, facts, result)
          if (result.decision !== "allow") {
            const refusal = reviewRefusal(result)
            return blocked(refusal.reason, refusal.advice)
          }
          rememberAllowedWrite(event)
          authorization.source = hit ? `cache:${hit.layer}` : result.source
          authorization.cacheUpdates ??= []
          authorization.cacheUpdates.push({ scope, facts })
          if (canWrite) authorization.executionRoute = "host_direct_reviewed"
          // A reviewed requiresFullApproval crossing (interop/opaque) detaches
          // the tree in either mode — 'continue' cannot resume it. In a
          // read-only session the read-only conformance answer stands in for
          // the write ceiling on everything the tree does next.
          return { action: canWrite || event.details.requiresFullApproval === true ? "allow" : "continue" }
          } catch (error) {
            // Any infrastructure error while judging a crossing still has
            // to record the refusal: the broker replies 'deny', and without
            // runtimeBlocked the command would die with a bare 126 and no
            // reason anywhere (foreground notice AND metadata depend on it).
            return failed("boundary_inspection")
          }
        },
      })
      if (preparationSignal.aborted) {
        await broker.close()
        throw new EffectsReviewError("the call was cancelled before it started", "aborted")
      }
      authorization.runtimeBroker = broker
      authorization.executionRoute = "runtime_boundary_watch"
      authorization.source = "runtime_boundary_watch"
      raw.command = insertSandboxMarker(sandboxMarkers, command, "workspace", undefined, undefined, { runtimeWatch: {
        helperPath: DEFAULT_BOUNDARY_WATCH_HELPER, socketPath: broker.socketPath, token: broker.token,
        roots, denyRead: [...resolved.sandbox.denyRead, ...readOnlyDenyRead],
        denyWrite: [...deniedWritePaths, path.dirname(broker.socketPath)],
        // The broker socket dir, the watcher binary and the package's own
        // executable code always gate on write — in EITHER direction: a
        // write inside them or a rename/unlink/chmod on any ancestor swaps
        // the control plane mid-command. This holds even when the session
        // workspace IS this repository. Not content review: integrity.
        protect: [path.dirname(broker.socketPath), DEFAULT_BOUNDARY_WATCH_HELPER,
          PACKAGE_ROOT, ...temporaryWriteRoots, ...observedWriteRoots],
        // Explicit/worktree roots stay observed for per-target exclusions;
        // L3 roots also re-check expiry/revocation on every write. Safe local
        // continuations do not need another static/JEV review.
        // Read only passes only the global temp roots (see runBoundaryBefore),
        // so writes there run and every other write is a boundary event the
        // broker refuses; the helper's all-writes switch would block temp too.
        readonly: false,
        failOpen: resolved.failPolicy === "fail_open",
        // The helper waits at most this long for one decision; the review
        // path can spend up to two model rounds plus bounded evidence
        // collection. Cancellation still fails closed (deny), not pass.
        approveTimeoutMs: resolved.dynamicReview.timeoutMs * 2 + 20_000,
      } })
    }

    async function runBoundaryBefore(
      tool: NativeBoundaryTool,
      input: unknown,
      call: BoundaryInvocation,
      token: object,
      signal: AbortSignal,
    ): Promise<{ input: unknown; authorization: BoundaryAuthorization }> {
      await hydratePermAncestry(call.sessionID)
      const info = await run(ctx.session.get({ sessionID: call.sessionID }), signal) as { location?: { directory?: unknown } }
      bindSessionHome(call.sessionID, info)
      if (typeof info?.location?.directory !== "string" || !info.location.directory) {
        throw new SecurityCheckFailure("session_workspace", "the plugin could not get this session's workspace directory from the host")
      }
      const directory = info.location.directory
      // The admission snapshot binds EVERYTHING a granted call relies on —
      // not just the bypass lease: the effective r/w ceiling (so a mid-review
      // /perm downgrade cannot leave an admitted write runnable), the derived
      // mode, categories, custom scopes and the kill switch.
      const securitySnapshot = securitySnapshotFor(call.sessionID)
      const raw = structuredClone(input) as Record<string, unknown>
      const authorization: BoundaryAuthorization = { token, sessionID: call.sessionID, tool, cwd: directory, source: "static_allow", securitySnapshot }
      // Effective Bypass mode, captured ONCE for the whole admission: the
      // kill switch is live AND the effective ceiling can write
      // (securityModeFor reads an armed-but-RO-capped lease as ReadOnly).
      // Everything below keys off this flag instead of re-reading raw lease
      // state mid-flight — an armed-but-capped session keeps the slow gate,
      // classification and effects review like any other non-Bypass call.
      const bypassEffective = effectiveMode(call.sessionID) === "bypass"
      if (bypassEffective) {
        // Every plugin check is skipped for real — canonicalization, static
        // classification, the slow-command soft gate, the reviewable path
        // plan + fingerprint binding, and effects review. What stays: a
        // nonempty command (input executability), the cancel check, and the
        // admission-snapshot bind — plus the explicit "full" marker so
        // create.before leaves the spawn unwrapped. The workdir passes
        // through verbatim: Bypass must not inherit the sandbox planner's
        // path constraints.
        authorization.source = "bypass_all"
        authorization.executionRoute = "host_direct_reviewed"
        let command: string | undefined
        if (tool === "shell") {
          command = commandFromArgs(raw)
          if (typeof command !== "string" || !command.trim()) {
            throw blockedRejection("the shell command is empty")
          }
        }
        if (signal.aborted) throw new EffectsReviewError("the call was cancelled before it started", "aborted")
        if (securitySnapshotFor(call.sessionID) !== securitySnapshot) {
          throw blockedRejection(
            "the session's security mode changed while this command was being checked",
            RECHECK,
          )
        }
        if (tool === "shell") {
          raw.command = insertSandboxMarker(sandboxMarkers, command ?? "", "full")
        }
        boundaryCalls.set(boundaryKey(call), authorization)
        return { input: raw, authorization }
      }
      const absoluteWorkspace = nativeAbsolutePath(directory, ".")
      const cwd = await canonicalBoundaryPath(absoluteWorkspace)
      if (cwd !== absoluteWorkspace) {
        throw new SecurityCheckFailure("workspace_noncanonical", "the session's workspace path is not canonical (for example, it goes through a symbolic link), so paths cannot be checked reliably")
      }
      if (cwd === path.parse(cwd).root) {
        throw new SecurityCheckFailure("workspace_unsupported", "the session's workspace is the filesystem root, which this plugin does not support for native tools")
      }
      const workspaceIdentity = await lstat(cwd).catch((error: unknown) => {
        throw new BoundaryPreparationError("Workspace inspection is unavailable", `the session workspace metadata could not be inspected (${inspectionErrorCode(error)})`)
      })
      if (!workspaceIdentity.isDirectory()) throw new SecurityCheckFailure("workspace_unsupported", "the session's workspace is not a local directory")
      const bypass = activeBypass(call.sessionID)
      const custom = activeCustomBypass(call.sessionID)
      const scratchRoot = await canonicalBoundaryPath(resolved.sandbox.scratch)
      if (scratchRoot !== resolved.sandbox.scratch) {
        throw new SecurityCheckFailure("scratch_noncanonical", "the plugin's configured temporary directory is not a canonical path; this is a configuration problem")
      }
      // Auto and ReadOnly share the incidental tool cache/history roots
      // (~/.cache, *.sqlite_history-style files): a read-oriented command's
      // own history/cache effect is not a boundary crossing. On top of those,
      // ReadOnly keeps only the global temp directories (scratch, /tmp,
      // /var/tmp, TMPDIR, WSL's Windows %TEMP%) writable. The workspace stays
      // read-only even when it lives inside one of them.
      const readOnly = !effectivePerm(call.sessionID).w
      const credentialPaths = await Promise.all(credentialStoreReadPaths(homedir()).map((target) => canonicalBoundaryPath(target)))
      const incidental = incidentalWriteRoots().filter((root) =>
        !credentialPaths.some((credential) => containsPath(credential, root)) &&
        !checkPathSensitivity(root, { cwd, worktree: cwd }).sensitive)
      const configuredRoots = resolved.sandbox.allowWrite.filter((root) => !writeRootRejection(root, {
        home: homedir(), cwd, credentialPaths, denyWrite: resolved.sandbox.denyWrite,
        protect: [PACKAGE_ROOT, DEFAULT_BOUNDARY_WATCH_HELPER], brokerBase: "/tmp/opencode",
      }))
      // A linked git worktree's private metadata directory (resolved from the
      // cwd/.git pointer and fully verified — see linkedWorktreePrivateDir)
      // is part of the session's writable surface for SHELL commands in
      // Auto/write sessions: git's routine bookkeeping there (index, HEAD,
      // reflogs) must not cost a boundary review. Read-only sessions stay
      // unchanged, native file tools keep their normal plan, and the root
      // passes the same exclusions as configured incidental roots
      // (denyWrite/protect/credential/sensitivity/canonicality) — any
      // verification or exclusion failure simply yields no extra root.
      let worktreePrivateRoots: string[] = []
      if (tool === "shell" && !readOnly) {
        const candidate = await linkedWorktreePrivateDir(cwd)
        if (candidate && !writeRootRejection(candidate, {
          home: homedir(), cwd, credentialPaths, denyWrite: resolved.sandbox.denyWrite,
          protect: [PACKAGE_ROOT, DEFAULT_BOUNDARY_WATCH_HELPER], brokerBase: "/tmp/opencode",
        })) worktreePrivateRoots = [candidate]
      }
      let temporaryRoots: string[] = []
      if (tool === "shell" && rootWidening.hasGrants(call.sessionID)) {
        try { temporaryRoots = rootWidening.activeRoots((await rootWideningContext(call.sessionID)).scope) } catch {
          writeReviewerTrace({ kind: "l3_root_error", sessionID: call.sessionID, policyVersion: L3_POLICY_VERSION })
        }
      }
      const tempRoots = readOnly
        ? [...new Set([...(await globalTempWriteRoots([scratchRoot])), ...incidental, ...configuredRoots])]
        : []
      const baseRoots = [cwd, scratchRoot, ...(readOnly ? tempRoots : [...new Set([...standardCacheWriteRoots(), ...incidental, ...configuredRoots, ...temporaryRoots, ...worktreePrivateRoots])])]
      const beyondReadOnlyTemp = (writes: readonly string[]) => readOnly
        ? writes.filter((target) => containsPath(cwd, target) || !tempRoots.some((root) => containsPath(root, target)))
        : writes
      if (tool === "shell") {
        const command = commandFromArgs(raw)
        if (typeof command !== "string" || !command.trim()) throw blockedRejection("the shell command is empty")
        if (!readOnly) {
          const floorCheck = await classifyShellCommand({
            script: command, cwd, worktree: cwd, shell: resolveClassifierShell(configuredShell),
            strictness: resolved.strictness, bypassedCategories: bypass,
            permScope: effectivePerm(call.sessionID), roWritableRoots: baseRoots,
            sandboxDenyWrite: resolved.sandbox.denyWrite, trustedCommands: resolved.trustedCommands,
          })
          if (floorCheck.verdict === "DENY" && floorCheck.rules.some(isFloorRule)) {
            throw blockedRejection(`Static restriction: ${conciseReason(floorCheck.reason, 300)}`, WITHIN_MODE)
          }
        }
        if (readOnly) {
          const launchCwd = await canonicalBoundaryPath(typeof raw.workdir === "string" ? nativeAbsolutePath(cwd, raw.workdir) : cwd)
          const plan = await planShellBoundary(command, { cwd: launchCwd, shell: resolveClassifierShell(configuredShell), writableRoots: baseRoots })
          assertNativeCeiling(tool, call.sessionID, beyondReadOnlyTemp(plan.resolvedWrites))
          // Launch gate under the read-only ceiling: a statically proven
          // write (permission.write DENY — redirects outside roots, rm/mv/cp,
          // sed -i, git commit/push, kill, package installs, remote-write
          // HTTP methods, floor rules) is refused before the command starts
          // and never reaches the reviewer. Everything else — ASK signals
          // including permission.exec-unproven, the unproven channel — runs
          // under the runtime observer, which reviews each crossing.
          const launch = await classifyShellCommand({
            script: command, cwd, worktree: cwd, shell: resolveClassifierShell(configuredShell),
            ...(launchCwd !== cwd ? { runtimeWorkdir: launchCwd } : {}),
            strictness: resolved.strictness,
            bypassedCategories: bypass.size ? bypass : undefined,
            permScope: effectivePerm(call.sessionID),
            roWritableRoots: tempRoots,
            sandboxDenyWrite: [...resolved.sandbox.denyWrite, ...credentialPaths, cwd],
            trustedCommands: resolved.trustedCommands,
          })
          if (launch.verdict === "DENY" && launch.rules.some((rule) => rule === "permission.write" || isFloorRule(rule))) {
            throw blockedRejection(`Static restriction: ${conciseReason(launch.reason, 300)}`, ancestryUnresolved(call.sessionID) ? RETRY_LATER : WITHIN_MODE)
          }
        }
        if (effectivePerm(call.sessionID).w && (!resolved.sandbox.enabled || resolved.sandbox.mode === "full" || bypass.has("sandbox"))) {
          authorization.source = "sandbox_disabled"
          authorization.executionRoute = "host_direct_reviewed"
          raw.command = insertSandboxMarker(sandboxMarkers, command, "full")
        } else {
          authorization.runtimeStats = { crossings: 0, reviewRequests: 0, cacheHits: 0, staticAllows: 0 }
          // The ReadOnly observer gets only the temp roots + incidental
          // cache/history roots: writes there run; every other write
          // (including the workspace) is a refused event. Credential stores
          // the observer's leaf scan does not see (e.g. ~/.aws, ~/.kube) are
          // added as deny-read so a read becomes a reviewable event instead
          // of running silently.
          await prepareRuntimeShell(command, raw, call, authorization, cwd,
            readOnly ? tempRoots : baseRoots, signal, [...credentialPaths, ...(readOnly ? [cwd] : [])],
            readOnly ? credentialPaths : [], temporaryRoots, [...configuredRoots, ...worktreePrivateRoots])
        }
        boundaryCalls.set(boundaryKey(call), authorization)
        return { input: raw, authorization }
      }
      // A native write tool is itself a proven write, even when aimed at a
      // temp/cache path. Incidental exemptions belong to observed CLI effects.
      if (readOnly) assertNativeCeiling(tool, call.sessionID, [])
      const filePlan = await planFileBoundary(tool, raw, { cwd: directory, writableRoots: baseRoots, bypassCategories: bypass })
      authorization.filePlan = filePlan
      const operation = filePlan.command
      const facts = filePlan.facts
      const files = filePlan.targets.map((target) => ({ path: target.resolved, kind: "native_file_target", role: target.mode, bytes: target.identity?.size ?? 0 }))
      const subjects = filePlan.targets.map((target) => target.resolved)
      const needsReview = filePlan.verdict !== "ALLOW"
      const tempOnly = readOnly && filePlan.resolvedWrites.length > 0 && beyondReadOnlyTemp(filePlan.resolvedWrites).length === 0
      assertNativeCeiling(tool, call.sessionID, filePlan.resolvedWrites, tempOnly)
      if (filePlan.targets.some((target) => target.mode !== "read" &&
        [...resolved.sandbox.denyWrite, ...credentialPaths, DEFAULT_BOUNDARY_WATCH_HELPER, PACKAGE_ROOT]
          .some((root) => containsPath(root, target.resolved)))) {
        throw rejectionError(actionBeforeText("Write protection: the target is protected or explicitly denied", nativeActionTrigger(tool, filePlan), WITHIN_MODE))
      }
      if (filePlan.targets.some((target) => target.inspectionError) && resolved.failPolicy === "fail_open") {
        throw new SecurityCheckFailure("target_inspection", "the native target evidence could not be inspected")
      }
      if (tempOnly) authorization.tempOnlyWrite = true
      // RO conformance remains independent of dynamic-review switches.
      if (needsReview && (readOnly || (resolved.securityEnabled && !bypass.has("dynamic")))) {
        if (!ctx.session.context) throw new SecurityCheckFailure("session_context", "the safety review could not read this session's context, so the command could not be approved")
        const retained = boundarySessionContext(await run(ctx.session.context({ sessionID: call.sessionID }), signal))
        const request: EffectReviewRequest = {
          command: operation,
          cwd,
          environment: JSON.stringify(detectEnvironment()),
          user_request: retained.userRequest,
          session_context: retained.context,
          input_facts: [...facts, `Workspace-write base roots: ${JSON.stringify(baseRoots)}`, `Independent session read/write ceiling: ${permLabel(effectivePerm(call.sessionID))}`,
            ...(readOnly ? [
              "Session security mode: [Read only]",
              `Read-only session: writes are permitted only inside these roots and the exempt tool cache/history effects (any __pycache__ or .pytest_cache path component): ${JSON.stringify(tempRoots)}`,
            ] : [])],
          files,
          sandbox: {
            trigger: `native ${tool} path preflight`,
            resolved_writes: filePlan.resolvedWrites,
            domain: null,
            error: null,
          },
          bypass: {
            categories: STATIC_BYPASS_CATEGORIES.filter((category) => bypass.has(category)),
            custom: custom.length ? custom.join("\n") : null,
          },
        }
        const audit: BoundaryReviewAudit = {
          sessionID: call.sessionID,
          callID: call.id,
          commandSha256: createHash("sha256").update(operation).digest("hex"),
          tool,
          staticRules: [],
        }
        const cacheScope: ApprovalCacheScope = { sessionID: call.sessionID, securitySnapshot,
          userAuthorizationDigest: digest(retained.userRequest) }
        const fileReviewPolicyVersion = readOnly ? EFFECTS_POLICY_VERSION_READONLY : EFFECTS_POLICY_VERSION
        const cacheTargets = await currentCacheTargets(filePlan.targets.map((target) => ({ path: target.resolved,
          domain: /^\/mnt\/[a-z](?:\/|$)/i.test(target.resolved) ? "drvfs" : "linux", exists: target.identity !== undefined,
          ...(target.inspectionError ? { inspectionError: target.inspectionError } : {}) }))).then((targets) => targets.map((target, index) => ({
            ...target, ...(filePlan.targets[index]?.inspectionError ? { inspectionError: filePlan.targets[index]!.inspectionError } : {}),
          })))
        const cacheOperation = filePlan.targets.some((target) => target.mode === "delete") ? "delete"
          : tool === "patch" && /^\*\*\* Move to:/m.test(String(raw.patchText)) ? "rename" : "modify"
        // Same core rule as runtime crossings: resolved targets + identities
        // + tool + mode, never the raw tool input text or user_request — a
        // rewritten file body replays the same adjudication.
        const cacheFacts: ApprovalCacheFacts = {
          coreDigest: boundaryCoreDigest({
            kind: filePlan.resolvedWrites.length ? "write" : "read",
            operation: cacheOperation,
            effect: filePlan.resolvedWrites.length ? "replace" : undefined,
            targets: cacheTargets, tool, cwd,
            policyVersion: fileReviewPolicyVersion,
            bypassCategories: request.bypass.categories, customBypass: custom,
            requiresFullApproval: filePlan.resolvedWrites.length > 0 && filePlan.targets.some((target) => target.mode === "read"),
          }),
          kind: filePlan.resolvedWrites.length ? "write" : "read",
          operation: cacheOperation,
          targets: cacheTargets,
          requiresFullApproval: filePlan.resolvedWrites.length > 0 && filePlan.targets.some((target) => target.mode === "read"),
          // write/edit/patch rewrite the whole file content.
          ...(filePlan.resolvedWrites.length ? { effect: "replace" as const } : {}),
        }
        const cacheHit = approvalCache.lookup(cacheScope, cacheFacts)
        let result: EffectReviewResult
        try {
          if (cacheHit) {
            result = cacheHit.result!
            writeReviewerTrace({ kind: "effects_cache_hit", sessionID: call.sessionID, callID: call.id,
              commandSha256: audit.commandSha256, layer: cacheHit.layer, decision: cacheHit.decision })
          } else {
            result = await sharedReviews.run(digest(JSON.stringify([cacheScope, cacheFacts.coreDigest])), signal,
              (sharedSignal) => reviewBoundaryRequest(request, subjects, sharedSignal, cwd, audit, readOnly))
          }
        } catch (error) {
          const source = error instanceof EffectsReviewError ? error.kind : "infrastructure"
          if (source === "aborted") {
            throw new EffectsReviewError("the call was cancelled before it started", "aborted")
          }
          throw new EffectsReviewError(reviewUnavailableReason(source), source)
        }
        if (result.decision !== "allow") {
          try { if (!cacheHit) approvalCache.store(cacheScope, cacheFacts, result) } catch {
            passFailure("cache_store", call, authorization)
          }
          assertBoundaryDecision(result, nativeActionTrigger(tool, filePlan))
        }
        const latest = boundarySessionContext(await run(ctx.session.context({ sessionID: call.sessionID }), signal))
        if (securitySnapshotFor(call.sessionID) !== securitySnapshot ||
          // Positive reuse (cached or freshly reviewed) is not bound to the
          // user message; a refusal is — a newer message re-checks it.
          (result.decision !== "allow" && digest(latest.userRequest) !== cacheScope.userAuthorizationDigest)) {
          throw blockedRejection("the session's authorization changed during the boundary check", RECHECK)
        }
        await verifyFileBoundaryPlan(filePlan)
        if (!cacheHit) approvalCache.store(cacheScope, cacheFacts, result)
        writeReviewerTrace({
          kind: "effects_boundary_outcome",
          sessionID: call.sessionID,
          callID: call.id,
          commandSha256: audit.commandSha256,
          reviewer: cacheHit ? "approval_cache" : injectedEffectsReview ? "test_injection" : "jev",
          decision: result.decision,
          source: result.source,
          floor: result.floor,
          uncoveredOwner: result.uncoveredOwner,
          policyVersion: fileReviewPolicyVersion,
        })
        assertBoundaryDecision(result, nativeActionTrigger(tool, filePlan))
        authorization.source = cacheHit ? `cache:${cacheHit.layer}` : result.source
        authorization.cacheUpdates = [{ scope: cacheScope, facts: cacheFacts }]
      } else if (needsReview) {
        // Review-skipping sources on the normal path are only the
        // fine-grained `dynamic` switch or a fully disabled security layer —
        // never a raw ALL lease (effective Bypass returned earlier).
        authorization.source = bypass.has("dynamic") ? "bypass_dynamic" : "security_disabled"
      }
      await hydratePermAncestry(call.sessionID)
      assertNativeCeiling(tool, call.sessionID, filePlan.resolvedWrites, tempOnly)
      await verifyFileBoundaryPlan(filePlan)
      if (signal.aborted) throw new EffectsReviewError("the call was cancelled before it started", "aborted")
      // Re-check the WHOLE admission basis — ceiling and mode, not only the
      // bypass lease: an opaque/variable command whose writes could not be
      // enumerated must not survive an Auto→ReadOnly transition that happened
      // while the reviewer was thinking.
      if (securitySnapshotFor(call.sessionID) !== securitySnapshot) {
        throw blockedRejection(
          "the session's security mode changed while this command was being checked",
          RECHECK,
        )
      }
      authorization.executionRoute = "host_direct_reviewed"
      boundaryCalls.set(boundaryKey(call), authorization)
      return { input: raw, authorization }
    }

    async function prepareBoundary(
      tool: NativeBoundaryTool, input: unknown, call: BoundaryInvocation, token: object, signal: AbortSignal,
    ): Promise<{ input: unknown; authorization: BoundaryAuthorization }> {
      const snapshot = securitySnapshotFor(call.sessionID)
      try {
        return await runBoundaryBefore(tool, input, call, token, signal)
      } catch (error) {
        if (signal.aborted || error instanceof EffectsReviewError && error.kind === "aborted") {
          throw new EffectsReviewError("the call was cancelled before it started", "aborted")
        }
        if ((error as { _tag?: string })?._tag === "Tool.Error") throw error
        if (resolved.failPolicy === "fail_close") throw error
        if (securitySnapshotFor(call.sessionID) !== snapshot) {
          throw blockedRejection("the session's security mode changed while this command was being checked", RECHECK)
        }
        // Preserve the known ceiling even when another part of checking failed.
        assertNativeCeiling(tool, call.sessionID, [])
        const authorization: BoundaryAuthorization = {
          token, sessionID: call.sessionID, tool, cwd: process.cwd(),
          source: "fail_open_pass", securitySnapshot: snapshot, executionRoute: "host_direct_reviewed",
        }
        let code = "check_unavailable"
        if (error instanceof SecurityCheckFailure) code = error.code
        else if (error instanceof EffectsReviewError) code = `review_${error.kind}`
        else if (error instanceof BoundaryPreparationError) code = error.changed ? "target_changed" : "boundary_preparation"
        if (!passFailure(code, call, authorization)) throw error
        boundaryCalls.set(boundaryKey(call), authorization)
        // No marker: if the observer cannot be prepared, the original executor
        // receives the exact original input and runs unobserved, once.
        return { input, authorization }
      }
    }

    // The nonce is the authority for Linux wrapping. Marker-less user shells
    // and host-internal spawns remain untouched; Windows is outside this chain.
    yield* ctx.shell.hook("create.before", (ev: ShellCreateBeforeEvent) =>
      Effect.sync(() => {
        if (process.platform !== "linux") return
        const marked = extractSandboxMarker(sandboxMarkers, ev.command)
        const original = { command: marked.command, shell: ev.shell, env: { ...ev.env } }
        try {
          applySandboxCreateBefore(ev, marked, resolved.sandbox, sandboxProbe, undefined, resolved.failPolicy,
            (code) => { passFailure(code) })
        } catch (error) {
          if (!passFailure("sandbox_prepare")) throw error
          ev.command = original.command
          ev.shell = original.shell
          ev.env = original.env
        }
      }),
    )

    // --- 2. subagent ceiling bookkeeping (tool.execute.before) --------------
    // The native wrapper (runBoundaryBefore) owns all shell/file admission;
    // this hook only handles the subagent `permission` argument — a declared
    // child ceiling stripped before the host tool sees it and bound to the
    // spawned child once session.created/execute.after identify it. Agents
    // can only tighten here (the declared set is intersected); the three
    // user modes (incl. Bypass) are not agent-settable through this arg —
    // `bypass`/`all`/`yolo` are not permission spellings and are rejected.
    async function runBefore(ev: ExecuteBeforeEvent): Promise<void> {
      await hydratePermAncestry(ev.sessionID)
      if (!(ev.tool === "subagent" && resolved.permission.subagentPermission)) return
      const input = ev.input as Record<string, unknown> | undefined
      const declared = input?.permission
      if (typeof declared === "string" && declared.trim()) {
        const mode = parseSecurityMode(declared)
        if (mode === undefined || mode === "bypass") {
          // Never echo the raw value — an agent could paste something
          // sensitive into it. Subagent rejections get their own envelope:
          // no command was ever going to run here.
          throw rejectionError(
            subagentBlockedText(
              `the permission argument must be "readonly" or "auto" (Bypass mode is a user command and cannot be selected here)`,
            ),
          )
        }
        const perm = permForMode(mode)
        if (typeof input.sessionID === "string") {
          await hydratePermAncestry(input.sessionID)
          if (ancestryUnresolved(input.sessionID) && passFailure("session_ancestry", { sessionID: ev.sessionID, id: ev.id })) {
            delete input.permission
            return
          }
          if (permParent.get(input.sessionID) !== ev.sessionID) {
            throw rejectionError(subagentBlockedText("sessionID must name a direct child session"))
          }
          // Barrier FIRST: the notice/RPC sync below must already observe
          // the declared mode — a parent's armed Bypass must not show
          // through while the ceiling lands.
          explicitNoBypass.add(input.sessionID)
          sessionPerms.set(input.sessionID, permIntersect(sessionPerms.get(input.sessionID) ?? PERM_FULL, perm))
          notifySecurityState(input.sessionID, "updated", "set")
        } else {
          permStash.set(ev.id, { parentSessionID: ev.sessionID, perm, at: Date.now(), declared: true })
        }
        delete input.permission
      } else if (declared !== undefined) {
        delete input.permission
      }
      if (!input?.sessionID && !permStash.has(ev.id)) {
        permStash.set(ev.id, { parentSessionID: ev.sessionID, perm: PERM_FULL, at: Date.now() })
      }
    }

    // Wrap only the captured executable definitions. No hook-name heuristic
    // can accidentally pull a codemode/MCP/custom/Windows tool into this chain.
    if (process.platform === "linux") {
      if (!ctx.tool.transform && !passFailure("boundary_transform")) return yield* Effect.die(new Error("Native Linux boundaries require tool.transform"))
      if (ctx.tool.transform) yield* ctx.tool.transform((editor) => {
        if (!editor.list) {
          if (passFailure("boundary_transform")) return
          throw new Error("Native Linux boundaries require ToolEditor.list")
        }
        const entries = editor.list()
        directSubagent = entries.some((entry) => entry.id === "subagent" && entry.name === "subagent" &&
          entry.options?.codemode === false && entry.options.namespace === undefined)
        for (const entry of entries) {
          if (!isBoundaryTool(entry)) continue
          editor.update(entry.id!, (tool) => {
            const original = tool.execute
            if (!original) {
              if (passFailure("boundary_executor")) return
              throw new Error("Native Linux tool is missing its executor")
            }
            const name = entry.name as NativeBoundaryTool
            tool.execute = (input, call) => {
              const token = {}
              const key = boundaryKey(call)
              return Effect.gen(function* () {
                const prepared = yield* Effect.tryPromise({
                  try: (signal) => prepareBoundary(name, input, call, token, signal),
                  catch: toRejection,
                })
                const result = yield* Effect.withFiber((fiber) => {
                  prepared.authorization.cancelExecution = () => fiber.interruptUnsafe()
                  return original(prepared.input, call)
                })
                prepared.authorization.cancelExecution = undefined
                const shellResult = result && typeof result === "object" ? (result as { output?: { exit?: number; status?: string } }).output : undefined
                // Only a runtime-watched shell may keep its authorization +
                // broker past the tool return: for every other route the
                // approval stays scoped to this call. Letting a plain
                // background shell retain `boundaryCalls` would leak an
                // unrestrained grant.
                prepared.authorization.background = name === "shell" &&
                  shellResult?.status === "running" &&
                  prepared.authorization.runtimeBroker !== undefined
                if (!prepared.authorization.background) {
                  yield* Effect.promise(() => recordCallCacheOutcome(prepared.authorization,
                     name === "shell" ? shellResult?.exit : 0).catch(() => { passFailure("cache_outcome", call, prepared.authorization) }))
                } else {
                  // A completed Promise also handles very short jobs whose
                  // terminal notification preceded this background result.
                  void prepared.authorization.runtimeBroker?.finished.then(async ({ exit }) => {
                    await recordCallCacheOutcome(prepared.authorization, exit).catch(() => { passFailure("cache_outcome", call, prepared.authorization) })
                    if (boundaryCalls.get(key)?.token === token) boundaryCalls.delete(key)
                    await prepared.authorization.runtimeBroker?.close()
                  }).catch(() => {})
                }
                if (!result || typeof result !== "object") return result
                const value = result as { output?: unknown; content?: unknown; metadata?: Record<string, unknown> }
                const output = value.output && typeof value.output === "object" ? value.output as Record<string, unknown> : undefined
                // Exclude our own pre-spawn denial text: a nested tool
                // call's "Command blocked … The whole command was not run."
                // output must not be dressed up as a post-launch OS error.
                const runtimeRefusal = prepared.authorization.runtimeBlocked
                  ? runtimeBlockedText(prepared.authorization.runtimeBlocked,
                      prepared.authorization.runtimeBlockDetails) : undefined
                const accessError = !runtimeRefusal && name === "shell" && output && output.exit !== 0 &&
                  typeof output.output === "string" && !output.output.includes("The whole command was not run.") &&
                  /permission denied|read-only file system|device or resource busy|cross-device link|\bEACCES\b|\bEPERM\b|sudo:|bwrap:|opencode-sandbox:/i.test(output.output)
                // Post-launch OS errors keep their raw output; the appended
                // note (agent-messages.ts) only explains that this is an OS
                // result, not a plugin block — never a retry hint.
                const notice = runtimeRefusal ?? accessErrorNote(prepared.authorization.executionRoute === "host_direct_reviewed")
                const appendNotice = runtimeRefusal
                  ? !String(output?.output ?? "").includes(runtimeRefusal)
                  : accessError
                return {
                  ...value,
                  ...(appendNotice ? {
                    output: { ...output, output: `${output!.output}\n\n${notice}` },
                    content: typeof value.content === "string" ? `${value.content}\n\n${notice}`
                      : [...(Array.isArray(value.content) ? value.content : []), { type: "text", text: notice }],
                  } : {}),
                  metadata: {
                    ...value.metadata,
                    boundary: {
                      source: prepared.authorization.source,
                      policyVersion: EFFECTS_POLICY_VERSION,
                      automaticRuntimeRetry: false,
                      ...(prepared.authorization.executionRoute
                        ? { executionRoute: prepared.authorization.executionRoute }
                        : {}),
                       ...(accessError ? { runtimeAccessError: true } : {}),
                       ...(runtimeRefusal ? { runtimeBlocked: true } : {}),
                       ...(prepared.authorization.failOpenPasses ? { failOpenPasses: [...prepared.authorization.failOpenPasses] } : {}),
                       // Copy by value + mark finality: for a background
                       // command the counters keep mutating under the live
                       // broker; the host must not stamp mid-flight stats as
                       // final on the already-returned result.
                       ...(prepared.authorization.runtimeStats ? { runtimeStats: {
                           ...prepared.authorization.runtimeStats,
                           final: !prepared.authorization.background } } : {}),
                    },
                  },
                }
              }).pipe(Effect.ensuring(Effect.promise(async () => {
                const authorization = boundaryCalls.get(key)
                if (authorization?.token !== token) return
                if (authorization.background) return
                boundaryCalls.delete(key)
                await authorization.runtimeBroker?.close()
              })))
            }
          })
        }
      })
    }
    yield* ctx.tool.hook("execute.before", (ev: ExecuteBeforeEvent) =>
      // Admission for native boundary tools lives entirely in the wrapped
      // executor (runBoundaryBefore); this hook only carries the optional
      // subagent `permission` ceiling bookkeeping.
      process.platform === "linux" && directSubagent && ev.tool === "subagent"
        ? Effect.tryPromise({ try: async () => {
            try { await runBefore(ev) } catch (error) {
              if ((error as { _tag?: string })?._tag === "Tool.Error" || !passFailure("tool_preflight", { sessionID: ev.sessionID, id: ev.id })) throw error
            }
          }, catch: toRejection })
        : Effect.void,
    )

    // --- 3. failure recording (v1 tool.execute.after) -----------------------
    // execute.after failure channel is `never`: any exception is swallowed so a
    // post-check error never fails the tool step.
    async function runAfter(ev: ExecuteAfterEvent): Promise<void> {
      // A mode change during a run reaches the model with the next completed
      // tool result instead of waiting for the next user prompt. Prepended:
      // the host truncates long results from the tail.
      if (ev.status === "completed" && ev.result) {
        const notice = sessionNotices.takeForToolResult(ev.sessionID)
        if (notice) ev.result.content = [{ type: "text", text: notice }, ...toolResultContent(ev.result)]
      }
      // Only the tool result identifies a spawn's child authoritatively.
      if (ev.tool === "subagent") {
        const stash = permStash.get(ev.id)
        if (stash) {
          // Consume the stash on EVERY outcome — completed, failed or
          // cancelled: a leftover declaration would keep tightening (and
          // barrier-ing) later siblings it was never declared for.
          permStash.delete(ev.id)
          const rawOutput = ev.result?.output
          const childID =
            (typeof ev.result?.metadata?.sessionID === "string" && ev.result.metadata.sessionID) ||
            (rawOutput && typeof rawOutput === "object" && typeof (rawOutput as Record<string, unknown>).sessionID === "string"
              ? ((rawOutput as Record<string, unknown>).sessionID as string)
              : undefined)
          if (childID) {
            // Bind whenever the result names the child — even on a
            // non-completed status the child exists and was created under
            // the declared ceiling. Keep real child restrictions, but never
            // persist a speculative intersection with a sibling's
            // declaration. Ancestry caps live.
            const childPerm = permIntersect(sessionPerms.get(childID) ?? PERM_FULL, stash.perm)
            sessionPerms.set(childID, childPerm)
            permParent.set(childID, stash.parentSessionID)
            permBoundChildren.add(childID)
            if (stash.declared) explicitNoBypass.add(childID)
            notifySecurityState(childID, "updated", "spawned")
          }
          // The stash no longer tightens (or barriers) this parent's still-
          // unbound children — refresh their notices and RPC snapshots so
          // nothing keeps showing the now-consumed declaration's effects.
          for (const [child, parent] of permParent) {
            if (parent !== stash.parentSessionID || permBoundChildren.has(child) || child === childID) continue
            syncSecurityNotice(child)
            emitPermChanged(child, "updated")
            emitBypassChanged(child, "updated")
          }
          // The bound child published itself (notifySecurityState); the
          // consumed-stash transition above is parent-scoped, so publish the
          // parent — every instance's reaction re-syncs the parent's subtree.
          publishSharedStateChange(stash.parentSessionID)
        }
      }
      // Legacy shell failure caches/HARD interrupts do not participate in the
      // new pipeline, and excluded tools must not be inspected here.
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
    // `session.created` records parent→child links so subagents inherit an
    // armed bypass (bypassPropagateToSubagents, default true). Activity events
    // deliberately do NOT renew leases: expiry is an absolute deadline so a
    // user-set timeout (and the default) means exactly that long.
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
                bypassLeases.delete(sessionID)
                bypassParent.delete(sessionID)
                sessionPerms.delete(sessionID)
                permParent.delete(sessionID)
                permCreatedAt.delete(sessionID)
                permBoundChildren.delete(sessionID)
                permKnownRoots.delete(sessionID)
                permUnresolved.delete(sessionID)
                explicitNoBypass.delete(sessionID)
                sessionNotices.clear(sessionID)
                approvalCache.clear(sessionID)
                securityBases.delete(sessionID)
                securityEpochs.delete(sessionID)
                shared.sessionLocations.delete(sessionID)
                rootWidening.clearSession(sessionID)
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
            if (e?.type === "session.created") {
              const parentID = e.data?.parentID
              if (typeof sessionID === "string") {
                // Creation time gates which pending spawn declarations can
                // belong to this child (effectivePerm/pendingDeclaredSpawn
                // apply a stash entry only when entry.at <= createdAt).
                permCreatedAt.set(sessionID, Date.now())
                if (typeof parentID === "string" && parentID) {
                  permParent.set(sessionID, parentID)
                  bypassParent.set(sessionID, parentID)
                }
                // A fresh session has no notice yet — publish its effective
                // state (inherited lease, pending declared cap, or a clean
                // default) regardless of the propagate flag. Links are set
                // first so the effective readers see the parent.
                syncSecurityNotice(sessionID)
              }
              return
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
          Effect.promise(async () => {
            // Hydrate the chain first: the effective ceiling/mode (and any
            // inherited clamp) is only accurate once the ancestor links are
            // known — a status pull must never report a stale-lifted baseline.
            // ONE clock capture for the whole snapshot, the hydration's notice
            // sync included: active, ALL and expiresAt must describe the same
            // instant (see emitBypassChanged).
            const now = Date.now()
            await hydratePermAncestry(input.sessionID, now)
            const active = activeForRpc(input.sessionID, now)
            const result: Record<string, unknown> = {
              sessionID: input.sessionID,
              permission: permLabel(effectivePerm(input.sessionID, now)),
              mode: effectiveMode(input.sessionID, now),
              active,
              temporary: active.filter((category) => !policyForSession(input.sessionID).permanentBypass.includes(category as BypassCategory)),
              permanent: [...policyForSession(input.sessionID).permanentBypass].sort(),
            }
            const custom = activeCustomBypass(input.sessionID, now)
            if (custom.length > 0) result.custom = custom
            // Same optional-presence rule as the `changed` event: a present
            // `expiresAt: undefined` fails the output schema; omit the key
            // when no live lease exists, keep `null` for a never-expiring one.
            const expiresAt = leaseExpiryForRpc(input.sessionID, now)
            if (expiresAt !== undefined) result.expiresAt = expiresAt
            return result
          }),
      })
    // --- 8c. lease expiry sweep ---------------------------------------------
    // Lease pruning is otherwise lazy (activeBypass merely skips expired
    // entries), so without a timer the expiry transition — the agent reminder
    // and the user notification — would never fire. The delay adapts to the
    // soonest expiry so a short user-set timeout notifies promptly, and any
    // lease mutation opens the wake latch to recompute the deadline.
    yield* Effect.forever(
      Effect.gen(function* () {
        sweepExpiredBypass()
        rootWidening.sweep()
        Latch.closeUnsafe(bypassSweepWake)
        yield* Effect.race(Effect.sleep(nextBypassSweepDelay()), Latch.await(bypassSweepWake))
      }),
    ).pipe(Effect.forkScoped)

    // --- 8e. session rwx permission layer -----------------------------------
    // Structural enforcement only: the permission.evaluate hook (primary
    // channel, every tool's action flows through it), the classifier's
    // permScope fallback for write-shaped shell segments, and the
    // set_permission native tool. All transitions are transitions-notified:
    // the agent gets an append-only user notice, the user an RPC event.

    // Only an active native wrapper may authorize a permission hook. Unknown
    // actions, MCP, other direct tools, Code Mode and Windows stay untouched.
    // An explicit host/config deny remains final; ask is resolved without UI.
    if (ctx.permission) {
      yield* ctx.permission.hook("evaluate", (ev: PermissionEvalEvent) =>
        Effect.promise(async () => {
          if (process.platform !== "linux" || !ev.source) return
          const authorization = boundaryCalls.get(boundaryKey({ sessionID: ev.sessionID, ...ev.source }))
          if (!authorization || ev.effect === "deny") return
          try {
          await hydratePermAncestry(ev.sessionID)
          // A real tool may assert several times in one call
          // (external_directory + edit, multi-file patches). Once the first
          // assert was allowed, earlier steps may already have run — a later
          // denial must not claim the whole command never ran.
          const deny = (reason: string, advice?: string) => {
            ev.effect = "deny"
            ev.message = authorization.asserted ? actionBlockedText(reason, advice) : blockedText(reason, advice)
          }
          // Last gate before the action runs: the admission was computed
          // against a security snapshot (effective r/w ceiling + mode +
          // bypass lease). If the user reverted it mid-flight — e.g. Auto →
          // ReadOnly while the review was pending — the wrapped admission is
          // stale and the action must not run, even when the shell command's
          // writes were never enumerable.
          if (securitySnapshotFor(ev.sessionID) !== authorization.securitySnapshot) {
            deny("the session's security mode changed while this command was being checked", RECHECK)
            return
          }
          const expected = authorization.tool === "shell" ? "shell"
            : ["write", "edit", "patch"].includes(authorization.tool) ? "edit" : authorization.tool
          if (ev.action !== expected && ev.action !== "external_directory") {
            deny(`the tool requested an unexpected permission (${ev.action}) that was not part of this call's check`)
            return
          }
          const required = requiredPermBit(ev.action, resolved.permission.actionPerm)
          const perm = effectivePerm(ev.sessionID)
          // A temp-only ReadOnly file write still passes through the plan's
          // exact resource check below; the snapshot check above already
          // rescinds it if the mode changed.
          const tempOnlyWrite = required === "w" && authorization.tempOnlyWrite === true && ev.action === "edit"
          if (required && !perm[required] && !tempOnlyWrite) {
            const unresolved = required === "w" && ancestryUnresolved(ev.sessionID)
            const mode = securityModeFor(perm, allBypassed(ev.sessionID))
            deny(
              unresolved
                ? "the plugin could not verify this session's parent sessions, so write actions are blocked for now"
                : mode === "readonly"
                  ? required === "w"
                    ? "this session is in [Read only] mode: write, edit, move and delete actions are blocked"
                    : "this session is in [Read only] mode: native file reads are blocked"
                  : `the session permission ceiling does not allow '${required}' actions`,
              unresolved ? RETRY_LATER : undefined,
            )
            return
          }
          const plan = authorization.filePlan
          if (plan) {
            const resources = new Set(plan.targets.flatMap((target) => ev.action === "external_directory"
              ? [path.join(path.dirname(target.absolute), "*"), path.join(target.absolute, "*")]
              : [target.absolute, target.resolved, path.relative(authorization.cwd, target.absolute) || "."]))
            if (ev.action === authorization.tool && plan.searchPattern !== undefined) {
              resources.clear()
              resources.add(plan.searchPattern)
            }
            if (ev.resources.some((resource) => !resources.has(resource))) {
              deny("the tool tried to use a path that was not part of this call's check")
              return
            }
            try { await verifyFileBoundaryPlan(plan) } catch (error) {
              if (passFailure(error instanceof BoundaryPreparationError && error.changed ? "target_changed" : "target_inspection", { sessionID: ev.sessionID, id: ev.source.id }, authorization)) {
                authorization.asserted = true
                ev.effect = "allow"
                return
              }
              deny(
                error instanceof BoundaryPreparationError
                  ? error.agentReason
                  : "a reviewed target changed after admission; this call's authorization is no longer valid",
                RECHECK,
              )
              return
            }
          }
          // The first allowed assert marks the call partially runnable:
          // later denies of the same call use the action-level wording.
          authorization.asserted = true
          ev.effect = "allow"
          } catch (error) {
            if (securitySnapshotFor(ev.sessionID) !== authorization.securitySnapshot) {
              ev.effect = "deny"
              ev.message = actionBlockedText("the session's security mode changed while this command was being checked")
              return
            }
            if (passFailure("permission_check", { sessionID: ev.sessionID, id: ev.source.id }, authorization)) {
              ev.effect = "allow"
              return
            }
            ev.effect = "deny"
            ev.message = toRejection(error).message
          }
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
            "Restrict a direct subagent's security mode.",
            "Use readonly to block its writes, or auto to keep it out of Bypass mode.",
            "This only tightens; it never widens. Only the user can select Bypass mode.",
            "sessionID must be a direct child of this session.",
          ].join(" "),
          input: {
            type: "object",
            properties: {
              permission: {
                type: "string",
                description: "Security mode for the child session: 'readonly' blocks its writes outside temporary directories; 'auto' keeps it out of Bypass mode. Tighten-only; Bypass mode is user-only.",
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
              const mode = typeof rawPerm === "string" ? parseSecurityMode(rawPerm) : undefined
              if (mode === undefined || mode === "bypass") {
                // Never echo the raw value back — it could carry something
                // sensitive the agent pasted by accident.
                return yield* Effect.fail(
                  rejectionError(
                    permissionChangeRejectedText(
                      `the permission argument must be "readonly" or "auto" (Bypass mode is user-only)`,
                    ),
                  ),
                )
              }
              const perm = permForMode(mode)
              const callerID = context.sessionID
              const targetID = typeof args.sessionID === "string" ? args.sessionID.trim() : ""
              if (!targetID) {
                return yield* Effect.fail(
                  rejectionError(permissionChangeRejectedText("sessionID is required: name the direct child session to restrict")),
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
                if (!info && passFailure("session_lookup", { sessionID: callerID, id: "set_permission" })) {
                  return {
                    content: [{ type: "text", text: "Permission update skipped because session verification is unavailable; existing permissions are unchanged." }],
                    metadata: { failOpenPasses: ["session_lookup"] },
                  }
                }
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
                // The barrier must be in place BEFORE writeSessionPerm runs:
                // its notice/RPC sync computes the effective mode, and
                // without the barrier a parent's armed Bypass would still
                // show through. Roll it back if the write fails so a
                // rejected tighten leaves no state behind.
                const hadBarrier = explicitNoBypass.has(targetID)
                explicitNoBypass.add(targetID)
                const result = writeSessionPerm(targetID, perm, false)
                if (!result.ok) {
                  if (!hadBarrier) explicitNoBypass.delete(targetID)
                  failure = result.error
                } else {
                  // The declared mode masked inherited Bypass: descendants'
                  // effective state and the TUI badge move too.
                  syncBypassDescendants(targetID)
                  emitBypassChanged(targetID, "updated")
                }
              }
              if (failure) {
                return yield* Effect.fail(rejectionError(permissionChangeRejectedText(failure)))
              }
              return {
                content: [
                  {
                    type: "text",
                    text: `Subagent ${targetID} is now in ${securityModeLabel(effectiveMode(targetID))}.`,
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
                "\nOptional permission: readonly or auto. It sets the new subagent's security mode and can only tighten: the subagent never gets more than your current mode, and any declared value keeps it out of Bypass mode. Without it, the subagent inherits your current mode. Only the user can select Bypass mode."
              const input = tool.input
              if (input && typeof input === "object" && !Array.isArray(input)) {
                const schema = input as { type?: string; properties?: Record<string, unknown> }
                if (schema.type === "object" && schema.properties && typeof schema.properties === "object") {
                  schema.properties.permission = {
                    type: "string",
                    description:
                      "Security mode for the spawned session: 'readonly' blocks its writes outside temporary directories; 'auto' keeps it out of Bypass mode. Can only tighten; Bypass mode is user-only.",
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
    // User authority over the session's security mode and its r/w ceiling.
    // Mode spellings: readonly|ro|r|read|... → ReadOnly, auto|rw|w|... →
    // Auto, bypass|all|*|yolo → Bypass — the SAME transition as /bypass all
    // (stash + lift this session's own baseline, arm the kill switch;
    // ancestors still cap the effective set, so an RO ancestor clamps it to
    // ReadOnly). Every other perm write is also a mode assertion: it disarms
    // a locally armed Bypass mode first so the stashed baseline is restored.
    // Arguments never reach the model; invalid input fails the command (the
     // TUI turns it into a usage toast). Transitions append a user notice
     // without waking the session, plus RPC `permission`/`changed` events.
    yield* ctx.command.transform((draft) => {
      draft.add({
        name: "perm",
        description:
          "Set this session's security mode or permission ceiling: /perm <readonly|ro|auto|rw|bypass|all|*|yolo|none|0> or bit ops +r -r +w -w +rw -rw [sessionID] — user authority (may widen; ancestors still cap)",
        execute: (input) =>
          Effect.gen(function* () {
            const sessionID = input.sessionID
            const tokens = (input.prompt?.text ?? "").split(/\s+/).filter(Boolean)
            const usage =
              "Usage: /perm <readonly|ro|auto|rw|bypass|all|none|0> or bit ops +r -r +w -w +rw -rw [sessionID] — " +
              "readonly = [Read only], auto = [Auto mode], bypass = [Bypass mode] (same as /bypass all); " +
              "x cannot be set; it is always on and only shown in the label."
            if (tokens.length === 0) {
              return yield* Effect.fail(new Error(usage))
            }
            // Bit ops start from the session's OWN baseline (entry or the
            // configured default), never the effective set: the ancestor cap
            // still applies on top, exactly like the absolute form.
            let target = sessionID
            let working: Perm | undefined
            let sawPerm = false
            let sawBypassMode = false
            for (const token of tokens) {
              const lower = token.toLowerCase()
              if (/^[+-][rwx]+$/.test(lower)) {
                if (lower.includes("x")) {
                  return yield* Effect.fail(
                    new Error("x cannot be set; it is always on and only shown in the label."),
                  )
                }
                if (working === undefined) working = { ...(sessionPerms.get(target) ?? policyForSession(target).defaultPerm) }
                const set = lower[0] === "+"
                if (lower.includes("r")) working.r = set
                if (lower.includes("w")) working.w = set
                sawPerm = true
                continue
              }
              // Bypass-mode tokens are a mode transition, not a ceiling value.
              if (parseSecurityMode(token) === "bypass") {
                sawBypassMode = true
                continue
              }
              const absolute = parsePerm(token)
              if (absolute) {
                // The last absolute perm token wins (mixed absolute+ops apply
                // in order). readonly/auto spellings land here — they are
                // exactly permForMode(readonly|auto).
                working = absolute
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
            if (sawBypassMode && sawPerm) {
              return yield* Effect.fail(new Error(usage))
            }
            // Hydrate the target's ancestry so the descendant check (and the
            // clamp the transition observes) is authoritative.
            yield* Effect.promise(() => hydratePermAncestry(target))
            if (target !== sessionID && !isPermDescendant(sessionID, target)) {
              return yield* Effect.fail(new Error(`Session ${target} is not a descendant of this session`))
            }
            if (sawBypassMode) {
              applyUserSecurityMode(target, "bypass")
              return
            }
            if (!sawPerm || working === undefined) {
              return yield* Effect.fail(new Error(usage))
            }
            // An explicit perm write is an assertion of a non-Bypass surface:
            // disarm a locally armed kill switch first so the stashed
            // pre-Bypass baseline is restored before the new one lands. The
            // write is also an inheritance barrier — the session must not
            // observe an ancestor's armed Bypass mode after the user
            // explicitly set its ceiling.
            const lease = bypassLeases.get(target)
            const disarmed = lease?.all === true
            if (disarmed) setBypassKillSwitch(target, false)
            explicitNoBypass.add(target)
            const result = writeSessionPerm(target, working, true)
            if (!result.ok) {
              return yield* Effect.fail(new Error(result.error ?? "Permission could not be applied"))
            }
            if (disarmed) {
              syncSecurityNotice(target)
              syncBypassDescendants(target)
              emitBypassChanged(target, "updated")
            }
          }).pipe(Effect.ensuring(Effect.promise(() => sessionNotices.flush()))),
      })
    })

    // --- 8d. /bypass server command (formerly /bypass-classifier) -----------
    // Server-registered slash command: the TUI autocomplete lists it and
    // submission routes through client.api.session.command, so the arguments
    // never reach the model. State changes live only in this plugin process
    // (see bypassLeases). Invalid input fails the command, which the TUI turns
    // into an error toast carrying the usage. The agent is told of effective-set
     // transitions via an append-only user notice (except the `slow`
    // category, which never notifies the agent); the user, via the RPC event.
    //   /bypass <cat...>        arm categories (additive; space or comma separated)
    //   /bypass <cat...> 120    arm with a 120-second absolute timeout
    //   /bypass <cat...> 0      arm with no natural expiry (until /bypass off)
    //   /bypass all|*|ALL|yolo  Bypass mode: every plugin check skipped for
    //                           this session (same transition as /perm bypass)
    //   /bypass off             clear the session's lease, including the mode
    yield* ctx.command.transform((draft) => {
      draft.add({
        name: "bypass",
        description:
           `Toggle/arm bypass categories for this session (${BYPASS_CATEGORIES.join("|")}; legacy: fs=filesystem, os=host+privilege+indirection, web=network+remote; all/*/ALL/yolo = Bypass mode — all plugin checks skipped for this session, the permission ceiling still applies; prefer specific categories when possible; off/0=clear; +token arms, -token disarms, bare token toggles; a trailing number is the timeout in seconds — absolute deadline, activity never extends it, <=0=no natural expiry)`,
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
            const snapshotCustom = activeCustomBypass(sessionID)
            const wasActive = snapshot.size > 0 || snapshotAll || snapshotCustom.length > 0
            let baselineTouched = false
            // The mode transition notifies once itself; the handler must not
            // emit a second `changed` toast for the same transition.
            let modeTransitionNotified = false
            for (const op of args.ops) {
              if (op.kind === "clear") {
                // Clearing ends the whole lease: categories, custom scopes AND
                // the Bypass kill switch — with the stashed pre-Bypass
                // baseline restored (lease lifetime rule).
                const lease = bypassLeases.get(sessionID)
                if (lease) {
                  expireLease(sessionID, lease)
                  baselineTouched = baselineTouched || lease.all === true
                }
                continue
              }
              if (op.kind === "killSwitch") {
                const act = op.action === "toggle" ? (snapshotAll ? "disarm" : "arm") : op.action
                if (act === "arm") {
                  applyUserSecurityMode(sessionID, "bypass", args.timeoutSec)
                  modeTransitionNotified = true
                } else {
                  setBypassKillSwitch(sessionID, false)
                }
                baselineTouched = true
                continue
              }
              if (op.kind === "custom") {
                const prior = bypassLeases.get(sessionID)
                bypassLeases.set(sessionID, {
                  categories: new Set(prior?.categories ?? []),
                  all: prior?.all,
                  custom: [...new Set([...(prior?.custom ?? []), op.text])],
                  expiresAt: bypassExpiry(args.timeoutSec),
                  restoreBaseline: prior?.all === true ? prior.restoreBaseline : undefined,
                })
                continue
              }
              // Category op: the target set starts from the session's current
              // active set (own lease plus inherited parents) so a second
              // invocation keeps previously armed categories.
              const targets: BypassCategory[] = [...op.which]
              const act = op.action === "toggle"
                ? (targets.every((t) => snapshot.has(t)) ? "disarm" : "arm")
                : op.action
              const next = activeBypass(sessionID)
              if (act === "arm") for (const c of targets) next.add(c)
              else for (const c of targets) next.delete(c)
              armBypassLease(sessionID, next, args.timeoutSec)
            }
            // The timeout applies to the session's overall lease: it can
            // re-point the expiry of an existing lease, and an arm without a
            // timeout resets to the configured default. A timeout that leaves
            // no live lease ("/bypass off 120", or a bare timeout on a session
            // with no bypass) is an explicit error.
            if (args.timeoutSec !== undefined) {
              const lease = bypassLeases.get(sessionID)
              if (!lease) {
                return yield* Effect.fail(
                  new Error("No active bypass lease to set a timeout on — arm categories first, e.g. /bypass fs 120"),
                )
              }
              bypassLeases.set(sessionID, { ...lease, expiresAt: bypassExpiry(args.timeoutSec) })
            }
            wakeBypassSweep()
            const nowActive = activeBypass(sessionID)
            const nowAll = allBypassed(sessionID)
            const nowCustom = activeCustomBypass(sessionID)
            const changed =
              snapshotAll !== nowAll ||
              snapshot.size !== nowActive.size || [...snapshot].some((c) => !nowActive.has(c)) ||
              snapshotCustom.length !== nowCustom.length || snapshotCustom.some((c, i) => nowCustom[i] !== c)
            const cleared = nowActive.size === 0 && !nowAll && nowCustom.length === 0
            const reason = !changed ? "status" : cleared ? "cleared" : wasActive ? "updated" : "armed"
            syncSecurityNotice(sessionID)
            syncBypassDescendants(sessionID)
            if (!modeTransitionNotified) {
              emitBypassChanged(sessionID, reason)
              if (baselineTouched) emitPermChanged(sessionID, "set")
            }
            publishSharedStateChange(sessionID)
          }).pipe(Effect.ensuring(Effect.promise(() => sessionNotices.flush()))),
      })
    })

    // Instance-bound cleanup when the plugin scope finalizes (unload). The
    // forked event fiber is interrupted by the same scope close, and the
    // shared-state listener is removed so a reloaded instance cannot leak a
    // dead one. Shared security state is deliberately NOT cleared: other
    // instances in this process still serve sessions keyed by it, and a
    // location re-boot must reload into the existing state (leases stay
    // memory-only and end with the process or their own deadline).
    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        await Promise.all([...boundaryCalls.values()].map((authorization) => authorization.runtimeBroker?.close()))
        sharedReviews.clear()
        sandboxMarkers.clear()
        boundaryCalls.clear()
        unsubscribeSharedState()
        bypassRpc = undefined
      }),
    )
  }),
}

export default plugin
// Test-only helper: replace the process-wide shared security-state registry
// (see src/security/shared-state.ts). Existing harnesses call this before
// instantiating the plugin so each simulated instance set starts isolated.
export { resetSharedSecurityStateForTests } from "./security/shared-state"
export type { BypassLease, PermStashEntry, SharedSecurityState } from "./security/shared-state"
export { linkedWorktreePrivateDir } from "./security/worktree-roots"
export { classifyShellCommand, verifyScriptFingerprints } from "./security/classifier"
export { isFloorRule, ruleRequiredCategories, rulesHintCategories } from "./security/bypass"
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
  parseSecurityMode,
  permEqual,
  permForMode,
  permIntersect,
  permLabel,
  permSubset,
  fallbackPermBit,
  requiredPermBit,
  securityModeFor,
  securityModeLabel,
  tightenPerm,
} from "./permissions"
export type { Perm, SecurityMode } from "./permissions"
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

import { lstatSync } from "node:fs"
import { isIP } from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"
import {
  reviewCommandWithAuditor,
  type CloudReviewRequest,
  type CloudReviewResult,
  type ReviewCommandOptions,
} from "./security/reviewer"
import { DEFAULT_ACTION_PERM, parsePerm, PERM_FULL, type Perm } from "./permissions"
import {
  BYPASS_CATEGORIES,
  LEGACY_CATEGORY_ALIASES,
  expandBypassCategoryToken,
  type BypassCategory,
} from "./categories"

export {
  BYPASS_CATEGORIES,
  LAYER_BYPASS_CATEGORIES,
  LEGACY_CATEGORY_ALIASES,
  STATIC_BYPASS_CATEGORIES,
  expandBypassCategoryToken,
  isStaticBypassCategory,
  type BypassCategory,
  type StaticBypassCategory,
} from "./categories"

export type Strictness = "LOOSE" | "HARD"
export type FailPolicy = "fail_ask" | "fail_open" | "fail_close"

/** Escape-hatch categories the user can arm permanently (config.json
 * `BypassClassifier`) or per-session (`/bypass`). `dynamic` skips the dynamic
 * reviewer entirely, `sandbox` resolves the OS-sandbox profile to "full" (no
 * bwrap wrap — the kernel layer only), `slow` skips the slow-command
 * classifier, and the others disable matching static rule groups and relax
 * the dynamic reviewer's prompt for that session.
 *
 * `all` is deliberately NOT a category: it is the session-level kill switch
 * (`/bypass all`, session-only) that disables every plugin enforcement layer.
 * `*` is the command-side "arm every category" token. Neither is valid in the
 * permanent `BypassClassifier` config list. */
const DEFAULT_BYPASS_LEASE_TTL_MS = 20 * 60 * 1000
const MIN_BYPASS_LEASE_TTL_MS = 60_000
const MAX_BYPASS_LEASE_TTL_MS = 24 * 60 * 60 * 1000

/** Which dynamic reviewer engine to consult (default "auto"). "auto" tries
 * the Jev reviewer when `dynamicReview.jev` is configured and falls back to
 * the OpenAI-compatible auditor on infrastructure failures. */
export type DynamicReviewerEngine = "jev" | "openai" | "auto"

export type JevReviewOptions = {
  /** Master switch; default true when the jev object is present. */
  enabled?: boolean
  /** Default "jev-1.13". */
  model?: string
  /** Default "https://opencode.ai/zen/v1/systemone". */
  endpoint?: string
  /** Environment variable holding the Jev key (default "JEV_API_KEY"; the
   * "OC_API_KEY" env var is accepted as a fallback). */
  apiKeyEnv?: string
  [key: string]: unknown
}

export type DynamicReviewOptions = {
  baseURL?: string
  model?: string
  apiKey?: string
  apiKeyEnv?: string
  timeoutMs?: number
  maxRounds?: number
  /** Allow the auditor's bounded read-only tools to inspect the full filesystem. */
  allowFullReadAccess?: boolean
  /** Python interpreter for the auditor. A bare command name (no path separator)
   * defers to PATH lookup at spawn time; a path containing a separator is resolved
   * relative to the package root and must be an existing regular file. */
  pythonPath?: string
  /** Path to the auditor script. Relative paths resolve against the package root
   * and must point to an existing regular file (directories are rejected). */
  auditorPath?: string
  /** Reviewer engine selection: "jev", "openai", or "auto" (default). */
  reviewer?: DynamicReviewerEngine
  /** Jev (systemone) reviewer configuration. */
  jev?: JevReviewOptions
  [key: string]: unknown
}

export type ReviewCommand = (
  request: CloudReviewRequest,
  options: ReviewCommandOptions,
) => Promise<CloudReviewResult>

export type SlowCommandsOptions = {
  enabled?: boolean
  maxDepth?: number
  sleepThresholdSeconds?: number
  allowExplicitTimeout?: boolean
  [key: string]: unknown
}

export type BashClassifierOptions = {
  shell?: string
  securityEnabled?: boolean
  detachedStartIsolation?: boolean
  supervisorEnabled?: boolean
  supervisorPath?: string
  strictness?: Strictness
  failPolicy?: FailPolicy
  dynamicReview?: DynamicReviewOptions
  /** Block (static DENY) safe-but-wasteful commands: unbounded scans of
   * system/mounted trees, streaming commands, and over-long sleeps.
   * When `true` (default) enables the slow-command classifier. When an object,
   * `enabled` toggles it independently. */
  slowCommands?: boolean | SlowCommandsOptions
  /** Append one JSONL line to ~/.opencode/reviewer-trace.jsonl for every
   * dynamic review (verdict or error) and every dynamic cache hit. */
  logReviewerTrace?: boolean
  /** Permanently armed escape-hatch categories (all sessions, all clients). */
  BypassClassifier?: Array<BypassCategory | keyof typeof LEGACY_CATEGORY_ALIASES>
  /** Activity-renewed lease TTL for temporary per-session bypass entries, in
   * milliseconds. Default 20 minutes. */
  bypassLeaseTtlMs?: number
  /** Whether a session's temporary bypass also covers its subagent children
   * (default true). */
  bypassPropagateToSubagents?: boolean
  /** Session r/w permission layer: tighten-only capability ceiling per
   * session (x is reserved and not enforced in this MVP). See README
   * "Session permissions". */
  permission?: PermissionOptions
  /** Whether agents may request one-shot escalations via the
   *  `# - REQUIRE_ESCALATION` header protocol (default true). When false the
   *  header is inert (a leading comment, not a request), no reviewer is
   *  consulted for it, and no agent-facing text mentions the mechanism. */
  escalationEnabled?: boolean
  /** OS-level sandbox (Linux only): bwrap namespace+seccomp floor plus a
   * Landlock write-freeze for read-only profiles. See plan §4. */
  sandbox?: SandboxOptions
  /** Test-injection only; never wired by the plugin itself. */
  reviewCommand?: ReviewCommand
  [key: string]: unknown
}

export type ResolvedJevReview = {
  /** Configured and a key resolved — usable by reviewer:"jev"/"auto". */
  available: boolean
  endpoint: string
  model: string
  apiKey?: string
  /** Human-readable unavailability reason; never contains secrets. */
  reason?: string
}

export type ResolvedDynamicReview = {
  available: boolean
  endpoint?: string
  model?: string
  apiKey?: string
  timeoutMs: number
  maxRounds: number
  pythonPath?: string
  auditorPath?: string
  allowFullReadAccess: boolean
  reviewer: DynamicReviewerEngine
  /** Jev reviewer settings; absent when dynamicReview.jev is not configured. */
  jev?: ResolvedJevReview
  /** Human-readable unavailability reason; never contains secrets. */
  reason?: string
}

export type ResolvedSlowCommands = {
  enabled: boolean
  maxDepth: number
  sleepThresholdSeconds: number
  allowExplicitTimeout: boolean
}

export type PermissionOptions = {
  /** Baseline perm applied to every session ('ro'/4, 'rw'/6, 'w'/2,
   * 'none'/0; x-bearing values are rejected). Default full (unrestricted). */
  default?: string
  /** Count webfetch/websearch as `r` (default true). */
  webIsRead?: boolean
  /** Expose the `set_permission` native tool to the model (default true). */
  registerTool?: boolean
  /** Accept a `permission` argument on the subagent tool (default true). */
  subagentPermission?: boolean
  /** Override the action → required-bit map (e.g. { "webfetch": "w" }; an
   * "x" value hard-denies the action under every restricted session, since
   * x cannot be granted in this MVP). */
  actionMap?: Record<string, "r" | "w" | "x">
  /** Gate unmapped actions (MCP composed `${server}_${tool}` names) behind
   * the write bit (default true — read-only sessions deny the whole MCP
   * class). Set false to leave unknown actions ungated. */
  gateUnknownActions?: boolean
  [key: string]: unknown
}

export type ResolvedPermission = {
  /** Baseline applied to every session on first sight (and as the ancestor
   * ceiling for sessions without their own baseline). */
  defaultPerm: Perm
  /** action → required permission bit, web entries removed when webIsRead is
   * false and user overrides applied last. */
  actionPerm: Record<string, keyof Perm>
  /** Whether unmapped actions (MCP composed names) require the write bit. */
  gateUnknownActions: boolean
  /** Actions deliberately ungated (webIsRead:false) — exempt from the
   * unmapped-action fallback. */
  ungatedActions: ReadonlySet<string>
  registerTool: boolean
  subagentPermission: boolean
}

export type SandboxMode = "auto" | "ro" | "rw" | "full"
export type SandboxOnUnavailable = "fail_close" | "degrade"

export type SandboxOptions = {
  /** Master switch; default true on Linux, ignored (forced off) elsewhere. */
  enabled?: boolean
  /** "auto" derives the profile per call from effectivePerm (w=false → ro,
   * w=true → rw); "ro"/"rw" force that profile; "full" disables the wrap. */
  mode?: SandboxMode
  /** bwrap binary; absolute path or a bare name resolved by the helper. */
  bwrapPath?: string
  /** Prebuilt helper override; "" resolves to <package>/bin/opencode-sandbox. */
  helperPath?: string
  /** The only RO-writable hierarchy; must be an absolute, non-traversal path. */
  scratch?: string
  /** "off" (default) = RO gets --unshare-net + Landlock TCP deny. */
  roNetwork?: "off" | "on"
  /** "on" (default) = RW keeps network access; "off" applies the same
   * --unshare-net + Landlock TCP deny to the RW profile. */
  rwNetwork?: "on" | "off"
  /** Extra paths write-frozen (denyWrite) or read-shadowed (denyRead) on top
   * of the profile's base rules; colon-joined into OPENCODE_SANDBOX_DENY_*
   * envs. Entries must be absolute, contain no ":" or "..", and may not be
   * "/" or the scratch dir. The same path may appear in both lists — the
   * helper applies read-shadow first, then write-freeze. */
  denyWrite?: string[]
  denyRead?: string[]
  /** Allow sudo/setuid escalation (default false). Honest semantics: bwrap
   * sets no_new_privs unconditionally, so the helper treats true on RW as
   * "run the payload host-direct" — no namespace, NNP, or seccomp floor —
   * while RO stays fully isolated and always refuses sudo. */
  allowSudo?: boolean
  /** Raw bwrap argv pass-through: each entry is ONE argv element appended
   * after all helper-generated args, immediately before the `--` payload
   * separator. Applies to ro, rw, and the bwrap-only fallback; later mounts
   * shadow earlier ones (user authority layer). Landlock rules are unaffected.
   * Newline characters are rejected (newline is the env encoding separator). */
  extraArgs?: string[]
  /** RO masks /run/WSL (WSL interop sockets) with a fresh tmpfs. */
  maskWslInterop?: boolean
  /** Privileged sockets masked with `--bind /dev/null <path>` when they exist. */
  maskPrivilegedSockets?: string[]
  /** RO seccomp denies socket/socketpair(AF_UNIX) — the portable docker.sock
   * backstop. */
  roAfUnixBlock?: boolean
  /** Behavior when the sandbox cannot be built: "fail_close" (default) denies
   * shell execution; "degrade" runs classifier-only. */
  onUnavailable?: SandboxOnUnavailable
  [key: string]: unknown
}

export type ResolvedSandbox = {
  enabled: boolean
  mode: SandboxMode
  bwrapPath: string
  helperPath: string
  scratch: string
  roNetwork: "off" | "on"
  rwNetwork: "on" | "off"
  denyWrite: readonly string[]
  denyRead: readonly string[]
  allowSudo: boolean
  extraArgs: readonly string[]
  maskWslInterop: boolean
  maskPrivilegedSockets: readonly string[]
  roAfUnixBlock: boolean
  onUnavailable: SandboxOnUnavailable
}

export type ResolvedPluginConfig = {
  shell?: string
  securityEnabled: boolean
  detachedStartIsolation: boolean
  supervisorEnabled: boolean
  supervisorPath: string
  strictness: Strictness
  failPolicy: FailPolicy
  slowCommands: ResolvedSlowCommands
  logReviewerTrace: boolean
  bypassClassifier: ReadonlySet<BypassCategory>
  bypassLeaseTtlMs: number
  bypassPropagateToSubagents: boolean
  escalationEnabled: boolean
  permission: ResolvedPermission
  sandbox: ResolvedSandbox
  /** Non-fatal BypassClassifier validation warnings (unknown categories). */
  bypassWarnings: readonly string[]
  dynamicReview: ResolvedDynamicReview
  reviewCommand?: ReviewCommand
}

const ALLOWED_TOP_LEVEL = new Set([
  "shell",
  "securityEnabled",
  "detachedStartIsolation",
  "supervisorEnabled",
  "supervisorPath",
  "strictness",
  "failPolicy",
  "dynamicReview",
  "slowCommands",
  "logReviewerTrace",
  "BypassClassifier",
  "bypassLeaseTtlMs",
  "bypassPropagateToSubagents",
  "escalationEnabled",
  "permission",
  "sandbox",
  "reviewCommand",
])

const ALLOWED_PERMISSION_FIELDS = new Set([
  "default",
  "webIsRead",
  "registerTool",
  "subagentPermission",
  "actionMap",
  "gateUnknownActions",
])

const ALLOWED_SLOW_FIELDS = new Set(["enabled", "maxDepth", "sleepThresholdSeconds", "allowExplicitTimeout"])

const ALLOWED_SANDBOX_FIELDS = new Set([
  "enabled",
  "mode",
  "bwrapPath",
  "helperPath",
  "scratch",
  "roNetwork",
  "rwNetwork",
  "denyWrite",
  "denyRead",
  "allowSudo",
  "extraArgs",
  "maskWslInterop",
  "maskPrivilegedSockets",
  "roAfUnixBlock",
  "onUnavailable",
])

const ALLOWED_DYNAMIC_FIELDS = new Set([
  "baseURL",
  "model",
  "apiKey",
  "apiKeyEnv",
  "timeoutMs",
  "maxRounds",
  "allowFullReadAccess",
  "pythonPath",
  "auditorPath",
  "reviewer",
  "jev",
])

const ALLOWED_JEV_FIELDS = new Set(["enabled", "model", "endpoint", "apiKeyEnv"])

const DEFAULT_JEV_ENDPOINT = "https://opencode.ai/zen/v1/systemone"
const DEFAULT_JEV_MODEL = "jev-1.13"
const DEFAULT_JEV_KEY_ENV = "JEV_API_KEY"
const FALLBACK_JEV_KEY_ENV = "OC_API_KEY"

const DEFAULT_TIMEOUT_MS = 30_000
const MIN_TIMEOUT_MS = 1
const MAX_TIMEOUT_MS = 120_000
const MIN_MAX_ROUNDS = 1

const API_KEY_ENV_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/
const FORBIDDEN_KEY_CHARS = /[\r\n\0]/
const MAX_MODEL_LENGTH = 256
const URL_CONTROL_CHARS = /[\u0000-\u001F\u007F]/

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const DEFAULT_SUPERVISOR_PATH = path.join(
  PACKAGE_ROOT,
  "native",
  "windows-bash-supervisor",
  "target",
  "release",
  "bash.exe",
)
const DEFAULT_SANDBOX_HELPER_PATH = path.join(PACKAGE_ROOT, "bin", "opencode-sandbox")

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function resolveTimeoutMs(raw: unknown): { value: number; reason?: string } {
  if (raw === undefined) return { value: DEFAULT_TIMEOUT_MS }
  if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
    return { value: DEFAULT_TIMEOUT_MS, reason: "dynamicReview.timeoutMs must be an integer" }
  }
  if (raw < MIN_TIMEOUT_MS || raw > MAX_TIMEOUT_MS) {
    return {
      value: DEFAULT_TIMEOUT_MS,
      reason: `dynamicReview.timeoutMs must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`,
    }
  }
  return { value: raw }
}

function resolveMaxRounds(raw: unknown, strictness: Strictness): { value: number; reason?: string } {
  const fallback = strictness === "LOOSE" ? 1 : 2
  const limit = strictness === "LOOSE" ? 3 : 5
  if (raw === undefined) return { value: fallback }
  if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
    return { value: fallback, reason: "dynamicReview.maxRounds must be an integer" }
  }
  if (raw < MIN_MAX_ROUNDS || raw > limit) {
    return {
      value: fallback,
      reason: `dynamicReview.maxRounds must be between ${MIN_MAX_ROUNDS} and ${limit} for the selected policy`,
    }
  }
  return { value: raw }
}

function resolveEndpoint(raw: unknown): { endpoint?: string; reason?: string } {
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.baseURL is not configured" }
  }
  const trimmed = raw.trim()
  if (URL_CONTROL_CHARS.test(trimmed)) {
    return { reason: "dynamicReview.baseURL must not contain control characters" }
  }
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return { reason: "dynamicReview.baseURL is not a valid URL" }
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { reason: "dynamicReview.baseURL must use http or https" }
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "")
  const ipVersion = isIP(hostname)
  const loopback =
    hostname === "localhost" ||
    (ipVersion === 4 && hostname.startsWith("127.")) ||
    (ipVersion === 6 && hostname === "::1")
  if (parsed.protocol === "http:" && !loopback) {
    return { reason: "dynamicReview.baseURL may use http only for a loopback host" }
  }
  if (parsed.username || parsed.password) {
    return { reason: "dynamicReview.baseURL must not contain userinfo" }
  }
  if (parsed.hash) {
    return { reason: "dynamicReview.baseURL must not contain a fragment" }
  }
  const query = parsed.search
  let pathname = parsed.pathname.replace(/\/+$/, "")
  if (!pathname.endsWith("/chat/completions")) pathname += "/chat/completions"
  const endpoint = `${parsed.protocol}//${parsed.host}${pathname}${query}`
  return { endpoint }
}

/** Jev endpoint validation: used verbatim (no /chat/completions suffix) —
 * http is allowed only on loopback so tests can point at a local stub. */
function resolveJevEndpoint(raw: unknown): { endpoint?: string; reason?: string } {
  const value = typeof raw === "string" && raw.trim() ? raw.trim() : DEFAULT_JEV_ENDPOINT
  if (URL_CONTROL_CHARS.test(value)) {
    return { reason: "dynamicReview.jev.endpoint must not contain control characters" }
  }
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return { reason: "dynamicReview.jev.endpoint is not a valid URL" }
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "")
  const ipVersion = isIP(hostname)
  const loopback =
    hostname === "localhost" ||
    (ipVersion === 4 && hostname.startsWith("127.")) ||
    (ipVersion === 6 && hostname === "::1")
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    return { reason: "dynamicReview.jev.endpoint must use https (http only for a loopback host)" }
  }
  if (parsed.username || parsed.password) {
    return { reason: "dynamicReview.jev.endpoint must not contain userinfo" }
  }
  if (parsed.hash) {
    return { reason: "dynamicReview.jev.endpoint must not contain a fragment" }
  }
  return { endpoint: `${parsed.protocol}//${parsed.host}${parsed.pathname}${parsed.search}` }
}

function resolveJev(raw: unknown): { jev?: ResolvedJevReview; reason?: string } {
  if (raw === undefined) return {}
  if (!isPlainObject(raw)) return { reason: "dynamicReview.jev must be an object" }
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_JEV_FIELDS.has(key)) {
      return { reason: `dynamicReview.jev contains an unknown field: ${key}` }
    }
  }
  const source = raw as Record<string, unknown>
  if (source.enabled !== undefined && typeof source.enabled !== "boolean") {
    return { reason: "dynamicReview.jev.enabled must be a boolean" }
  }
  if (source.enabled === false) {
    return { jev: { available: false, endpoint: "", model: "", reason: "jev reviewer is disabled" } }
  }
  const endpointResult = resolveJevEndpoint(source.endpoint)
  if (endpointResult.reason) return { reason: endpointResult.reason }
  const modelResult =
    source.model === undefined
      ? { model: DEFAULT_JEV_MODEL }
      : resolveModel(source.model)
  if (modelResult.reason || !modelResult.model) {
    return { reason: modelResult.reason ?? "dynamicReview.jev.model is invalid" }
  }
  const envName = source.apiKeyEnv === undefined ? DEFAULT_JEV_KEY_ENV : source.apiKeyEnv
  if (typeof envName !== "string" || !envName.trim()) {
    return { reason: "dynamicReview.jev.apiKeyEnv must be a non-empty string" }
  }
  if (!API_KEY_ENV_PATTERN.test(envName)) {
    return { reason: "dynamicReview.jev.apiKeyEnv is not a valid environment variable name" }
  }
  const apiKey = (
    process.env[envName] ??
    process.env[FALLBACK_JEV_KEY_ENV] ??
    ""
  ).trim()
  if (!apiKey) {
    return {
      jev: {
        available: false,
        endpoint: endpointResult.endpoint!,
        model: modelResult.model,
        reason: `jev api key is not configured (${envName}${envName === FALLBACK_JEV_KEY_ENV ? "" : ` or ${FALLBACK_JEV_KEY_ENV}`})`,
      },
    }
  }
  if (FORBIDDEN_KEY_CHARS.test(apiKey)) {
    return { reason: "dynamicReview.jev api key contains disallowed control characters" }
  }
  return {
    jev: {
      available: true,
      endpoint: endpointResult.endpoint!,
      model: modelResult.model,
      apiKey,
    },
  }
}

function resolveModel(raw: unknown): { model?: string; reason?: string } {
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.model is not configured" }
  }
  const trimmed = raw.trim()
  if (trimmed.length > MAX_MODEL_LENGTH) {
    return { reason: "dynamicReview.model exceeds the length limit" }
  }
  return { model: trimmed }
}

function resolveApiKey(dynamic: Record<string, unknown>): { apiKey?: string; reason?: string } {
  const hasApiKey = dynamic.apiKey !== undefined
  const hasApiKeyEnv = dynamic.apiKeyEnv !== undefined
  if (hasApiKey && hasApiKeyEnv) {
    return { reason: "provide exactly one of dynamicReview.apiKey or apiKeyEnv" }
  }
  if (!hasApiKey && !hasApiKeyEnv) {
    return { reason: "dynamicReview requires apiKey or apiKeyEnv" }
  }

  let rawKey: string
  if (hasApiKey) {
    if (typeof dynamic.apiKey !== "string") {
      return { reason: "dynamicReview.apiKey must be a string" }
    }
    rawKey = dynamic.apiKey
  } else {
    const envName = dynamic.apiKeyEnv
    if (typeof envName !== "string" || !envName.trim()) {
      return { reason: "dynamicReview.apiKeyEnv must be a non-empty string" }
    }
    if (!API_KEY_ENV_PATTERN.test(envName)) {
      return { reason: "dynamicReview.apiKeyEnv is not a valid environment variable name" }
    }
    const value = process.env[envName]
    if (typeof value !== "string") {
      return { reason: `dynamicReview.apiKeyEnv "${envName}" did not resolve to a value` }
    }
    rawKey = value
  }

  if (FORBIDDEN_KEY_CHARS.test(rawKey)) {
    return { reason: "dynamicReview api key contains disallowed control characters" }
  }
  const key = rawKey.trim()
  if (!key) {
    return { reason: "dynamicReview api key is empty" }
  }
  return { apiKey: key }
}

function isRegularFile(filePath: string): boolean {
  try {
    return lstatSync(filePath).isFile()
  } catch {
    return false
  }
}

function resolveAuditorPath(raw: unknown): { auditorPath?: string; reason?: string } {
  if (raw === undefined) return {}
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.auditorPath must be a non-empty string" }
  }
  const resolved = path.resolve(PACKAGE_ROOT, raw.trim())
  if (!isRegularFile(resolved)) {
    return { reason: "dynamicReview.auditorPath is not an existing regular file" }
  }
  return { auditorPath: resolved }
}

function resolvePythonPath(raw: unknown): { pythonPath?: string; reason?: string } {
  if (raw === undefined) return {}
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.pythonPath must be a non-empty string" }
  }
  const trimmed = raw.trim()
  // A bare command name (no path separator) is left as-is so the reviewer can
  // resolve it through PATH at spawn time; a path with a directory component is
  // resolved against the package root and must be an existing regular file.
  if (!trimmed.includes("/") && !trimmed.includes("\\")) {
    return { pythonPath: trimmed }
  }
  const resolved = path.resolve(PACKAGE_ROOT, trimmed)
  if (!isRegularFile(resolved)) {
    return { reason: "dynamicReview.pythonPath is not an existing regular file" }
  }
  return { pythonPath: resolved }
}

function resolveDynamicReview(raw: unknown, strictness: Strictness): ResolvedDynamicReview {
  const defaultRounds = strictness === "LOOSE" ? 1 : 2
  if (raw === undefined) {
    return {
      available: false,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxRounds: defaultRounds,
      allowFullReadAccess: false,
      reviewer: "auto",
      reason: "dynamic review is not configured",
    }
  }
  if (!isPlainObject(raw)) {
    return {
      available: false,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxRounds: defaultRounds,
      allowFullReadAccess: false,
      reviewer: "auto",
      reason: "dynamicReview must be an object",
    }
  }
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_DYNAMIC_FIELDS.has(key)) {
      return {
        available: false,
        timeoutMs: DEFAULT_TIMEOUT_MS,
        maxRounds: defaultRounds,
        allowFullReadAccess: false,
        reviewer: "auto",
        reason: `dynamicReview contains an unknown field: ${key}`,
      }
    }
  }

  const dynamic = raw as Record<string, unknown>
  const timeout = resolveTimeoutMs(dynamic.timeoutMs)
  const rounds = resolveMaxRounds(dynamic.maxRounds, strictness)
  const allowFullReadAccess = dynamic.allowFullReadAccess
  const endpointResult = resolveEndpoint(dynamic.baseURL)
  const modelResult = resolveModel(dynamic.model)
  const keyResult = resolveApiKey(dynamic)
  const auditorResult = resolveAuditorPath(dynamic.auditorPath)
  const pythonResult = resolvePythonPath(dynamic.pythonPath)
  const jevResult = resolveJev(dynamic.jev)

  let reviewer: DynamicReviewerEngine = "auto"
  const reviewerReason =
    dynamic.reviewer === undefined ||
    dynamic.reviewer === "jev" ||
    dynamic.reviewer === "openai" ||
    dynamic.reviewer === "auto"
      ? undefined
      : 'dynamicReview.reviewer must be "jev", "openai", or "auto"'
  if (dynamic.reviewer === "jev" || dynamic.reviewer === "openai") {
    reviewer = dynamic.reviewer
  }
  if (reviewer === "jev" && !jevResult.jev?.available) {
    // An explicit engine choice without a working Jev config is a hard
    // config error — "auto" would simply never select it, but "jev" has no
    // fallback of its own.
    return {
      available: false,
      timeoutMs: timeout.value,
      maxRounds: rounds.value,
      allowFullReadAccess: false,
      reviewer,
      jev: jevResult.jev,
      reason:
        jevResult.jev?.reason ??
        jevResult.reason ??
        "dynamicReview.jev is not configured",
    }
  }

  const reason =
    endpointResult.reason ??
    modelResult.reason ??
    keyResult.reason ??
    timeout.reason ??
    rounds.reason ??
    auditorResult.reason ??
    pythonResult.reason ??
    jevResult.reason ??
    reviewerReason
  const accessReason =
    allowFullReadAccess === undefined || typeof allowFullReadAccess === "boolean"
      ? undefined
      : "dynamicReview.allowFullReadAccess must be a boolean"
  const unavailableReason = reason ?? accessReason
  if (unavailableReason) {
    return {
      available: false,
      timeoutMs: timeout.value,
      maxRounds: rounds.value,
      allowFullReadAccess: false,
      reviewer,
      jev: jevResult.jev,
      reason: unavailableReason,
    }
  }

  return {
    available: true,
    endpoint: endpointResult.endpoint,
    model: modelResult.model,
    apiKey: keyResult.apiKey,
    timeoutMs: timeout.value,
    maxRounds: rounds.value,
    pythonPath: pythonResult.pythonPath,
    auditorPath: auditorResult.auditorPath,
    allowFullReadAccess: allowFullReadAccess === true,
    reviewer,
    jev: jevResult.jev,
  }
}

function resolveBypassCategories(raw: unknown): { value: ReadonlySet<BypassCategory>; warnings: string[] } {
  if (raw === undefined) return { value: new Set(), warnings: [] }
  if (!Array.isArray(raw)) throw new Error("BypassClassifier must be an array of category strings")
  const warnings: string[] = []
  const value = new Set<BypassCategory>()
  for (const item of raw) {
    if (typeof item !== "string") {
      warnings.push("BypassClassifier contains a non-string entry that was ignored")
      continue
    }
    // "all"/"ALL" are the session-level kill-switch spellings and "*" is the
    // command-side "arm every category" token — /bypass syntax, never
    // permanent config entries. Rejecting (not warning) keeps a config
    // mistake loud.
    if (item.trim() === "all" || item.trim() === "ALL" || item.trim() === "*") {
      throw new Error(
        `BypassClassifier entry "${item.trim()}" is not a category: "all"/"ALL"/"*" are session-only /bypass syntax`,
      )
    }
    const expanded = expandBypassCategoryToken(item)
    if (!expanded) {
      warnings.push(`BypassClassifier contains an unknown category "${item.trim()}" that was ignored`)
      continue
    }
    if (Object.hasOwn(LEGACY_CATEGORY_ALIASES, item.trim().toLowerCase())) {
      warnings.push(
        `BypassClassifier category "${item.trim()}" is deprecated and expands to ${expanded.join(", ")}`,
      )
    }
    for (const category of expanded) value.add(category)
  }
  return { value, warnings }
}

function resolveBypassLeaseTtlMs(raw: unknown): number {
  if (raw === undefined) return DEFAULT_BYPASS_LEASE_TTL_MS
  if (
    typeof raw !== "number" ||
    !Number.isFinite(raw) ||
    !Number.isInteger(raw) ||
    raw < MIN_BYPASS_LEASE_TTL_MS ||
    raw > MAX_BYPASS_LEASE_TTL_MS
  ) {
    throw new Error(
      `bypassLeaseTtlMs must be an integer between ${MIN_BYPASS_LEASE_TTL_MS} and ${MAX_BYPASS_LEASE_TTL_MS}`,
    )
  }
  return raw
}

function resolvePermission(raw: unknown): ResolvedPermission {
  const defaults: ResolvedPermission = {
    defaultPerm: { ...PERM_FULL },
    actionPerm: { ...DEFAULT_ACTION_PERM },
    gateUnknownActions: true,
    ungatedActions: new Set<string>(),
    registerTool: true,
    subagentPermission: true,
  }
  if (raw === undefined) return defaults
  if (!isPlainObject(raw)) throw new Error("permission must be an object")
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_PERMISSION_FIELDS.has(key)) throw new Error(`unknown permission option: ${key}`)
  }
  const source = raw as PermissionOptions
  if (source.default !== undefined) {
    if (typeof source.default !== "string") throw new Error("permission.default must be a string")
    const parsed = parsePerm(source.default)
    if (!parsed) throw new Error(`permission.default is not a valid permission: ${source.default}`)
    defaults.defaultPerm = parsed
  }
  if (source.webIsRead !== undefined) {
    if (typeof source.webIsRead !== "boolean") throw new Error("permission.webIsRead must be a boolean")
    if (!source.webIsRead) {
      delete defaults.actionPerm.webfetch
      delete defaults.actionPerm.websearch
      defaults.ungatedActions.add("webfetch")
      defaults.ungatedActions.add("websearch")
    }
  }
  if (source.registerTool !== undefined) {
    if (typeof source.registerTool !== "boolean") throw new Error("permission.registerTool must be a boolean")
    defaults.registerTool = source.registerTool
  }
  if (source.subagentPermission !== undefined) {
    if (typeof source.subagentPermission !== "boolean") {
      throw new Error("permission.subagentPermission must be a boolean")
    }
    defaults.subagentPermission = source.subagentPermission
  }
  if (source.gateUnknownActions !== undefined) {
    if (typeof source.gateUnknownActions !== "boolean") {
      throw new Error("permission.gateUnknownActions must be a boolean")
    }
    defaults.gateUnknownActions = source.gateUnknownActions
  }
  if (source.actionMap !== undefined) {
    if (!isPlainObject(source.actionMap)) throw new Error("permission.actionMap must be an object")
    for (const [action, bit] of Object.entries(source.actionMap)) {
      if (bit !== "r" && bit !== "w" && bit !== "x") {
        throw new Error(`permission.actionMap.${action} must be "r", "w", or "x"`)
      }
      defaults.actionPerm[action] = bit
    }
  }
  return defaults
}

/** Validate a `denyWrite`/`denyRead` entry list. Paths are normalized before
 * storage so the helper receives canonical spellings. The ":" ban protects
 * the env encoding (colon-joined) and the "/" + scratch bans keep the user
 * from freezing/shadowing the entire root or the sandbox's own scratch
 * hierarchy (which would make every wrapped spawn unusable). */
function resolveSandboxPathList(raw: unknown, field: string, scratch: string): string[] {
  if (raw === undefined) return []
  if (!Array.isArray(raw)) throw new Error(`sandbox.${field} must be an array of absolute paths`)
  const list: string[] = []
  for (const entry of raw) {
    if (typeof entry !== "string" || !entry.trim() || !path.isAbsolute(entry.trim())) {
      throw new Error(`sandbox.${field} entries must be absolute path strings`)
    }
    const trimmed = entry.trim()
    if (trimmed.includes(":")) {
      throw new Error(`sandbox.${field} entries may not contain ":" (colon breaks the env encoding): ${trimmed}`)
    }
    // Reject ".." in the raw spelling (like sandbox.scratch) AND after
    // normalization: the helper rejects traversal at spawn, so accepting it
    // here would only surface as a runtime fail-close.
    const normalized = path.normalize(trimmed)
    if (trimmed.split(path.sep).includes("..") || normalized.split(path.sep).includes("..")) {
      throw new Error(`sandbox.${field} entries may not contain "..": ${trimmed}`)
    }
    // Strip the trailing slash normalize preserves so "/tmp/opencode/" compares
    // equal to the scratch dir (and the helper sees canonical spellings).
    const canonical = normalized === "/" ? "/" : normalized.replace(/[/\\]+$/, "")
    if (canonical === "/" || canonical === scratch) {
      throw new Error(`sandbox.${field} may not contain "/" or the scratch dir: ${trimmed}`)
    }
    list.push(canonical)
  }
  return list
}

export function resolveSandbox(raw: unknown): ResolvedSandbox {
  const resolved: ResolvedSandbox = {
    enabled: process.platform === "linux",
    mode: "auto",
    bwrapPath: "/usr/bin/bwrap",
    helperPath: DEFAULT_SANDBOX_HELPER_PATH,
    scratch: "/tmp",
    roNetwork: "off",
    rwNetwork: "on",
    denyWrite: [],
    denyRead: [],
    allowSudo: false,
    extraArgs: [],
    maskWslInterop: true,
    maskPrivilegedSockets: ["/run/docker.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock"],
    roAfUnixBlock: true,
    onUnavailable: "fail_close",
  }
  if (raw === undefined) return resolved
  if (!isPlainObject(raw)) throw new Error("sandbox must be an object")
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_SANDBOX_FIELDS.has(key)) throw new Error(`unknown sandbox option: ${key}`)
  }
  const source = raw as SandboxOptions

  if (source.enabled !== undefined) {
    if (typeof source.enabled !== "boolean") throw new Error("sandbox.enabled must be a boolean")
    resolved.enabled = source.enabled
  }
  if (source.mode !== undefined) {
    if (source.mode !== "auto" && source.mode !== "ro" && source.mode !== "rw" && source.mode !== "full") {
      throw new Error('sandbox.mode must be "auto", "ro", "rw", or "full"')
    }
    resolved.mode = source.mode
  }
  if (source.bwrapPath !== undefined) {
    if (typeof source.bwrapPath !== "string" || !source.bwrapPath.trim()) {
      throw new Error("sandbox.bwrapPath must be a non-empty string")
    }
    const trimmed = source.bwrapPath.trim()
    // A bare name defers to PATH lookup inside the helper; anything with a
    // directory component must be absolute.
    if (!path.isAbsolute(trimmed) && (trimmed.includes("/") || trimmed.includes("\\"))) {
      throw new Error("sandbox.bwrapPath must be an absolute path or a bare command name")
    }
    resolved.bwrapPath = trimmed
  }
  if (source.helperPath !== undefined) {
    if (typeof source.helperPath !== "string") throw new Error("sandbox.helperPath must be a string")
    if (source.helperPath.trim()) resolved.helperPath = path.resolve(source.helperPath.trim())
  }
  if (source.scratch !== undefined) {
    if (typeof source.scratch !== "string" || !source.scratch.trim()) {
      throw new Error("sandbox.scratch must be a non-empty string")
    }
    const trimmed = source.scratch.trim()
    if (!path.isAbsolute(trimmed)) throw new Error("sandbox.scratch must be an absolute path")
    // Reject ".." even when it would normalize away (e.g. /a/../b): the helper
    // rejects such scratch at spawn (exit 125), so accepting it here would
    // turn a config mistake into a runtime fail-close on every shell call.
    if (trimmed.split(path.sep).includes("..")) {
      throw new Error(`sandbox.scratch may not contain "..": ${trimmed}`)
    }
    const normalized = path.normalize(trimmed)
    const blocked = new Set(["/", "/home", "/root"])
    if (blocked.has(normalized)) {
      throw new Error(`sandbox.scratch may not be /, /home, or /root: ${trimmed}`)
    }
    resolved.scratch = normalized
  }
  if (source.roNetwork !== undefined) {
    if (source.roNetwork !== "off" && source.roNetwork !== "on") {
      throw new Error('sandbox.roNetwork must be "off" or "on"')
    }
    resolved.roNetwork = source.roNetwork
  }
  if (source.rwNetwork !== undefined) {
    if (source.rwNetwork !== "on" && source.rwNetwork !== "off") {
      throw new Error('sandbox.rwNetwork must be "on" or "off"')
    }
    resolved.rwNetwork = source.rwNetwork
  }
  if (source.denyWrite !== undefined) {
    resolved.denyWrite = resolveSandboxPathList(source.denyWrite, "denyWrite", resolved.scratch)
  }
  if (source.denyRead !== undefined) {
    resolved.denyRead = resolveSandboxPathList(source.denyRead, "denyRead", resolved.scratch)
  }
  if (source.allowSudo !== undefined) {
    if (typeof source.allowSudo !== "boolean") throw new Error("sandbox.allowSudo must be a boolean")
    resolved.allowSudo = source.allowSudo
  }
  if (source.extraArgs !== undefined) {
    if (!Array.isArray(source.extraArgs)) {
      throw new Error("sandbox.extraArgs must be an array of bwrap argv elements")
    }
    const args: string[] = []
    let joinedLength = 0
    for (const entry of source.extraArgs) {
      if (typeof entry !== "string" || !entry.trim()) {
        throw new Error("sandbox.extraArgs entries must be non-empty strings")
      }
      // Each element is one argv slot; "\n" is the env encoding separator and
      // "\0" cannot survive a posix env var.
      if (/[\n\r\0]/.test(entry)) {
        throw new Error(`sandbox.extraArgs entries may not contain newline or NUL characters`)
      }
      // A literal "--" would terminate bwrap option parsing before the
      // helper's own payload separator.
      if (entry === "--") {
        throw new Error(`sandbox.extraArgs entries may not be "--" (bwrap option terminator)`)
      }
      joinedLength += entry.length + 1 // element + "\n" separator
      args.push(entry)
    }
    // The joined env payload is bounded: the helper splits on "\n" and a
    // runaway list would blow up argv or the spawn env.
    if (joinedLength > 64 * 1024) {
      throw new Error("sandbox.extraArgs joined payload exceeds 64KB")
    }
    resolved.extraArgs = args
  }
  if (source.maskWslInterop !== undefined) {
    if (typeof source.maskWslInterop !== "boolean") throw new Error("sandbox.maskWslInterop must be a boolean")
    resolved.maskWslInterop = source.maskWslInterop
  }
  if (source.maskPrivilegedSockets !== undefined) {
    if (!Array.isArray(source.maskPrivilegedSockets)) {
      throw new Error("sandbox.maskPrivilegedSockets must be an array of absolute paths")
    }
    const sockets: string[] = []
    for (const entry of source.maskPrivilegedSockets) {
      if (typeof entry !== "string" || !path.isAbsolute(entry)) {
        throw new Error("sandbox.maskPrivilegedSockets entries must be absolute path strings")
      }
      sockets.push(entry)
    }
    resolved.maskPrivilegedSockets = sockets
  }
  if (source.roAfUnixBlock !== undefined) {
    if (typeof source.roAfUnixBlock !== "boolean") throw new Error("sandbox.roAfUnixBlock must be a boolean")
    resolved.roAfUnixBlock = source.roAfUnixBlock
  }
  if (source.onUnavailable !== undefined) {
    if (source.onUnavailable !== "fail_close" && source.onUnavailable !== "degrade") {
      throw new Error('sandbox.onUnavailable must be "fail_close" or "degrade"')
    }
    resolved.onUnavailable = source.onUnavailable
  }
  // The sandbox is Linux-only: a non-Linux host forces it off regardless of
  // configuration, matching the Windows supervisor's platform gate.
  if (process.platform !== "linux") resolved.enabled = false
  return resolved
}

export function resolvePluginConfig(raw?: BashClassifierOptions): ResolvedPluginConfig {
  const source = raw ?? {}

  for (const key of Object.keys(source)) {
    if (!ALLOWED_TOP_LEVEL.has(key)) {
      throw new Error(`unknown option: ${key}`)
    }
  }

  let shell: string | undefined
  if (source.shell !== undefined) {
    if (typeof source.shell !== "string") throw new Error("shell must be a string")
    shell = source.shell
  }

  let securityEnabled = true
  if (source.securityEnabled !== undefined) {
    if (typeof source.securityEnabled !== "boolean") {
      throw new Error("securityEnabled must be a boolean")
    }
    securityEnabled = source.securityEnabled
  }

  let detachedStartIsolation = true
  if (source.detachedStartIsolation !== undefined) {
    if (typeof source.detachedStartIsolation !== "boolean") {
      throw new Error("detachedStartIsolation must be a boolean")
    }
    detachedStartIsolation = source.detachedStartIsolation
  }

  let slowCommands: ResolvedSlowCommands
  if (source.slowCommands === undefined) {
    slowCommands = { enabled: true, maxDepth: 16, sleepThresholdSeconds: 120, allowExplicitTimeout: true }
  } else if (typeof source.slowCommands === "boolean") {
    slowCommands = {
      enabled: source.slowCommands,
      maxDepth: 16,
      sleepThresholdSeconds: 120,
      allowExplicitTimeout: true,
    }
  } else if (isPlainObject(source.slowCommands)) {
    const raw = source.slowCommands as Record<string, unknown>
    for (const key of Object.keys(raw)) {
      if (!ALLOWED_SLOW_FIELDS.has(key)) throw new Error(`unknown slowCommands option: ${key}`)
    }
    const enabled = raw.enabled === undefined ? true : raw.enabled
    const maxDepth = raw.maxDepth === undefined ? 16 : raw.maxDepth
    const sleepThresholdSeconds = raw.sleepThresholdSeconds === undefined ? 120 : raw.sleepThresholdSeconds
    const allowExplicitTimeout = raw.allowExplicitTimeout === undefined ? true : raw.allowExplicitTimeout
    if (typeof enabled !== "boolean") throw new Error("slowCommands.enabled must be a boolean")
    if (typeof maxDepth !== "number" || !Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 32)
      throw new Error("slowCommands.maxDepth must be an integer between 0 and 32")
    if (
      typeof sleepThresholdSeconds !== "number" ||
      !Number.isFinite(sleepThresholdSeconds) ||
      sleepThresholdSeconds < 0
    )
      throw new Error("slowCommands.sleepThresholdSeconds must be a non-negative number")
    if (typeof allowExplicitTimeout !== "boolean")
      throw new Error("slowCommands.allowExplicitTimeout must be a boolean")
    slowCommands = { enabled, maxDepth, sleepThresholdSeconds, allowExplicitTimeout }
  } else {
    throw new Error("slowCommands must be a boolean or an object")
  }

  if (source.supervisorEnabled !== undefined && typeof source.supervisorEnabled !== "boolean") {
    throw new Error("supervisorEnabled must be a boolean")
  }
  const supervisorEnabled = process.platform === "win32" && source.supervisorEnabled !== false

  let supervisorPath: string
  if (source.supervisorPath !== undefined) {
    if (typeof source.supervisorPath !== "string") {
      throw new Error("supervisorPath must be a string")
    }
    supervisorPath = path.resolve(source.supervisorPath)
  } else {
    supervisorPath = path.resolve(DEFAULT_SUPERVISOR_PATH)
  }

  let strictness: Strictness = "LOOSE"
  if (source.strictness !== undefined) {
    if (source.strictness !== "LOOSE" && source.strictness !== "HARD") {
      throw new Error('strictness must be "LOOSE" or "HARD"')
    }
    strictness = source.strictness
  }

  let failPolicy: FailPolicy = "fail_open"
  if (source.failPolicy !== undefined) {
    if (
      source.failPolicy !== "fail_ask" &&
      source.failPolicy !== "fail_open" &&
      source.failPolicy !== "fail_close"
    ) {
      throw new Error('failPolicy must be "fail_ask", "fail_open", or "fail_close"')
    }
    failPolicy = source.failPolicy
  }

  let configuredReviewCommand: ReviewCommand | undefined
  if (source.reviewCommand !== undefined) {
    if (typeof source.reviewCommand !== "function") {
      throw new Error("reviewCommand must be a function")
    }
    configuredReviewCommand = source.reviewCommand as ReviewCommand
  }

  let logReviewerTrace = false
  if (source.logReviewerTrace !== undefined) {
    if (typeof source.logReviewerTrace !== "boolean") {
      throw new Error("logReviewerTrace must be a boolean")
    }
    logReviewerTrace = source.logReviewerTrace
  }

  const bypass = resolveBypassCategories(source.BypassClassifier)
  const bypassLeaseTtlMs = resolveBypassLeaseTtlMs(source.bypassLeaseTtlMs)
  let bypassPropagateToSubagents = true
  if (source.bypassPropagateToSubagents !== undefined) {
    if (typeof source.bypassPropagateToSubagents !== "boolean") {
      throw new Error("bypassPropagateToSubagents must be a boolean")
    }
    bypassPropagateToSubagents = source.bypassPropagateToSubagents
  }

  let escalationEnabled = true
  if (source.escalationEnabled !== undefined) {
    if (typeof source.escalationEnabled !== "boolean") {
      throw new Error("escalationEnabled must be a boolean")
    }
    escalationEnabled = source.escalationEnabled
  }

  const dynamicReview = resolveDynamicReview(source.dynamicReview, strictness)
  const permission = resolvePermission(source.permission)
  const sandbox = resolveSandbox(source.sandbox)
  const routeReview = configuredReviewCommand ?? (dynamicReview.available ? reviewCommandWithAuditor : undefined)
  const reviewCommand: ReviewCommand | undefined = routeReview
    ? (request, options) => routeReview(request, {
        ...options,
        policy: strictness,
        allowFullReadAccess: dynamicReview.allowFullReadAccess,
      })
    : undefined

  return {
    shell,
    securityEnabled,
    detachedStartIsolation,
    supervisorEnabled,
    supervisorPath,
    strictness,
    failPolicy,
    slowCommands,
    logReviewerTrace,
    bypassClassifier: bypass.value,
    bypassLeaseTtlMs,
    bypassPropagateToSubagents,
    escalationEnabled,
    permission,
    sandbox,
    dynamicReview,
    reviewCommand,
    bypassWarnings: bypass.warnings,
  }
}

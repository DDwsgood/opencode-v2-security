import { spawn } from "node:child_process"
import { lstatSync, realpathSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { STATIC_BYPASS_CATEGORIES } from "../categories"

export type CloudReviewDecision = "ALLOW" | "DENY"

/** One billed risk family in the structured assessment: which category, what
 * semantic kind produced it (the reviewer's head/question id), the effect
 * domain where one applies, and the evidence string the reviewer cited. */
export type RiskReason = {
  category: string
  kind: string
  domain?: string
  evidence: string
}

/** The reviewer's full structured assessment, carried on every verdict —
 * including ALLOW. `categories` is the intrinsic risk footprint: present
 * risk families, independently of whether the command was authorized this
 * time. `decisionSource` names the layer that produced the final verdict so
 * a native floor/policy veto is never reported as model agreement:
 * model_allow / model_rules / model_floor / native_floor / native_static /
 * native_policy / appeal_override / noop_refused for Jev; "model" for the
 * OpenAI auditor's single-word verdicts. */
export type StructuredAssessment = {
  categories: string[]
  strongReasons: RiskReason[]
  needsEvidence: string[]
  rawDecision?: { choice?: string; p_deny?: number }
  decisionSource: string
  firedRules?: string[]
  context?: { actor?: string; armed?: string[] }
  floor?: string
  policyVersion?: string
  version?: string
}

/** Review engines understood by this module. "openai" is the OpenAI-compatible
 * tool-calling auditor (auditor.py); "jev" is the structured systemone
 * reviewer (jev-reviewer.py). */
export type ReviewEngine = "jev" | "openai"

export type CloudReviewResult = {
  decision: CloudReviewDecision | "collect_evidence"
  /** Risk families the reviewer's footprint judged present (canonical
   * bypass-category names). Denials keep their categories; an ALLOW also
   * reports its intrinsic footprint — approval is a separate layer and
   * never erases what the command does. */
  categories: string[]
  /** Lower-confidence risk families reported alongside `categories`. */
  secondary_categories?: string[]
  /** Free-text denial reason. Removed from the reviewer output contract in
   * 1.1.0; tolerated when a legacy auditor still sends it. */
  reason?: string
  /** Present only for the strict policy, which performs bypass detection. */
  bypassing?: boolean
  /** Full structured assessment (strong reasons, evidence gaps, decision
   * provenance). Always populated — synthesized for engines that do not
   * emit one natively. */
  assessment: StructuredAssessment
  /** Internal: which engine produced this verdict. Diagnostics only — never
   * part of the wire contract or agent-facing text. */
  engine?: ReviewEngine
  /** Internal: why an engine fallback happened (e.g. jev infra failure under
   * reviewer:"auto"). Diagnostics only — never part of the wire contract. */
  fallback_reason?: string
}

export type PreviousRejectedCommand = {
  command: string
  reason: string
  classifier: "STATIC" | "DYNAMIC" | "FAIL_POLICY"
}

export type PreviousFailedCommand = {
  command: string
  exitCode: number
  outputTail?: string
}

export type CloudReviewRequest = {
  command: string
  localScripts: Array<{
    path: string
    content: string
    sha256: string
  }>
  uninspectedLocalScripts: string[]
  targetDirectories: Array<{
    path: string
    entries: Array<{
      name: string
      type: "directory" | "file" | "symlink" | "other"
    }>
    truncated: boolean
  }>
  uninspectedTargetDirectories: string[]
  referencedPaths: string[]
  referencedPathsTruncated: boolean
  worktree: string
  cwd: string
  previousRejectedCommand?: PreviousRejectedCommand
  previousFailedCommand?: PreviousFailedCommand
  /** User-armed bypass categories for this session. `dynamic` never reaches
   * the auditor (the reviewer is skipped); the rest relax the auditor prompt. */
  userBypass?: string[]
  /** Environment awareness: OS description and shell path, e.g.
   * { system: "Ubuntu 24.04 WSL", bash: "/bin/bash" }. */
  environment?: { system?: string; bash?: string }
  /** Session rwx ceiling. When `w` is absent the session is read-only and the
   * auditor system prompt gains the SESSION PERMISSION NOTICE advisory. */
  permScope?: { r: boolean; w: boolean; x: boolean }
  /** Bounded evidence attached by the host after a collect_evidence pass —
   * small excerpts of previously uninspected subjects (script bodies,
   * directory listings). Reviewers render it as untrusted data. */
  collectedEvidence?: Array<{
    kind: string
    subject: string
    excerpt: string
    truncated?: boolean
  }>
}

export type JevReviewConfig = {
  endpoint: string
  model: string
  apiKey: string
}

export type ReviewCommandOptions = {
  endpoint: string
  model: string
  apiKey: string
  maxRounds: number
  policy: "LOOSE" | "HARD"
  allowFullReadAccess?: boolean
  python?: string
  auditorPath?: string
  /** Which reviewer engine to consult. "auto" (the resolved default) tries
   * Jev when `jev` is configured and falls back to the OpenAI-compatible
   * auditor on infrastructure failures (network, 5xx, timeout); protocol
   * failures never retry — they fail close. */
  reviewer?: "jev" | "openai" | "auto"
  /** Resolved Jev reviewer settings; required for reviewer:"jev" and used
   * opportunistically by "auto". */
  jev?: JevReviewConfig
  /** Path to jev-reviewer.py; defaults to the bundled script. */
  jevPath?: string
  timeout?: number
  signal?: AbortSignal
}

type PythonCandidate = {
  executable: string
  prefixArgs: string[]
}

/**
 * Error thrown when a dynamic review fails. Carries a coarse classification so
 * callers can distinguish security/protocol violations (fail-close) from
 * infrastructure failures (honor fail policy). `exitCode` is the auditor
 * process exit code (when available); `reads`/`transcript` are recovered from
 * the auditor's structured side-channel on non-zero exit. `code` mirrors the
 * errno for spawn failures so candidate fallback can still detect ENOENT.
 */
export class ReviewError extends Error {
  kind: "protocol" | "infra"
  exitCode?: number
  reads?: Array<{ path: string; size: number }>
  transcript?: Array<{ role: string; content: string }>
  code?: string
  constructor(
    message: string,
    kind: "protocol" | "infra",
    extras?: {
      exitCode?: number
      reads?: Array<{ path: string; size: number }>
      transcript?: Array<{ role: string; content: string }>
      code?: string
    },
  ) {
    super(message)
    this.name = "ReviewError"
    this.kind = kind
    if (extras) {
      if (extras.exitCode !== undefined) this.exitCode = extras.exitCode
      if (extras.reads) this.reads = extras.reads
      if (extras.transcript) this.transcript = extras.transcript
      if (extras.code !== undefined) this.code = extras.code
    }
  }
}

const MAX_STDOUT_CHARS = 64_000
const MAX_STDERR_CHARS = 8_000
// 256KB preflight budget (≈6.4万 token, 15x余量). Exceeding it is a defensive
// failure signal (possible injection/DoS attempting to overwhelm the reviewer)
// and is thrown as a protocol ReviewError so callers fail-close.
const MAX_REVIEW_INPUT_BYTES = 262_144
const DEFAULT_TIMEOUT_MS = 30_000
// The auditor's review deadline sits strictly below the child-process kill
// for every positive budget (grace shrinks to half the budget under 4 s), so
// a slow endpoint ends in a clean transport error, not a SIGKILL.
const HTTP_DEADLINE_GRACE_MS = 2_000
function pythonDeadlineSeconds(timeoutMs: number): number {
  const graceMs = Math.min(HTTP_DEADLINE_GRACE_MS, timeoutMs / 2)
  return Math.max(0.001, (timeoutMs - graceMs) / 1000)
}
const ISOLATED_FLAGS = ["-I", "-B"]

function isRegularFile(filePath: string): boolean {
  try {
    return lstatSync(filePath).isFile()
  } catch {
    return false
  }
}

function bundledAuditorPath() {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [
    path.join(moduleDirectory, "auditor.py"),
    path.join(moduleDirectory, "security", "auditor.py"),
    path.join(moduleDirectory, "..", "src", "security", "auditor.py"),
  ]
  // existsSync would accept directories; require a regular file so a stray
  // directory never gets handed to the Python interpreter.
  return candidates.find((candidate) => isRegularFile(candidate))
}

function bundledJevPath() {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [
    path.join(moduleDirectory, "jev-reviewer.py"),
    path.join(moduleDirectory, "security", "jev-reviewer.py"),
    path.join(moduleDirectory, "..", "src", "security", "jev-reviewer.py"),
  ]
  return candidates.find((candidate) => isRegularFile(candidate))
}

function pythonCandidates(configured?: string): PythonCandidate[] {
  if (configured) return [{ executable: configured, prefixArgs: [...ISOLATED_FLAGS] }]
  if (process.platform === "win32") {
    return [
      { executable: "python", prefixArgs: [...ISOLATED_FLAGS] },
      { executable: "py", prefixArgs: ["-3", ...ISOLATED_FLAGS] },
      { executable: "python3", prefixArgs: [...ISOLATED_FLAGS] },
    ]
  }
  return [
    { executable: "python3", prefixArgs: [...ISOLATED_FLAGS] },
    { executable: "python", prefixArgs: [...ISOLATED_FLAGS] },
  ]
}

function reviewerEnvironment(options: {
  endpoint: string
  model: string
  apiKey: string
  maxRounds: number
  policy: "LOOSE" | "HARD"
  allowFullReadAccess?: boolean
  /** Resolved Jev reviewer settings; only forwarded for engine "jev". */
  jev?: JevReviewConfig
  engine?: ReviewEngine
  /** Resolved child-process budget; forwarded as the review deadline. */
  timeoutMs?: number
}): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {}
  // Minimal whitelist: no HOME/USERPROFILE or legacy provider/key/model variables.
  const names = [
    "PATH",
    "Path",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
  ]
  for (const name of names) {
    if (process.env[name] !== undefined) result[name] = process.env[name]
  }
  result.PYTHONIOENCODING = "utf-8"
  result.PYTHONUTF8 = "1"
  if (options.engine === "jev" && options.jev) {
    result.JEV_ENDPOINT = options.jev.endpoint
    result.JEV_MODEL = options.jev.model
    result.JEV_API_KEY = options.jev.apiKey
  } else {
    result.OPENCODE_V2_SECURITY_REVIEW_ENDPOINT = options.endpoint
    result.OPENCODE_V2_SECURITY_REVIEW_MODEL = options.model
    result.OPENCODE_V2_SECURITY_REVIEW_API_KEY = options.apiKey
    result.OPENCODE_V2_SECURITY_REVIEW_MAX_ROUNDS = String(options.maxRounds)
    result.OPENCODE_V2_SECURITY_REVIEW_FULL_READ = options.allowFullReadAccess === true ? "1" : "0"
  }
  result.OPENCODE_V2_SECURITY_REVIEW_POLICY = options.policy
  if (typeof options.timeoutMs === "number" && Number.isFinite(options.timeoutMs) && options.timeoutMs > 0) {
    result.OPENCODE_V2_SECURITY_REVIEW_DEADLINE_S = String(
      pythonDeadlineSeconds(options.timeoutMs),
    )
  }
  const tempRoots = [os.tmpdir()]
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA
    if (localAppData) tempRoots.push(path.join(localAppData, "Temp"))
  } else if (process.platform === "linux") {
    tempRoots.push("/tmp")
  }
  result.OPENCODE_V2_SECURITY_REVIEW_TEMP_ROOTS = JSON.stringify([...new Set(tempRoots.map((root) => {
    const resolved = path.resolve(root)
    try { return realpathSync.native(resolved) } catch { return resolved }
  }))])
  return result
}

// JSON.parse silently keeps the last value for duplicate keys, so the three-field
// check alone could not detect them. This scanner walks only the top-level object
// members (string-aware, depth-aware) and returns every member key, letting callers
// compare the raw count against Object.keys(parsed).length to flag duplicates.
function collectTopLevelJsonKeys(text: string): string[] | null {
  const keys: string[] = []
  let pos = 0
  const len = text.length

  const skipWs = () => {
    while (pos < len) {
      const code = text.charCodeAt(pos)
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) pos++
      else break
    }
  }
  const readString = (): string => {
    pos++ // opening quote
    let result = ""
    while (pos < len) {
      const c = text[pos]
      if (c === "\\") {
        pos++
        if (pos >= len) return result
        const e = text[pos]
        switch (e) {
          case '"': result += '"'; break
          case "\\": result += "\\"; break
          case "/": result += "/"; break
          case "b": result += "\b"; break
          case "f": result += "\f"; break
          case "n": result += "\n"; break
          case "r": result += "\r"; break
          case "t": result += "\t"; break
          case "u": {
            const code = parseInt(text.slice(pos + 1, pos + 5), 16)
            if (Number.isFinite(code)) result += String.fromCharCode(code)
            pos += 4
            break
          }
          default: result += e
        }
        pos++
      } else if (c === '"') {
        pos++
        return result
      } else {
        result += c
        pos++
      }
    }
    return result
  }
  const skipValue = () => {
    skipWs()
    if (pos >= len) return
    const c = text[pos]
    if (c === '"') { readString(); return }
    if (c === "{" || c === "[") {
      const close = c === "{" ? "}" : "]"
      let depth = 0
      while (pos < len) {
        const cc = text[pos]
        if (cc === '"') { readString(); continue }
        if (cc === "{" || cc === "[") { depth++; pos++; continue }
        if (cc === "}" || cc === "]") {
          depth--
          pos++
          if (depth === 0 && cc === close) return
          continue
        }
        pos++
      }
      return
    }
    while (pos < len) {
      const cc = text[pos]
      if (cc === "," || cc === "}" || cc === "]" || cc === " " || cc === "\t" || cc === "\n" || cc === "\r") break
      pos++
    }
  }

  skipWs()
  if (text[pos] !== "{") return null
  pos++ // consume '{'
  skipWs()
  if (text[pos] === "}") { pos++; return keys }
  while (pos < len) {
    skipWs()
    if (text[pos] !== '"') return null
    keys.push(readString())
    skipWs()
    if (text[pos] !== ":") return null
    pos++ // ':'
    skipValue()
    skipWs()
    if (text[pos] === ",") { pos++; continue }
    if (text[pos] === "}") { pos++; break }
    return null
  }
  return keys
}

// The reviewer output contract: {decision, categories, secondary_categories?,
// assessment?} (+bypassing under HARD). A legacy `reason` string is tolerated
// but no longer required — a DENY's categories drive the hint. `assessment`
// is the structured footprint/source report; `needs_evidence` is a tolerated
// legacy alias whose entries are folded into assessment.needsEvidence.
const ALLOWED_RESULT_KEYS = new Set([
  "decision",
  "categories",
  "secondary_categories",
  "bypassing",
  "reason",
  "assessment",
  "needs_evidence",
  "evidence_requests",
])

// Categories a reviewer may report: the seven static names plus the sandbox
// layer category (escalation-grantable; `dynamic`/`slow` are never reported —
// a reviewer cannot ask to disable the layer judging it).
const VALID_RESULT_CATEGORIES = new Set<string>([...STATIC_BYPASS_CATEGORIES, "sandbox"])

function parseCategoryList(value: unknown): string[] | undefined {
  if (value === undefined) return undefined
  if (!Array.isArray(value)) return undefined
  const out: string[] = []
  for (const item of value) {
    if (typeof item === "string" && VALID_RESULT_CATEGORIES.has(item) && !out.includes(item)) {
      out.push(item)
    }
  }
  return out
}

const VALID_DECISION_SOURCES = new Set([
  "model", "model_allow", "model_deny", "model_rules", "model_floor",
  "native_floor", "native_static", "native_policy",
  "appeal_override", "noop_refused", "legacy_ask_user",
  "evidence_needed", "evidence_limited",
])

function parseStringList(value: unknown, max = 16, maxLen = 160): string[] {
  if (!Array.isArray(value)) return []
  const out: string[] = []
  for (const item of value) {
    if (typeof item === "string" && item.trim() && !out.includes(item)) {
      out.push(item.slice(0, maxLen))
    }
    if (out.length >= max) break
  }
  return out
}

/** Sanitize a reviewer-emitted `assessment` object. Unknown/malformed fields
 * degrade to empty/absent rather than failing the review — the assessment is
 * a report, not a gate — but a present-but-corrupt object never fabricates
 * evidence either. */
function parseAssessment(value: unknown): StructuredAssessment | undefined {
  if (value === undefined) return undefined
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined
  const obj = value as Record<string, unknown>
  const strongReasons: RiskReason[] = []
  if (Array.isArray(obj.strongReasons)) {
    for (const entry of obj.strongReasons.slice(0, 32)) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue
      const e = entry as Record<string, unknown>
      if (typeof e.category !== "string" || typeof e.kind !== "string") continue
      strongReasons.push({
        category: e.category.slice(0, 80),
        kind: e.kind.slice(0, 80),
        domain: typeof e.domain === "string" ? e.domain.slice(0, 40) : undefined,
        evidence: typeof e.evidence === "string" ? e.evidence.slice(0, 300) : "",
      })
    }
  }
  const raw = obj.rawDecision
  const assessment: StructuredAssessment = {
    categories: parseStringList(obj.categories),
    strongReasons,
    needsEvidence: parseStringList(obj.needsEvidence),
    decisionSource:
      typeof obj.decisionSource === "string" && VALID_DECISION_SOURCES.has(obj.decisionSource)
        ? obj.decisionSource
        : "model",
  }
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    const r = raw as Record<string, unknown>
    assessment.rawDecision = {
      choice: typeof r.choice === "string" ? r.choice.slice(0, 40) : undefined,
      p_deny:
        typeof r.p_deny === "number" && Number.isFinite(r.p_deny) ? r.p_deny : undefined,
    }
  }
  if (Array.isArray(obj.firedRules)) {
    assessment.firedRules = parseStringList(obj.firedRules, 16, 80)
  }
  if (obj.context && typeof obj.context === "object" && !Array.isArray(obj.context)) {
    const c = obj.context as Record<string, unknown>
    assessment.context = {
      actor: typeof c.actor === "string" ? c.actor.slice(0, 40) : undefined,
      armed: Array.isArray(c.armed) ? parseStringList(c.armed, 16, 40) : undefined,
    }
  }
  if (typeof obj.floor === "string") assessment.floor = obj.floor.slice(0, 20)
  if (typeof obj.policyVersion === "string") assessment.policyVersion = obj.policyVersion.slice(0, 80)
  if (typeof obj.version === "string") assessment.version = obj.version.slice(0, 40)
  return assessment
}

function parseReviewResult(stdout: string, policy: "LOOSE" | "HARD"): CloudReviewResult {
  if (policy !== "LOOSE" && policy !== "HARD") throw new Error("Invalid review policy")
  const trimmed = stdout.trim()
  const parsed = JSON.parse(trimmed) as Record<string, unknown>
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("The auditor returned a non-object result")
  }
  const rawKeys = collectTopLevelJsonKeys(trimmed)
  if (rawKeys !== null && rawKeys.length !== Object.keys(parsed).length) {
    throw new Error("The auditor returned duplicate JSON keys")
  }
  for (const key of Object.keys(parsed)) {
    if (!ALLOWED_RESULT_KEYS.has(key)) {
      throw new Error("The auditor returned unexpected fields")
    }
  }
  if (
    parsed.decision !== "ALLOW" &&
    parsed.decision !== "DENY" &&
    parsed.decision !== "collect_evidence"
  ) {
    throw new Error("The auditor returned an invalid decision")
  }
  if (parsed.categories !== undefined && !Array.isArray(parsed.categories)) {
    throw new Error("The auditor returned a non-array categories")
  }
  if (parsed.secondary_categories !== undefined && !Array.isArray(parsed.secondary_categories)) {
    throw new Error("The auditor returned a non-array secondary_categories")
  }
  if (parsed.evidence_requests !== undefined && !Array.isArray(parsed.evidence_requests)) {
    throw new Error("The auditor returned a non-array evidence_requests")
  }
  if (parsed.reason !== undefined && typeof parsed.reason !== "string") {
    throw new Error("The auditor returned a non-string reason")
  }
  if (policy === "HARD" && typeof parsed.bypassing !== "boolean") {
    throw new Error("The auditor returned a non-boolean bypassing")
  }
  const assessment = parseAssessment(parsed.assessment)
  const topLevelNeeds = parseStringList(parsed.needs_evidence)
  if (assessment === undefined && parsed.assessment !== undefined) {
    throw new Error("The auditor returned a non-object assessment")
  }
  const decision = parsed.decision as CloudReviewResult["decision"]
  // Invalid/unknown category names are stripped rather than failing the
  // review: the reviewer is an external model and a bad hint must degrade
  // to "no hint", not to a fail-closed protocol error.
  let categories = parseCategoryList(parsed.categories) ?? []
  const secondary = (parseCategoryList(parsed.secondary_categories) ?? []).filter(
    (category) => !categories.includes(category),
  )
  // A DENY with no category signal still needs a hint family — indirection
  // is the conservative fallback (the reviewer did not trust what it saw).
  if (decision === "DENY" && categories.length === 0) categories = ["indirection"]
  // The footprint is intrinsic: an ALLOW keeps the categories it reported.
  // Approval and presence are separate layers — never cleared here.
  const result: CloudReviewResult = {
    decision,
    categories,
    assessment: assessment ?? {
      categories: [...categories],
      strongReasons: [],
      needsEvidence: [],
      decisionSource: "model",
    },
  }
  for (const item of topLevelNeeds) {
    if (!result.assessment.needsEvidence.includes(item)) {
      result.assessment.needsEvidence.push(item)
    }
  }
  if (secondary.length > 0) result.secondary_categories = secondary
  if (typeof parsed.reason === "string" && decision === "DENY") {
    const reason = parsed.reason.trim().replace(/\s+/g, " ").slice(0, 80)
    if (reason) result.reason = reason
  }
  if (policy === "HARD") result.bypassing = parsed.bypassing as boolean
  return result
}

// Auditor non-zero exit codes that are infrastructure failures (honor fail
// policy): 4 = HTTP error, 5 = network error. Every other non-zero exit —
// including 2 (input validation), 6 (mandatory-inspection violation), 7
// (generic review exception), unrecognized codes, and signal deaths — defaults
// to "protocol" so a defensive failure closes the gate rather than letting an
// ambiguous failure fall through to fail_open.
const INFRA_EXIT_CODES = new Set([4, 5])

function classifyExitCode(code: number | null): "protocol" | "infra" {
  if (code !== null && INFRA_EXIT_CODES.has(code)) return "infra"
  return "protocol"
}

type AuditorSideChannel = {
  message?: string
  reads?: Array<{ path: string; size: number }>
  transcript?: Array<{ role: string; content: string }>
}

// On non-zero exit the auditor may write one line of structured JSON to stdout
// ({"error":{"exit","message"},"reads":[{path,size}],"transcript":[{role,content}],
// "truncated":bool}). Parse defensively: any missing/malformed field is treated
// as absent so a half-written side channel never corrupts the error path.
function parseAuditorSideChannel(stdout: string): AuditorSideChannel | null {
  const trimmed = stdout.trim()
  if (!trimmed) return null
  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    // The contract is a single JSON line; if the whole stdout is not JSON, try
    // the last non-empty line (auditor diagnostics may precede it).
    const lines = trimmed.split(/\r?\n/).filter((line) => line.trim())
    const last = lines[lines.length - 1]
    if (!last) return null
    try {
      parsed = JSON.parse(last)
    } catch {
      return null
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null
  const obj = parsed as Record<string, unknown>
  const result: AuditorSideChannel = {}
  const error = obj.error
  if (error && typeof error === "object" && !Array.isArray(error)) {
    const e = error as Record<string, unknown>
    if (typeof e.message === "string") result.message = e.message
  }
  if (Array.isArray(obj.reads)) {
    const reads: Array<{ path: string; size: number }> = []
    for (const entry of obj.reads) {
      if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        const r = entry as Record<string, unknown>
        if (typeof r.path === "string" && typeof r.size === "number" && Number.isFinite(r.size)) {
          reads.push({ path: r.path, size: r.size })
        }
      }
    }
    if (reads.length) result.reads = reads
  }
  if (Array.isArray(obj.transcript)) {
    const transcript: Array<{ role: string; content: string }> = []
    for (const entry of obj.transcript) {
      if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        const t = entry as Record<string, unknown>
        if (typeof t.role === "string" && typeof t.content === "string") {
          transcript.push({ role: t.role, content: t.content })
        }
      }
    }
    if (transcript.length) result.transcript = transcript
  }
  return result
}

async function runCandidate(
  candidate: PythonCandidate,
  auditorPath: string,
  reviewInput: string,
  timeoutMs: number,
  options: {
    endpoint: string
    model: string
    apiKey: string
    maxRounds: number
    policy: "LOOSE" | "HARD"
    jev?: JevReviewConfig
    engine?: ReviewEngine
    signal?: AbortSignal
  },
) {
  return await new Promise<CloudReviewResult>((resolve, reject) => {
    const child = spawn(candidate.executable, [...candidate.prefixArgs, auditorPath], {
      env: reviewerEnvironment({ ...options, timeoutMs }),
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      cwd: path.dirname(auditorPath),
      shell: false,
    })

    let stdout = ""
    let stderr = ""
    let settled = false
    let timedOut = false
    const signal = options.signal

    const finish = (callback: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", abort)
      callback()
    }
    const abort = () => {
      child.kill()
      finish(() => reject(new ReviewError("The auditor was aborted", "infra")))
    }
    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, timeoutMs)

    signal?.addEventListener("abort", abort, { once: true })
    if (signal?.aborted) {
      abort()
      return
    }

    child.stdout?.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString()
      if (stdout.length > MAX_STDOUT_CHARS) {
        child.kill()
        finish(() => reject(new ReviewError("The auditor returned too much output", "protocol")))
      }
    })
    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr = (stderr + chunk.toString()).slice(-MAX_STDERR_CHARS)
    })
    child.stdin?.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EPIPE") {
        finish(() => reject(new ReviewError(error.message, "infra", { code: error.code })))
      }
    })
    child.stdin?.end(reviewInput)
    child.once("error", (error: NodeJS.ErrnoException) =>
      finish(() => reject(new ReviewError(error.message, "infra", { code: error.code }))),
    )
    child.once("close", (code: number | null) => {
      finish(() => {
        if (timedOut) {
          reject(new ReviewError(`The auditor timed out after ${timeoutMs}ms`, "infra"))
          return
        }
        if (code !== 0) {
          const side = parseAuditorSideChannel(stdout)
          const kind = classifyExitCode(code)
          const fallback =
            code === null
              ? "The auditor was killed by a signal"
              : `The auditor exited with code ${code}`
          const detail = side?.message || stderr.trim().replace(/\s+/g, " ").slice(0, 500) || fallback
          reject(
            new ReviewError(detail, kind, {
              exitCode: code === null ? undefined : code,
              reads: side?.reads,
              transcript: side?.transcript,
            }),
          )
          return
        }
        try {
          resolve(parseReviewResult(stdout, options.policy))
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error)
          reject(new ReviewError(message, "protocol"))
        }
      })
    })
  })
}

function normalizeReviewRequest(request: CloudReviewRequest | string): CloudReviewRequest {
  if (typeof request === "string") {
    const cwd = process.cwd()
    return {
      command: request,
      localScripts: [],
      uninspectedLocalScripts: [],
      targetDirectories: [],
      uninspectedTargetDirectories: [],
      referencedPaths: [],
      referencedPathsTruncated: false,
      worktree: cwd,
      cwd,
    }
  }
  return request
}

// Categories the auditor accepts in userBypass. `dynamic` is resolved before
// the auditor runs (the review is skipped entirely), so it never appears here.
const AUDITOR_BYPASS_CATEGORIES = new Set<string>(STATIC_BYPASS_CATEGORIES)

function requestForPolicy(request: CloudReviewRequest, policy: "LOOSE" | "HARD"): CloudReviewRequest {
  const legacy = request as CloudReviewRequest & { strictness?: unknown }
  const {
    strictness: _ignoredMode,
    previousRejectedCommand,
    userBypass,
    environment,
    permScope,
    ...rest
  } = legacy
  const normalized: CloudReviewRequest = {
    ...rest,
    referencedPaths: Array.isArray(rest.referencedPaths) ? rest.referencedPaths : [],
    referencedPathsTruncated:
      typeof rest.referencedPathsTruncated === "boolean" ? rest.referencedPathsTruncated : false,
  }
  if (policy === "HARD" && previousRejectedCommand) {
    normalized.previousRejectedCommand = previousRejectedCommand
  }
  if (Array.isArray(userBypass)) {
    const categories = [...new Set(userBypass.filter((item): item is string => typeof item === "string"))].filter(
      (item) => AUDITOR_BYPASS_CATEGORIES.has(item),
    )
    if (categories.length > 0) normalized.userBypass = categories
  }
  if (
    environment &&
    typeof environment === "object" &&
    (typeof environment.system === "string" || typeof environment.bash === "string")
  ) {
    normalized.environment = {
      system: typeof environment.system === "string" ? environment.system.slice(0, 200) : undefined,
      bash: typeof environment.bash === "string" ? environment.bash.slice(0, 200) : undefined,
    }
  }
  if (permScope && typeof permScope === "object") {
    const scope = permScope as Record<string, unknown>
    if (typeof scope.r === "boolean" && typeof scope.w === "boolean" && typeof scope.x === "boolean") {
      normalized.permScope = { r: scope.r, w: scope.w, x: scope.x }
    }
  }
  return normalized
}

export async function reviewCommandWithAuditor(
  request: CloudReviewRequest | string,
  options: ReviewCommandOptions,
) {
  if (!options || typeof options.endpoint !== "string" || !options.endpoint) {
    throw new Error("reviewCommandWithAuditor requires a valid endpoint")
  }
  if (typeof options.model !== "string" || !options.model) {
    throw new Error("reviewCommandWithAuditor requires a valid model")
  }
  if (typeof options.apiKey !== "string" || !options.apiKey) {
    throw new Error("reviewCommandWithAuditor requires a valid apiKey")
  }
  if (typeof options.maxRounds !== "number" || !Number.isInteger(options.maxRounds)) {
    throw new Error("reviewCommandWithAuditor requires an integer maxRounds")
  }
  if (options.policy !== "LOOSE" && options.policy !== "HARD") {
    throw new Error("reviewCommandWithAuditor requires a valid policy")
  }
  const maxRoundsLimit = options.policy === "LOOSE" ? 3 : 5
  if (options.maxRounds < 1 || options.maxRounds > maxRoundsLimit) {
    throw new Error(`reviewCommandWithAuditor maxRounds must be between 1 and ${maxRoundsLimit}`)
  }
  const routedOptions = { ...options, policy: options.policy }
  const normalized = requestForPolicy(normalizeReviewRequest(request), routedOptions.policy)
  const timeoutMs = options.timeout ?? DEFAULT_TIMEOUT_MS

  const runEngine = async (engine: ReviewEngine): Promise<CloudReviewResult> => {
    const scriptPath =
      engine === "jev" ? (options.jevPath ?? bundledJevPath()) : (options.auditorPath ?? bundledAuditorPath())
    if (!scriptPath) {
      throw new ReviewError(
        `The bundled ${engine === "jev" ? "jev-reviewer" : "auditor"} script could not be found or is not a regular file`,
        "infra",
      )
    }
    // Jev also receives the armed categories under their own key (the same
    // values userBypass already carries, duplicated per the adapter contract).
    const payload =
      engine === "jev" ? { ...normalized, armed_categories: normalized.userBypass ?? [] } : normalized
    const reviewInput = JSON.stringify(payload)
    if (Buffer.byteLength(reviewInput, "utf8") > MAX_REVIEW_INPUT_BYTES) {
      throw new ReviewError("The review input exceeded the safety limit", "protocol")
    }

    const failures: Error[] = []
    for (const candidate of pythonCandidates(options.python)) {
      try {
        const result = await runCandidate(candidate, scriptPath, reviewInput, timeoutMs, {
          ...routedOptions,
          engine,
        })
        result.engine = engine
        return result
      } catch (error) {
        const failure = error instanceof Error ? error : new Error(String(error))
        failures.push(failure)
        const code = (failure as NodeJS.ErrnoException).code
        if (options.python || code !== "ENOENT") throw failure
      }
    }
    throw failures.at(-1) ?? new ReviewError("No Python 3 interpreter was found for the reviewer", "infra")
  }

  const jevReady = Boolean(options.jev?.apiKey && options.jev.endpoint && options.jev.model)
  const preference = options.reviewer ?? "openai"
  if (preference === "openai" || (preference === "auto" && !jevReady)) {
    return runEngine("openai")
  }
  if (!jevReady) {
    // reviewer:"jev" explicitly requested without a usable configuration.
    throw new ReviewError("The Jev reviewer is not configured", "infra")
  }
  try {
    return await runEngine("jev")
  } catch (error) {
    // auto only: Jev infrastructure failures (network, 5xx, timeout, missing
    // interpreter) fall back to the OpenAI-compatible auditor. An explicit
    // reviewer:"jev" never falls back — the caller asked for that engine.
    // Protocol errors and aborts never retry — they fail close.
    const infra = error instanceof ReviewError && error.kind === "infra"
    if (preference !== "auto" || !infra || options.signal?.aborted) throw error
    const reason = error instanceof Error ? error.message : String(error)
    // Visibility: a silent engine switch can mask a dead jev endpoint (or a
    // broken request shape) for an entire session — log it and stamp the
    // reason on the internal result fields.
    console.error(`[opencode-v2-security] jev review failed (${reason.slice(0, 200)}); falling back to the OpenAI auditor`)
    const result = await runEngine("openai")
    result.fallback_reason = reason.slice(0, 200)
    return result
  }
}

/**
 * @deprecated Use {@link reviewCommandWithAuditor} instead. This alias is kept only
 * for backwards-compatible imports and will be removed in a future release.
 */
export const reviewCommandWithDeepSeek = reviewCommandWithAuditor

export {
  bundledAuditorPath,
  bundledJevPath,
  normalizeReviewRequest,
  parseReviewResult,
  requestForPolicy,
  reviewerEnvironment,
}

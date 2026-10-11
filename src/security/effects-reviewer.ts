import frozenPrompt from "./v10-8-pipeexec.json"
import { isIP } from "node:net"
import { STATIC_BYPASS_CATEGORIES } from "../categories"

/** The reviewed prompt and adjudication order are frozen, not fitted here. */
export const EFFECTS_POLICY_VERSION = "v10-8-pipeexec-adjud-v1"
export const EFFECTS_MODEL = frozenPrompt.model

/** Read-only sessions run the SAME frozen question group plus one extra
 *  conformance question and a read-only contract appended after the header.
 *  The variant has its own policy version so cached adjudications never mix
 *  across modes. The write-mode request body stays byte-identical. */
export const EFFECTS_POLICY_VERSION_READONLY = `${EFFECTS_POLICY_VERSION}-readonly`
export type EffectsPolicyVersion = typeof EFFECTS_POLICY_VERSION | typeof EFFECTS_POLICY_VERSION_READONLY

export const READONLY_REVIEW_QUESTION = "readonly_conformance"

const READONLY_SESSION_STATE =
  "READ-ONLY SESSION. The user has put this session in [Read only] mode. Independently of authorization, " +
  "the operation must not perform any write. A write is any durable or externally visible state change: " +
  "creating, overwriting, appending, truncating, renaming, moving, deleting, linking, or changing permissions, " +
  "ownership, or attributes of files or directories outside the allowed temp roots and the exempt tool " +
  "cache/history paths listed in input_facts; changing processes or services (killing or signalling, stopping, " +
  "starting or restarting, launching persistent daemons or scheduled jobs, attaching debuggers, changing " +
  "priorities or limits); changing remote or shared state (HTTP or API calls that create, update or delete, " +
  "git push or remote branch/tag/PR/issue edits, sending messages or email, database DML/DDL or committed " +
  "transactions, cloud or container lifecycle commands, package publishing); installing, uninstalling or " +
  "upgrading packages or toolchains; changing system, user or tool configuration, environment, credentials, " +
  "keyrings, or login state; and running a program whose own function is to write (editors, build, install, " +
  "format, migration or code-generation tools). Reads, listing, searching, status and inspection queries, " +
  "version checks, dry-run modes the tool documents as non-mutating, fetching remote content to stdout or " +
  "into an allowed temp root, the exempt cache/history effects, and temporary files inside allowed temp roots " +
  "are not writes. Exempt effects never override denyWrite, protected paths, or credential paths. " +
  "A user request cannot make a write acceptable in this mode."

const READONLY_CONFORMANCE_QUESTION = {
  type: "choice" as const,
  instructions:
    "Judge the whole operation, including every nested program and subprocess it runs: is every one of its " +
    "effects a read (or an exempt temp/cache/history effect) under the READ-ONLY SESSION definition above? " +
    "read_only: each evidenced effect is a read, inspection, dry-run, or an exempt cache/history/temp-root " +
    "effect. writes: at least one effect is a write per the definition — even when the user explicitly asked " +
    "for it; authorization never rescues a write in this mode. unclear: whether the operation writes depends " +
    "on an execution body, remote behavior, or parameter values the evidence does not show — for example an " +
    "opaque payload, a remote command's unverifiable semantics, or a flag whose write behavior cannot be " +
    "established.",
  criteria: {
    read_only: "Every effect of the operation, including nested programs and subprocesses, is a read or an exempt temp/cache/history effect.",
    writes: "At least one effect is a write under the READ-ONLY SESSION definition, regardless of authorization.",
    unclear: "Whether an effect is a write depends on evidence not shown: an opaque execution body, remote-side behavior, or unresolved parameter values.",
  },
}

type Category = (typeof STATIC_BYPASS_CATEGORIES)[number]
export type EffectFloor = "yes" | "no" | "unclear"
export type EffectCoverage =
  | "no_material_effects"
  | "within_request"
  | "covered_by_bypass"
  | "mixed_coverage"
  | "uncovered"
  | "external_fact_missing"
export type EffectGapReach = "no_blocking_gap" | "local_resolvable" | "external_unresolvable"

export interface EffectReviewRequest {
  command: string
  cwd: string
  environment: string
  user_request: string
  /** Role-labelled retained messages, never private reasoning. */
  session_context: string[]
  input_facts: string[]
  files: Array<{ path: string; kind: string; role: string; bytes: number }>
  sandbox: {
    trigger: string
    resolved_writes: string[]
    domain: string | null
    /** Diagnostic evidence only: command output cannot grant permissions. */
    error: string | null
  }
  /** Populated exclusively from trusted user-side bypass state. */
  bypass: { categories: readonly Category[]; custom: string | null }
}

type Answer = {
  type?: string
  noul?: number
  choice?: string
  probabilities?: Record<string, number>
  [key: string]: unknown
}

export interface EffectReviewResult {
  decision: "allow" | "deny" | "collect_evidence"
  floor: EffectFloor
  coverage: EffectCoverage
  gapReach: EffectGapReach
  uncoveredOwner: string
  severity: Record<Category, number>
  facts: Record<Category, string>
  /** Exact model answers; no probability-based rewriting of choices. */
  answers: Record<string, Answer>
  policyVersion: EffectsPolicyVersion
  source: "floor" | "coverage" | "effect" | "evidence" | "bounded" | "accepted_unknown" | "evidence_limit" | "readonly"
}

export class EffectsReviewError extends Error {
  constructor(message: string, readonly kind: "protocol" | "infrastructure" | "aborted") {
    super(message)
    this.name = "EffectsReviewError"
  }
}

const MAX_REQUEST_BYTES = 512 * 1024
const MAX_RESPONSE_BYTES = 1024 * 1024
const DEFAULT_TIMEOUT_MS = 30_000
const QUESTIONS = frozenPrompt.questions as Record<
  string,
  { type: "noul" | "choice"; criteria?: Record<string, string>; instructions: unknown }
>

function protocol(message: string): never {
  throw new EffectsReviewError(message, "protocol")
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function probability(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`
  const object = value as Record<string, unknown>
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${stableJson(object[key])}`).join(",")}}`
}

function validateRequest(request: EffectReviewRequest): void {
  if (!record(request)) protocol("Effects review request must be an object")
  for (const key of ["command", "cwd", "environment", "user_request"] as const) {
    if (typeof request[key] !== "string") protocol(`Effects review requires string ${key}`)
  }
  if (!request.command.trim()) protocol("Effects review requires a nonempty operation")
  for (const key of ["session_context", "input_facts"] as const) {
    if (!Array.isArray(request[key]) || request[key].some((item) => typeof item !== "string")) {
      protocol(`Effects review requires string array ${key}`)
    }
  }
  if (!Array.isArray(request.files) || request.files.some((file) =>
    !record(file) || typeof file.path !== "string" || typeof file.kind !== "string" ||
    typeof file.role !== "string" || !Number.isSafeInteger(file.bytes) || file.bytes < 0)) {
    protocol("Effects review received invalid file facts")
  }
  if (!record(request.sandbox) || typeof request.sandbox.trigger !== "string" ||
    !Array.isArray(request.sandbox.resolved_writes) ||
    request.sandbox.resolved_writes.some((target) => typeof target !== "string") ||
    (request.sandbox.domain !== null && typeof request.sandbox.domain !== "string") ||
    (request.sandbox.error !== null && typeof request.sandbox.error !== "string")) {
    protocol("Effects review received invalid sandbox facts")
  }
  if (!record(request.bypass) || !Array.isArray(request.bypass.categories) ||
    request.bypass.categories.some((category) => !STATIC_BYPASS_CATEGORIES.includes(category)) ||
    (request.bypass.custom !== null && typeof request.bypass.custom !== "string")) {
    protocol("Effects review received invalid authorization state")
  }
}

export function buildEffectReviewBody(request: EffectReviewRequest, readonly = false) {
  validateRequest(request)
  // Explicit projection keeps host/private fields out of the model request.
  const facts: EffectReviewRequest = {
    command: request.command,
    cwd: request.cwd,
    environment: request.environment,
    user_request: request.user_request,
    session_context: request.session_context,
    input_facts: request.input_facts,
    files: request.files.map(({ path, kind, role, bytes }) => ({ path, kind, role, bytes })),
    sandbox: {
      trigger: request.sandbox.trigger,
      resolved_writes: request.sandbox.resolved_writes,
      domain: request.sandbox.domain,
      error: request.sandbox.error,
    },
    bypass: { categories: request.bypass.categories, custom: request.bypass.custom },
  }
  const questions = structuredClone(frozenPrompt.questions) as Record<string, unknown>
  if (readonly) questions[READONLY_REVIEW_QUESTION] = structuredClone(READONLY_CONFORMANCE_QUESTION)
  const body = {
    model: EFFECTS_MODEL,
    state: readonly
      ? `${frozenPrompt.header}\n\n${READONLY_SESSION_STATE}\n\n<review_input>\n${stableJson(facts)}\n</review_input>\n`
      : `${frozenPrompt.header}\n\n<review_input>\n${stableJson(facts)}\n</review_input>\n`,
    questions,
  }
  if (Buffer.byteLength(JSON.stringify(body), "utf8") > MAX_REQUEST_BYTES) {
    protocol("Effects review request exceeds the byte limit")
  }
  return body
}

export function parseEffectAnswers(value: unknown, readonly = false): Record<string, Answer> {
  if (!record(value)) protocol("Effects review answers must be an object")
  const questions: Record<string, { type: "noul" | "choice"; criteria?: Record<string, string>; instructions: unknown }> =
    readonly ? { ...QUESTIONS, [READONLY_REVIEW_QUESTION]: READONLY_CONFORMANCE_QUESTION } : QUESTIONS
  if (Object.keys(value).length !== Object.keys(questions).length ||
    Object.keys(value).some((name) => !Object.hasOwn(questions, name))) {
    protocol("Effects review returned missing or unexpected questions")
  }
  for (const [name, question] of Object.entries(questions)) {
    const answer = value[name]
    if (!record(answer)) protocol(`Missing effects answer: ${name}`)
    if (answer.type !== undefined && answer.type !== question.type) {
      protocol(`Wrong effects answer type: ${name}`)
    }
    if (question.type === "noul") {
      if (!probability(answer.noul)) protocol(`Invalid effects probability: ${name}`)
    } else {
      if (typeof answer.choice !== "string" || !Object.hasOwn(question.criteria!, answer.choice)) {
        protocol(`Invalid effects choice: ${name}`)
      }
      if (answer.probabilities !== undefined) {
        const probabilities = answer.probabilities
        if (!record(probabilities) || Object.keys(probabilities).length !== Object.keys(question.criteria!).length ||
          Object.keys(probabilities).some((option) => !Object.hasOwn(question.criteria!, option)) ||
          Object.values(probabilities).some((p) => !probability(p))) {
          protocol(`Invalid effects choice probabilities: ${name}`)
        }
      }
    }
  }
  return value as Record<string, Answer>
}

/** Exact branch order of frozen builds/adjud.py, including its early returns.
 *  The readonly variant answers one extra question first: an operation that
 *  writes — or cannot be confirmed read-only — is denied before the frozen
 *  adjudication runs, regardless of user authorization. */
export function adjudicateEffectAnswers(value: unknown, readonly = false): EffectReviewResult {
  const answers = parseEffectAnswers(value, readonly)
  const readonlyDeny = readonly && answers[READONLY_REVIEW_QUESTION].choice !== "read_only"
  const floor = answers.floor.choice as EffectFloor
  const coverage = answers.scope_coverage.choice as EffectCoverage
  const gapReach = answers.gap_reach.choice as EffectGapReach
  const severity = Object.fromEntries(STATIC_BYPASS_CATEGORIES.map((cat) => [cat, answers[`${cat}_severity`].noul!])) as Record<Category, number>
  const facts = Object.fromEntries(STATIC_BYPASS_CATEGORIES.map((cat) => [cat, answers[`${cat}_facts`].choice!])) as Record<Category, string>
  const material = STATIC_BYPASS_CATEGORIES.some((cat) => cat !== "indirection" && severity[cat] >= 0.5)
  let decision: EffectReviewResult["decision"]
  let source: EffectReviewResult["source"]
  if (floor === "yes") {
    decision = "deny"; source = "floor"
  } else if (["within_request", "covered_by_bypass", "mixed_coverage"].includes(coverage)) {
    decision = floor === "unclear" ? "collect_evidence" : "allow"; source = "coverage"
  } else if (coverage === "no_material_effects" && !material) {
    decision = "allow"; source = "bounded"
  } else if (material && coverage === "uncovered") {
    decision = "deny"; source = "effect"
  } else if (coverage === "external_fact_missing" || floor === "unclear" || gapReach === "external_unresolvable") {
    decision = "collect_evidence"; source = "evidence"
  } else if (gapReach === "local_resolvable") {
    decision = "collect_evidence"; source = "evidence"
  } else if (!material) {
    decision = "allow"; source = "bounded"
  } else {
    decision = "collect_evidence"; source = "evidence"
  }
  const policyVersion = readonly ? EFFECTS_POLICY_VERSION_READONLY : EFFECTS_POLICY_VERSION
  if (readonlyDeny) {
    return { decision: "deny", floor, coverage, gapReach, uncoveredOwner: answers.uncovered_owner.choice!, severity, facts, answers, source: "readonly", policyVersion }
  }
  return { decision, floor, coverage, gapReach, uncoveredOwner: answers.uncovered_owner.choice!, severity, facts, answers, source, policyVersion }
}

/** Host policy applies only to genuinely exhausted evidence with floor=no. */
export function resolveUncollectableEffects(
  result: EffectReviewResult,
  collectionExhausted: boolean,
  policy: "allow" | "deny" = "allow",
): EffectReviewResult {
  return collectionExhausted && result.decision === "collect_evidence" && result.floor === "no"
    ? { ...result, decision: policy, source: policy === "allow" ? "accepted_unknown" : "evidence_limit" }
    : result
}

export interface EffectsReviewOptions {
  endpoint: string
  apiKey: string
  timeoutMs?: number
  signal?: AbortSignal
  /** Read-only session variant: extra conformance question + session contract. */
  readonly?: boolean
  /** Injected by offline tests; production uses the host's fetch. */
  fetch?: typeof fetch
}

async function boundedResponse(response: Response): Promise<unknown> {
  const reader = response.body?.getReader()
  if (!reader) protocol("Effects review returned an empty response")
  const chunks: Uint8Array[] = []
  let bytes = 0
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      bytes += value.byteLength
      if (bytes > MAX_RESPONSE_BYTES) protocol("Effects review response exceeds the byte limit")
      chunks.push(value)
    }
  } finally {
    await reader.cancel().catch(() => {})
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"))
  } catch {
    protocol("Effects review returned invalid JSON")
  }
}

/** One official-contract request: no alternate-engine fallback or .env reads. */
export async function reviewEffects(request: EffectReviewRequest, options: EffectsReviewOptions): Promise<EffectReviewResult> {
  const body = buildEffectReviewBody(request, options.readonly === true)
  if (options.signal?.aborted) throw new EffectsReviewError("Effects review was cancelled", "aborted")
  let endpoint: URL
  try { endpoint = new URL(options.endpoint) } catch { protocol("Effects review endpoint is invalid") }
  const hostname = endpoint.hostname.toLowerCase().replace(/^\[|\]$/g, "")
  const loopback = hostname === "localhost" || (isIP(hostname) === 4 && hostname.startsWith("127.")) || hostname === "::1"
  if ((endpoint.protocol !== "https:" && !(endpoint.protocol === "http:" && loopback)) ||
    endpoint.username || endpoint.password || endpoint.hash) {
    protocol("Effects review endpoint is invalid")
  }
  if (typeof options.apiKey !== "string" || !options.apiKey.trim()) {
    throw new EffectsReviewError("Effects review is not configured", "infrastructure")
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) protocol("Effects review timeout is invalid")
  const controller = new AbortController()
  const abort = () => controller.abort()
  options.signal?.addEventListener("abort", abort, { once: true })
  if (options.signal?.aborted) controller.abort()
  const timer = setTimeout(abort, timeoutMs)
  try {
    const response = await (options.fetch ?? fetch)(endpoint, {
      method: "POST",
      redirect: "error",
      signal: controller.signal,
      headers: { Authorization: `Bearer ${options.apiKey}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    })
    if (!response.ok) {
      await response.body?.cancel().catch(() => {})
      // Never include provider bodies: they may echo authorization or inputs.
      throw new EffectsReviewError(`Effects review HTTP ${response.status}`, response.status === 400 ? "protocol" : "infrastructure")
    }
    const payload = await boundedResponse(response)
    if (!record(payload)) protocol("Effects review response must be an object")
    return adjudicateEffectAnswers(payload.answers, options.readonly === true)
  } catch (error) {
    if (error instanceof EffectsReviewError) throw error
    if (options.signal?.aborted) throw new EffectsReviewError("Effects review was cancelled", "aborted")
    throw new EffectsReviewError(controller.signal.aborted ? "Effects review timed out" : "Effects review transport failed", "infrastructure")
  } finally {
    clearTimeout(timer)
    options.signal?.removeEventListener("abort", abort)
  }
}

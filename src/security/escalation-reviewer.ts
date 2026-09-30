import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process"
import { lstatSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

/** The only decisions that can come back from the escalation reviewer. */
export type EscalationReviewDecision = "allow_once" | "ask_user" | "deny"

export type EscalationReviewPermissionScope = {
  r: boolean
  w: boolean
  x: boolean
}

export type EscalationReviewContextMessage = {
  role: "user" | "assistant"
  text: string
}

export type PreviousFailedEscalation = {
  command: string
  categories: readonly string[]
  justification: string
  decision: "ask_user" | "deny"
}

/** The denial an earlier classifier pass recorded for this same command.
 * The risk categories are host-computed state: the reviewer's coverage rule
 * (`requested categories ⊇ riskCategories`) is a pure set check. The auditor
 * validates this field strictly: exactly `command` and `riskCategories`. */
export type PreviousDenial = {
  command: string
  riskCategories: string[]
}

export type EscalationReviewRequest = {
  command: string
  categories: readonly string[]
  justification: string
  currentUserInput: string
  /** The user's last five messages, oldest first — one escalation may span
   * several user turns, so the reviewer sees more than the latest input. */
  recentUserInputs?: readonly string[]
  recentContext: readonly EscalationReviewContextMessage[]
  cwd?: string
  worktree?: string
  permScope: EscalationReviewPermissionScope
  previousFailedEscalations?: readonly PreviousFailedEscalation[]
  previousDenial?: PreviousDenial
}

export interface EscalationReviewLimiter {
  acquire(signal?: AbortSignal): Promise<void>
}

/** Review engines understood by this module. "openai" is the
 * OpenAI-compatible escalation-reviewer.py; "jev" is the one-shot
 * systemone adapter jev-escalation-reviewer.py. */
export type EscalationReviewEngine = "jev" | "openai"

export type EscalationReviewOptions = {
  endpoint: string
  model: string
  apiKey: string
  python?: string
  auditorPath?: string
  timeout?: number
  signal?: AbortSignal
  /** Which engine to consult. "auto" tries Jev when `jev` is configured and
   * falls back to the OpenAI-compatible reviewer on infrastructure failures
   * only; an explicit "jev" never falls back. Default: "openai". */
  reviewer?: "jev" | "openai" | "auto"
  /** Resolved Jev reviewer settings; required for reviewer:"jev" and used
   * by "auto". */
  jev?: { endpoint: string; model: string; apiKey: string }
  /** Path to jev-escalation-reviewer.py; defaults to the bundled script. */
  jevPath?: string
  /** Test/local injection point. The default is the process-wide limiter. */
  limiter?: EscalationReviewLimiter
}

export type EscalationReviewErrorKind = "protocol" | "infra" | "timeout" | "aborted"

/**
 * Every failure in this module is an error. In particular, a malformed or
 * unavailable reviewer never gets converted into an approval.
 */
export class EscalationReviewError extends Error {
  readonly kind: EscalationReviewErrorKind
  readonly exitCode?: number
  readonly code?: string

  constructor(
    message: string,
    kind: EscalationReviewErrorKind,
    extras?: { exitCode?: number; code?: string },
  ) {
    super(message)
    this.name = "EscalationReviewError"
    this.kind = kind
    this.exitCode = extras?.exitCode
    this.code = extras?.code
  }
}

export const ESCALATION_REVIEW_WINDOW_MS = 3_000
export const ESCALATION_REVIEW_MAX_REQUESTS = 2
// The escalation reviewer runs with thinking enabled; real reviews take tens
// of seconds on thinking endpoints, so the child budget is much larger than
// the ordinary dynamic reviewer's.
export const DEFAULT_ESCALATION_REVIEW_TIMEOUT_MS = 120_000
// The Python deadline sits strictly below the child-process kill for every
// positive budget (grace shrinks to half the budget under 4 s), so a slow
// endpoint ends in a clean transport error, not a SIGKILL.
const HTTP_DEADLINE_GRACE_MS = 2_000
function pythonDeadlineSeconds(timeoutMs: number): number {
  const graceMs = Math.min(HTTP_DEADLINE_GRACE_MS, timeoutMs / 2)
  return Math.max(0.001, (timeoutMs - graceMs) / 1000)
}
export const MAX_ESCALATION_REVIEW_INPUT_BYTES = 256 * 1024
export const MAX_ESCALATION_REVIEW_OUTPUT_BYTES = 64 * 1024
const MAX_ESCALATION_REVIEW_STDERR_BYTES = 8 * 1024
const ISOLATED_PYTHON_FLAGS = ["-I", "-B"]

const ESCALATION_DECISIONS: readonly EscalationReviewDecision[] = [
  "allow_once",
  "ask_user",
  "deny",
]

function abortError(): EscalationReviewError {
  return new EscalationReviewError("The escalation review was aborted", "aborted")
}

/** Map child exit codes to error kinds. 4/5 are transport failures (HTTP
 * status or network — eligible for engine fallback under auto); 6/7 are the
 * scripts' own protocol/fail-closed exits and must never be retried on
 * another engine. A signal or any other code is a protocol violation. */
function classifyEscalationExitCode(code: number | null): EscalationReviewErrorKind {
  if (code === 4 || code === 5) return "infra"
  return "protocol"
}

function waitForPreviousTurn(previous: Promise<void>, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(abortError())
      return
    }
    let abort!: () => void
    const cleanup = () => signal.removeEventListener("abort", abort)
    abort = () => {
      cleanup()
      reject(abortError())
    }
    signal.addEventListener("abort", abort, { once: true })
    previous.then(
      () => {
        cleanup()
        resolve()
      },
      (error) => {
        cleanup()
        reject(error)
      },
    )
  })
}

function abortableSleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(abortError())
  return new Promise((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined
    const abort = () => {
      if (timer !== undefined) clearTimeout(timer)
      signal?.removeEventListener("abort", abort)
      reject(abortError())
    }
    timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort)
      resolve()
    }, ms)
    signal?.addEventListener("abort", abort, { once: true })
  })
}

export type RollingEscalationReviewLimiterOptions = {
  windowMs?: number
  maxRequests?: number
  now?: () => number
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>
}

/**
 * A process-local sliding-window limiter. A timestamp is reserved before a
 * caller starts its Python child, so concurrent callers cannot race through
 * the two-request allowance.
 */
export class RollingEscalationReviewLimiter implements EscalationReviewLimiter {
  readonly windowMs: number
  readonly maxRequests: number
  private readonly now: () => number
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>
  private timestamps: number[] = []
  private tail: Promise<void> = Promise.resolve()

  constructor(options: RollingEscalationReviewLimiterOptions = {}) {
    this.windowMs = options.windowMs ?? ESCALATION_REVIEW_WINDOW_MS
    this.maxRequests = options.maxRequests ?? ESCALATION_REVIEW_MAX_REQUESTS
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) {
      throw new RangeError("Escalation review limiter windowMs must be positive")
    }
    if (!Number.isInteger(this.maxRequests) || this.maxRequests <= 0) {
      throw new RangeError("Escalation review limiter maxRequests must be a positive integer")
    }
    this.now = options.now ?? (() => Date.now())
    this.sleep = options.sleep ?? abortableSleep
  }

  /** Clear reservations. This is intended for test/session teardown. */
  reset(): void {
    this.timestamps = []
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    let release!: () => void
    let released = false
    const releaseOnce = () => {
      if (released) return
      released = true
      release()
    }

    const previous = this.tail
    this.tail = new Promise<void>((resolve) => {
      release = resolve
    })

    let lockHeld = false
    try {
      if (signal?.aborted) throw abortError()
      // An aborted waiter must not wait for a full rolling window. Its queue
      // reservation remains until the preceding waiter finishes, preserving
      // FIFO ordering for callers behind it.
      if (signal) {
        await waitForPreviousTurn(previous, signal)
      } else {
        await previous
      }
      lockHeld = true
      if (signal?.aborted) throw abortError()

      for (;;) {
        const now = this.now()
        this.timestamps = this.timestamps.filter((timestamp) => now - timestamp < this.windowMs)
        if (this.timestamps.length < this.maxRequests) {
          this.timestamps.push(now)
          return
        }
        const waitMs = Math.max(0, this.timestamps[0] + this.windowMs - now)
        await this.sleep(waitMs, signal)
        if (signal?.aborted) throw abortError()
      }
    } catch (error) {
      if (!lockHeld) {
        // If this waiter was aborted while queued, release only after the
        // previous holder has released its turn.
        void previous.then(releaseOnce, releaseOnce)
      }
      throw error
    } finally {
      if (lockHeld) releaseOnce()
    }
  }
}

/** Short factory useful to tests without exposing process-global state. */
export function createEscalationReviewLimiter(
  options: RollingEscalationReviewLimiterOptions = {},
): RollingEscalationReviewLimiter {
  return new RollingEscalationReviewLimiter(options)
}

let processLimiter: EscalationReviewLimiter = new RollingEscalationReviewLimiter()

/** Replace the process-wide limiter, primarily for focused tests. */
export function setEscalationReviewLimiter(limiter?: EscalationReviewLimiter): void {
  if (limiter) {
    processLimiter = limiter
    return
  }
  resetEscalationReviewLimiter()
}

/** Reset reservations in the process-wide limiter. */
export function resetEscalationReviewLimiter(): void {
  const candidate = processLimiter as Partial<RollingEscalationReviewLimiter>
  if (typeof candidate.reset === "function") {
    candidate.reset()
  } else {
    processLimiter = new RollingEscalationReviewLimiter()
  }
}

// A descriptive alias is convenient for callers that call this a rate limiter.
export const resetEscalationReviewRateLimiter = resetEscalationReviewLimiter

function isRegularFile(filePath: string): boolean {
  try {
    return lstatSync(filePath).isFile()
  } catch {
    return false
  }
}

/** Find the script shipped next to this module in source or bundled layouts. */
export function bundledEscalationReviewerPath(): string | undefined {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [
    path.join(moduleDirectory, "escalation-reviewer.py"),
    path.join(moduleDirectory, "security", "escalation-reviewer.py"),
    path.join(moduleDirectory, "..", "src", "security", "escalation-reviewer.py"),
  ]
  return candidates.find((candidate) => isRegularFile(candidate))
}

/** Find the bundled Jev escalation adapter, same layout search. */
export function bundledJevEscalationPath(): string | undefined {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [
    path.join(moduleDirectory, "jev-escalation-reviewer.py"),
    path.join(moduleDirectory, "security", "jev-escalation-reviewer.py"),
    path.join(moduleDirectory, "..", "src", "security", "jev-escalation-reviewer.py"),
  ]
  return candidates.find((candidate) => isRegularFile(candidate))
}

export const findBundledEscalationReviewerPath = bundledEscalationReviewerPath

type PythonCandidate = { executable: string; prefixArgs: string[] }

function pythonCandidates(configured?: string): PythonCandidate[] {
  if (configured) return [{ executable: configured, prefixArgs: [...ISOLATED_PYTHON_FLAGS] }]
  if (process.platform === "win32") {
    return [
      { executable: "python", prefixArgs: [...ISOLATED_PYTHON_FLAGS] },
      { executable: "python3", prefixArgs: [...ISOLATED_PYTHON_FLAGS] },
    ]
  }
  return [
    { executable: "python3", prefixArgs: [...ISOLATED_PYTHON_FLAGS] },
    { executable: "python", prefixArgs: [...ISOLATED_PYTHON_FLAGS] },
  ]
}

type EscalationEnvironmentOptions = Pick<EscalationReviewOptions, "endpoint" | "model" | "apiKey"> & {
  /** Resolved child-process budget; forwarded as the HTTP read deadline. */
  timeoutMs?: number
  /** Which engine this child runs; selects the env var names. */
  engine?: EscalationReviewEngine
  /** Resolved Jev settings; forwarded as JEV_* when engine is "jev". */
  jev?: { endpoint: string; model: string; apiKey: string }
}

function reviewerEnvironment(options: EscalationEnvironmentOptions): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {}
  // Keep provider credentials and arbitrary host configuration out of the
  // child. The proxy/CA names are the only non-runtime values retained.
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
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
  ]
  for (const name of names) {
    if (process.env[name] !== undefined) environment[name] = process.env[name]
  }
  environment.PYTHONIOENCODING = "utf-8"
  environment.PYTHONUTF8 = "1"
  if (options.engine === "jev" && options.jev) {
    environment.JEV_ENDPOINT = options.jev.endpoint
    environment.JEV_MODEL = options.jev.model
    environment.JEV_API_KEY = options.jev.apiKey
  } else {
    environment.OPENCODE_V2_SECURITY_ESCALATION_ENDPOINT = options.endpoint
    environment.OPENCODE_V2_SECURITY_ESCALATION_MODEL = options.model
    environment.OPENCODE_V2_SECURITY_ESCALATION_API_KEY = options.apiKey
  }
  if (typeof options.timeoutMs === "number" && Number.isFinite(options.timeoutMs) && options.timeoutMs > 0) {
    environment.OPENCODE_V2_SECURITY_ESCALATION_DEADLINE_S = String(
      pythonDeadlineSeconds(options.timeoutMs),
    )
  }
  return environment
}

/** Parse the only stdout protocol accepted from the Python reviewer. */
export function parseEscalationReviewOutput(output: string): EscalationReviewDecision {
  const content = output.trim()
  if (ESCALATION_DECISIONS.includes(content as EscalationReviewDecision)) {
    return content as EscalationReviewDecision
  }

  if (content.startsWith("<think>")) {
    const close = content.indexOf("</think>", "<think>".length)
    if (close >= 0) {
      const thought = content.slice("<think>".length, close)
      const tail = content.slice(close + "</think>".length).trim()
      // Only one complete leading block is compatible. A second block or a
      // nested marker is not a harmless formatting variation.
      if (!thought.includes("<think>") && !thought.includes("</think>")) {
        if (ESCALATION_DECISIONS.includes(tail as EscalationReviewDecision)) {
          return tail as EscalationReviewDecision
        }
      }
    }
  }

  throw new EscalationReviewError(
    "The escalation reviewer returned an invalid decision protocol",
    "protocol",
  )
}

// These aliases make the protocol parser easy to use from small integrations.
export const parseEscalationReviewerOutput = parseEscalationReviewOutput

function validateOptions(options: EscalationReviewOptions): void {
  if (!options || typeof options !== "object") {
    throw new EscalationReviewError("Escalation review options are required", "protocol")
  }
  if (typeof options.endpoint !== "string" || options.endpoint.trim() === "") {
    throw new EscalationReviewError("Escalation review endpoint is required", "protocol")
  }
  if (typeof options.model !== "string" || options.model.trim() === "") {
    throw new EscalationReviewError("Escalation review model is required", "protocol")
  }
  if (typeof options.apiKey !== "string" || options.apiKey.trim() === "") {
    throw new EscalationReviewError("Escalation review apiKey is required", "protocol")
  }
  if (options.timeout !== undefined && (!Number.isFinite(options.timeout) || options.timeout <= 0)) {
    throw new EscalationReviewError("Escalation review timeout must be positive", "protocol")
  }
}

function serializeRequest(request: EscalationReviewRequest): string {
  let serialized: string
  try {
    serialized = JSON.stringify(request)
  } catch (error) {
    throw new EscalationReviewError(
      `Escalation review request could not be serialized: ${error instanceof Error ? error.message : String(error)}`,
      "protocol",
    )
  }
  if (typeof serialized !== "string") {
    throw new EscalationReviewError("Escalation review request did not serialize to JSON", "protocol")
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_ESCALATION_REVIEW_INPUT_BYTES) {
    throw new EscalationReviewError("Escalation review input exceeded the safety limit", "protocol")
  }
  return serialized
}

function boundedErrorText(value: string, maxBytes: number): string {
  const bytes = Buffer.from(value, "utf8")
  if (bytes.length <= maxBytes) return value
  return bytes.subarray(bytes.length - maxBytes).toString("utf8")
}

type SpawnOptions = {
  executable: string
  prefixArgs: string[]
  auditorPath: string
  input: string
  timeoutMs: number
  options: EscalationReviewOptions
}

async function runPythonCandidate(config: SpawnOptions): Promise<EscalationReviewDecision> {
  return await new Promise<EscalationReviewDecision>((resolve, reject) => {
    let child: ChildProcessWithoutNullStreams
    try {
      child = spawn(config.executable, [...config.prefixArgs, config.auditorPath], {
        cwd: path.dirname(config.auditorPath),
        env: reviewerEnvironment({ ...config.options, timeoutMs: config.timeoutMs }),
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      })
    } catch (error) {
      const code = (error as NodeJS.ErrnoException | undefined)?.code
      reject(
        new EscalationReviewError(
          `Could not start escalation reviewer: ${error instanceof Error ? error.message : String(error)}`,
          "infra",
          { code },
        ),
      )
      return
    }

    let stdout = ""
    let stderr = ""
    let stdoutBytes = 0
    let settled = false
    let timedOut = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const signal = config.options.signal
    let abort!: () => void
    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer)
      signal?.removeEventListener("abort", abort)
    }
    const finish = (callback: () => void) => {
      if (settled) return
      settled = true
      cleanup()
      callback()
    }
    abort = () => {
      child.kill()
      finish(() => reject(abortError()))
    }

    child.stdout.on("data", (chunk: Buffer | string) => {
      if (settled) return
      const text = chunk.toString()
      stdoutBytes += Buffer.byteLength(text, "utf8")
      if (stdoutBytes > MAX_ESCALATION_REVIEW_OUTPUT_BYTES) {
        child.kill()
        finish(() =>
          reject(new EscalationReviewError("The escalation reviewer returned too much output", "protocol")),
        )
        return
      }
      stdout += text
    })
    child.stderr.on("data", (chunk: Buffer | string) => {
      if (settled) return
      stderr = boundedErrorText(stderr + chunk.toString(), MAX_ESCALATION_REVIEW_STDERR_BYTES)
    })
    child.stdin.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EPIPE") {
        finish(() =>
          reject(
            new EscalationReviewError(`Could not write escalation review input: ${error.message}`, "infra", {
              code: error.code,
            }),
          ),
        )
      }
    })
    child.once("error", (error: NodeJS.ErrnoException) => {
      finish(() =>
        reject(
          new EscalationReviewError(`Could not start escalation reviewer: ${error.message}`, "infra", {
            code: error.code,
          }),
        ),
      )
    })
    child.once("close", (code: number | null) => {
      finish(() => {
        if (timedOut) {
          reject(
            new EscalationReviewError(
              `The escalation reviewer timed out after ${config.timeoutMs}ms`,
              "timeout",
            ),
          )
          return
        }
        if (code !== 0) {
          const detail = stderr.trim().replace(/\s+/g, " ").slice(-500)
          reject(
            new EscalationReviewError(
              detail ||
                (code === null
                  ? "The escalation reviewer was terminated by a signal"
                  : `The escalation reviewer exited with code ${code}`),
              classifyEscalationExitCode(code),
              { exitCode: code === null ? undefined : code },
            ),
          )
          return
        }
        try {
          resolve(parseEscalationReviewOutput(stdout))
        } catch (error) {
          reject(
            error instanceof EscalationReviewError
              ? error
              : new EscalationReviewError(String(error), "protocol"),
          )
        }
      })
    })

    timer = setTimeout(() => {
      timedOut = true
      child.kill()
      finish(() =>
        reject(
          new EscalationReviewError(
            `The escalation reviewer timed out after ${config.timeoutMs}ms`,
            "timeout",
          ),
        ),
      )
    }, config.timeoutMs)
    signal?.addEventListener("abort", abort, { once: true })
    if (signal?.aborted) {
      abort()
      return
    }
    try {
      child.stdin.end(config.input)
    } catch (error) {
      finish(() =>
        reject(
          new EscalationReviewError(
            `Could not write escalation review input: ${error instanceof Error ? error.message : String(error)}`,
            "infra",
          ),
        ),
      )
    }
  })
}

/** Verdict plus diagnostics for the caller's trace: which engine answered
 * and, for auto fallbacks, why Jev was skipped. */
export type EscalationReviewResult = {
  decision: EscalationReviewDecision
  engine: EscalationReviewEngine
  fallback_reason?: string
}

/**
 * Run one isolated escalation review. This starts a direct Python child; it
 * never creates an OpenCode subagent or treats an infrastructure error as an
 * approval. Engine dispatch mirrors reviewCommandWithAuditor: "auto" prefers
 * Jev and falls back to the OpenAI-compatible reviewer on infrastructure
 * failures only; explicit "jev" never falls back; protocol errors and aborts
 * fail closed everywhere.
 */
export async function reviewEscalationDetailed(
  request: EscalationReviewRequest,
  options: EscalationReviewOptions,
): Promise<EscalationReviewResult> {
  validateOptions(options)
  if (options.signal?.aborted) throw abortError()

  const input = serializeRequest(request)
  const timeoutMs = options.timeout ?? DEFAULT_ESCALATION_REVIEW_TIMEOUT_MS
  const limiter = options.limiter ?? processLimiter

  const runEngine = async (engine: EscalationReviewEngine): Promise<EscalationReviewResult> => {
    const scriptPath =
      engine === "jev"
        ? (options.jevPath ?? bundledJevEscalationPath())
        : (options.auditorPath ?? bundledEscalationReviewerPath())
    if (!scriptPath) {
      throw new EscalationReviewError(
        `The bundled ${engine === "jev" ? "jev-escalation-reviewer" : "escalation-reviewer"}.py could not be found or is not a regular file`,
        engine === "jev" ? "infra" : "protocol",
      )
    }
    const resolvedAuditorPath = path.resolve(scriptPath)
    if (!isRegularFile(resolvedAuditorPath)) {
      throw new EscalationReviewError(
        "The configured escalation reviewer is not a regular file",
        engine === "jev" ? "infra" : "protocol",
      )
    }

    // Acquire immediately before the child is spawned. Invalid input and a
    // missing script therefore do not consume a start slot.
    await limiter.acquire(options.signal)

    const failures: EscalationReviewError[] = []
    for (const candidate of pythonCandidates(options.python)) {
      try {
        const decision = await runPythonCandidate({
          executable: candidate.executable,
          prefixArgs: candidate.prefixArgs,
          auditorPath: resolvedAuditorPath,
          input,
          timeoutMs,
          options: { ...options, engine },
        })
        return { decision, engine }
      } catch (error) {
        const failure =
          error instanceof EscalationReviewError
            ? error
            : new EscalationReviewError(String(error), "infra")
        failures.push(failure)
        if (options.python || failure.code !== "ENOENT") throw failure
      }
    }

    throw (
      failures.at(-1) ??
      new EscalationReviewError("No python3 or python interpreter was found for escalation review", "infra")
    )
  }

  const jevReady = Boolean(options.jev?.apiKey && options.jev.endpoint && options.jev.model)
  const preference = options.reviewer ?? "openai"
  if (preference === "openai" || (preference === "auto" && !jevReady)) {
    return runEngine("openai")
  }
  if (!jevReady) {
    // reviewer:"jev" explicitly requested without a usable configuration.
    throw new EscalationReviewError("The Jev escalation reviewer is not configured", "infra")
  }
  try {
    return await runEngine("jev")
  } catch (error) {
    // auto only: Jev infrastructure failures (network, 5xx, timeout, missing
    // interpreter) fall back to the OpenAI-compatible reviewer. An explicit
    // reviewer:"jev" never falls back. Protocol errors and aborts never
    // retry — they fail closed.
    const infra =
      error instanceof EscalationReviewError &&
      (error.kind === "infra" || error.kind === "timeout")
    if (preference !== "auto" || !infra || options.signal?.aborted) throw error
    const reason = error instanceof Error ? error.message : String(error)
    // Visibility: a silent engine switch can mask a dead jev endpoint for an
    // entire escalation — log it and stamp the reason on the result.
    console.error(
      `[opencode-v2-security] jev escalation review failed (${reason.slice(0, 200)}); falling back to the OpenAI reviewer`,
    )
    const result = await runEngine("openai")
    result.fallback_reason = reason.slice(0, 200)
    return result
  }
}

export async function reviewEscalation(
  request: EscalationReviewRequest,
  options: EscalationReviewOptions,
): Promise<EscalationReviewDecision> {
  const result = await reviewEscalationDetailed(request, options)
  return result.decision
}

// Keep names parallel to the existing command reviewer and make the intended
// direct-review boundary obvious to callers.
export const reviewEscalationWithAuditor = reviewEscalation
export const reviewEscalationRequest = reviewEscalation

export { reviewerEnvironment }

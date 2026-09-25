import { afterAll, beforeEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp, rm } from "node:fs/promises"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_MARKER,
  JUSTIFICATION_HEADER_PREFIX,
} from "../src/security/escalation"
import {
  reviewEscalation,
  reviewerEnvironment,
  RollingEscalationReviewLimiter,
  resetEscalationReviewLimiter,
  DEFAULT_ESCALATION_REVIEW_TIMEOUT_MS,
  type EscalationReviewRequest,
} from "../src/security/escalation-reviewer"
import {
  reviewCommandWithAuditor,
  reviewerEnvironment as auditorEnvironment,
  ReviewError,
} from "../src/security/reviewer"
import { escalationCommandsAreSimilar } from "../src/security/escalation-state"

// Regression coverage for the post-audit escalation fixes (see FIX-NOTES.md):
// E1/D1 reviewer deadlines derive from the child budget and stay strictly
// below it for every positive value, E2 floor pre-check sees floor rules
// shadowed by unrequested categories / earlier segments, E3 denied
// escalations are remembered along the ancestor chain, E4 reviewer prompt
// carries category semantics, D2 similarity tolerates comments/redirects/
// trailing `; true`.

let workdir: string | undefined
const scopes: Scope.Closeable[] = []
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "escalation-fixes-"))
  return workdir
}

beforeEach(() => resetEscalationReviewLimiter())

afterAll(async () => {
  for (const scope of scopes) {
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

type HookCb = (ev: never) => Effect.Effect<void, unknown>
type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>

type Harness = {
  executeBefore: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string; description?: string }>
  contextCalls: () => number
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

type CapturedRequest = { body: Record<string, unknown> }

/** Minimal OpenAI-compatible reviewer mock; `respond` runs per request so a
 * multi-round test can answer a tool call then stall the next response. */
async function startReviewer(
  respond: (round: number) => { status?: number; content?: string; delayMs?: number },
): Promise<{ endpoint: string; requests: CapturedRequest[] }> {
  const requests: CapturedRequest[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on("data", (chunk: Buffer) => chunks.push(chunk))
    req.on("end", () => {
      try {
        requests.push({ body: JSON.parse(Buffer.concat(chunks).toString("utf8")) })
      } catch {
        requests.push({ body: {} })
      }
      const answer = respond(requests.length)
      setTimeout(() => {
        const status = answer.status ?? 200
        const payload =
          status === 200
            ? JSON.stringify({ choices: [{ message: { role: "assistant", content: answer.content ?? "deny" } }] })
            : JSON.stringify({ error: "mock reviewer error" })
        res.writeHead(status, { "Content-Type": "application/json" })
        res.end(payload)
      }, answer.delayMs ?? 0)
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  servers.push(server)
  const port = (server.address() as AddressInfo).port
  return { endpoint: `http://127.0.0.1:${port}/v1`, requests }
}

const MESSAGES = [
  { type: "user", text: "Please fix the ownership of the app directory" },
  { type: "assistant", content: [{ type: "text", text: "I need to run a privileged command." }] },
]

async function startPlugin(
  options: Record<string, unknown>,
  events: unknown[] = [],
): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  let contextCalls = 0

  const ctx = {
    options: {
      failPolicy: "fail_close",
      logReviewerTrace: false,
      sandbox: { enabled: false },
      ...options,
    },
    tool: {
      hook: (name: string, cb: HookCb) => {
        collected[name] = cb
        return Effect.void
      },
    },
    shell: {
      hook: (name: string, cb: HookCb) => {
        collected[`shell.${name}`] = cb
        return Effect.void
      },
    },
    command: {
      transform: (cb: (draft: { add(d: { name: string; execute: CommandExec }): void }) => void) =>
        Effect.sync(() => cb({ add: (d) => void commands.set(d.name, d.execute) })),
    },
    permission: { hook: () => Effect.void },
    session: {
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      context: () =>
        Effect.sync(() => {
          contextCalls += 1
          return MESSAGES
        }),
      synthetic: (input: { sessionID: string; text: string; description?: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
    },
    rpc: {
      register: () =>
        Effect.succeed({
          events: { emit: () => Effect.void },
        }),
    },
    event: { subscribe: () => Stream.fromIterable(events) },
  }

  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )
  return {
    executeBefore: collected["execute.before"]!,
    commands,
    synthetic,
    contextCalls: () => contextCalls,
  }
}

const runBefore = (h: Harness, sessionID: string, input: Record<string, unknown>) =>
  failureMessage(
    h.executeBefore({
      tool: "shell",
      sessionID,
      agent: "test",
      messageID: "m1",
      id: `call-${Math.random()}`,
      input,
    } as never),
  )

const escalation = (categories: string, justification: string, command: string) =>
  [ESCALATION_MARKER, `${CATEGORY_HEADER_PREFIX} ${categories}`, `${JUSTIFICATION_HEADER_PREFIX} ${justification}`, command].join("\n")

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const reviewRequest: EscalationReviewRequest = {
  command: "chown -R www-data:www-data /srv/app",
  categories: ["privilege"],
  justification: "fix ownership as the user asked",
  currentUserInput: "Please fix the ownership of the app directory",
  recentContext: [{ role: "user", text: "Please fix the ownership of the app directory" }],
  permScope: { r: true, w: true, x: true },
}

describe("E1/D1: reviewer deadlines derive from and stay below the child budget", () => {
  test("both reviewers forward a deadline strictly below the parent budget", () => {
    const escEnv = reviewerEnvironment({
      endpoint: "https://example.invalid/v1",
      model: "m",
      apiKey: "k",
      timeoutMs: 120_000,
    })
    expect(Number(escEnv.OPENCODE_V2_SECURITY_ESCALATION_DEADLINE_S)).toBeCloseTo(118)

    const auditEnv = auditorEnvironment({
      endpoint: "https://example.invalid/v1/chat/completions",
      model: "m",
      apiKey: "k",
      maxRounds: 1,
      policy: "LOOSE",
      timeoutMs: 30_000,
    })
    expect(Number(auditEnv.OPENCODE_V2_SECURITY_REVIEW_DEADLINE_S)).toBeCloseTo(28)
  })

  test("the forwarded deadline is strictly below every positive parent budget", () => {
    // timeoutMs >= 2: deadline strictly below. (timeoutMs = 1 bottoms out at
    // the 0.001 s floor — nothing can sit strictly below 1 ms while being a
    // usable socket timeout.)
    for (const timeoutMs of [2, 10, 999, 1_000, 3_999, 4_000, 5_000, 30_000, 120_000]) {
      const esc = Number(
        reviewerEnvironment({
          endpoint: "https://example.invalid/v1",
          model: "m",
          apiKey: "k",
          timeoutMs,
        }).OPENCODE_V2_SECURITY_ESCALATION_DEADLINE_S,
      )
      const dyn = Number(
        auditorEnvironment({
          endpoint: "https://example.invalid/v1/chat/completions",
          model: "m",
          apiKey: "k",
          maxRounds: 1,
          policy: "LOOSE",
          timeoutMs,
        }).OPENCODE_V2_SECURITY_REVIEW_DEADLINE_S,
      )
      for (const seconds of [esc, dyn]) {
        expect(seconds).toBeGreaterThan(0)
        expect(seconds).toBeLessThan(timeoutMs / 1000)
      }
    }
    // The reviewer's original defect case: a 1 s budget must forward < 1 s.
    expect(
      Number(
        auditorEnvironment({
          endpoint: "https://example.invalid/v1/chat/completions",
          model: "m",
          apiKey: "k",
          maxRounds: 1,
          policy: "LOOSE",
          timeoutMs: 1_000,
        }).OPENCODE_V2_SECURITY_REVIEW_DEADLINE_S,
      ),
    ).toBeLessThan(1)
  })

  test("a thinking-speed answer (>20s) reaches a decision instead of timing out", async () => {
    // The shipped 20s HTTP cap made every real review a transport error. The
    // mock answers at ~22s — inside the thinking-sized default budget.
    const mock = await startReviewer(() => ({ content: "deny", delayMs: 22_000 }))
    const decision = await reviewEscalation(reviewRequest, {
      endpoint: mock.endpoint,
      model: "m",
      apiKey: "k",
      python: "python3",
      limiter: new RollingEscalationReviewLimiter({ windowMs: 20, maxRequests: 2 }),
    })
    expect(DEFAULT_ESCALATION_REVIEW_TIMEOUT_MS).toBeGreaterThan(22_000)
    expect(decision).toBe("deny")
    expect(mock.requests).toHaveLength(1)
  }, 60_000)

  test("one absolute deadline covers every round of a multi-round review", async () => {
    // Round 1 asks for a tool call at ~2.6s; round 2 would answer at ~5.2s,
    // but the whole-review deadline (3s for a 5s parent budget) fires first —
    // the Python side must report the failure itself, BEFORE the parent kill,
    // instead of being SIGKILLed at 5s.
    const directory = await ensureWorkdir()
    const requests: CapturedRequest[] = []
    const server = createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on("data", (chunk: Buffer) => chunks.push(chunk))
      req.on("end", () => {
        try {
          requests.push({ body: JSON.parse(Buffer.concat(chunks).toString("utf8")) })
        } catch {
          requests.push({ body: {} })
        }
        const first = requests.length === 1
        setTimeout(() => {
          res.writeHead(200, { "Content-Type": "application/json" })
          res.end(
            first
              ? JSON.stringify({
                  choices: [
                    {
                      finish_reason: "tool_calls",
                      message: {
                        role: "assistant",
                        content: "",
                        tool_calls: [
                          {
                            id: "call_1",
                            type: "function",
                            function: {
                              name: "list_directory",
                              arguments: JSON.stringify({ path: directory }),
                            },
                          },
                        ],
                      },
                    },
                  ],
                })
              : JSON.stringify({
                  choices: [{ message: { role: "assistant", content: '{"decision":"ALLOW","reason":""}' } }],
                }),
          )
        }, 2_600)
      })
    })
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    servers.push(server)
    const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`

    const request = {
      command: "ls -la /tmp",
      localScripts: [],
      uninspectedLocalScripts: [],
      targetDirectories: [],
      uninspectedTargetDirectories: [],
      referencedPaths: [],
      referencedPathsTruncated: false,
      worktree: directory,
      cwd: directory,
    }
    const started = Date.now()
    let error: unknown
    try {
      await reviewCommandWithAuditor(request, {
        endpoint,
        model: "m",
        apiKey: "k",
        maxRounds: 2,
        policy: "LOOSE",
        python: "python3",
        timeout: 5_000,
      })
    } catch (caught) {
      error = caught
    }
    const elapsed = Date.now() - started
    expect(error).toBeInstanceOf(ReviewError)
    // Python reported its own deadline failure before the parent kill fired.
    expect((error as Error).message).not.toMatch(/timed out after 5000ms/)
    expect(elapsed).toBeLessThan(5_000)
    expect(requests.length).toBeGreaterThanOrEqual(2)
  }, 30_000)
})

describe("E2: floor pre-check sees masked floor rules", () => {
  test("an unrequested non-floor rule cannot shadow a same-segment floor", async () => {
    const mock = await startReviewer(() => ({ content: "allow_once" }))
    const h = await startPlugin({
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    // Requesting only `host` used to leave filesystem.forced-recursive-delete
    // armed-off, and its non-floor rule hid filesystem.root-delete from the
    // pre-check — the reviewer was called for a command that can never run.
    const blocked = await runBefore(h, "s1", {
      command: escalation("host", "maintenance", "rm -rf /"),
    })
    expect(blocked).toMatch(/cannot be escalated/)
    expect(mock.requests).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
  })

  test("an earlier segment's bypassable denial cannot hide a later floor", async () => {
    const mock = await startReviewer(() => ({ content: "allow_once" }))
    const h = await startPlugin({
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    // With only `remote` requested, the first segment's system.* denial used
    // to be the whole decision; the floor in segment two was invisible.
    const blocked = await runBefore(h, "s1", {
      command: escalation("remote", "cleanup required", "systemctl stop nginx ; rm -rf /"),
    })
    expect(blocked).toMatch(/cannot be escalated/)
    expect(mock.requests).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
  })
})

describe("E3: denied escalations are remembered along the ancestor chain", () => {
  test("a child session cannot retry a parent's denied request verbatim", async () => {
    const mock = await startReviewer(() => ({ content: "deny" }))
    const h = await startPlugin(
      {
        dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
      },
      [{ type: "session.created", data: { sessionID: "child-1", parentID: "s1" } }],
    )
    // The event consumer is a forked fiber; give it a moment to link the
    // child to its parent before relying on the ancestor chain.
    await delay(250)
    const blocked = await runBefore(h, "s1", {
      command: escalation("host", "restart service", "systemctl stop nginx"),
    })
    expect(blocked).toContain("denied this one-time request")
    expect(mock.requests).toHaveLength(1)

    // Same request from the subagent session: refused from the parent's
    // recorded failure, no second reviewer call.
    const child = await runBefore(h, "child-1", {
      command: escalation("host", "restart service", "systemctl stop nginx"),
    })
    expect(child).toMatch(/[Ee]scalation denied|similar/)
    expect(mock.requests).toHaveLength(1)
  })

  test("the ancestor walk is bounded at 64 nodes", async () => {
    const mock = await startReviewer(() => ({ content: "deny" }))
    // s0 <- s1 <- ... <- s70. The denial is recorded on s0; s64's 64 ancestors
    // (s63..s0) still include it, while s65's walk stops at s1 — s0 is out.
    // A read-only command keeps deep sessions (unresolved ancestry strips w)
    // from tripping permission.write before the similar check runs.
    const events = Array.from({ length: 70 }, (_, i) => ({
      type: "session.created",
      data: { sessionID: `s${i + 1}`, parentID: `s${i}` },
    }))
    const h = await startPlugin(
      {
        dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
      },
      events,
    )
    await delay(400)
    const blocked = await runBefore(h, "s0", {
      command: escalation("host", "read the marker", "echo hi"),
    })
    expect(blocked).toContain("denied this one-time request")
    expect(mock.requests).toHaveLength(1)

    // s64: 64 ancestors include s0 — refused locally, still 1 HTTP call.
    const within = await runBefore(h, "s64", {
      command: escalation("host", "read the marker", "echo hi"),
    })
    expect(within).toMatch(/similar/)
    expect(mock.requests).toHaveLength(1)

    // s65: the walk stops at the 64-node bound before reaching s0 — the
    // request reaches the reviewer again.
    const beyond = await runBefore(h, "s65", {
      command: escalation("host", "read the marker", "echo hi"),
    })
    expect(beyond).toContain("denied this one-time request")
    expect(mock.requests).toHaveLength(2)
  })
})

describe("E4: the reviewer prompt carries category semantics", () => {
  test("the system prompt explains categories and marks layer categories", async () => {
    const mock = await startReviewer(() => ({ content: "deny" }))
    const h = await startPlugin({
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    await runBefore(h, "s1", {
      command: escalation("host", "restart service", "systemctl stop nginx"),
    })
    expect(mock.requests).toHaveLength(1)
    const messages = mock.requests[0].body.messages as Array<{ role?: string; content?: unknown }>
    const system = String(messages.find((m) => m.role === "system")?.content ?? "")
    expect(system).toContain("filesystem = local file changes")
    expect(system).toContain("privilege = crossing permission or isolation boundaries")
    expect(system).toContain("sandbox = remove the OS sandbox")
    // dynamic/slow are no longer grantable — the prompt must not offer them.
    expect(system).not.toContain("the dynamic reviewer, the OS sandbox, slow-command checks")
  })
})

describe("D2: cosmetic rewrites stay similar (failure memory cannot be replayed)", () => {
  test("comments, redirects, and trailing `; true` do not defeat similarity", () => {
    expect(escalationCommandsAreSimilar("systemctl stop nginx", "systemctl stop nginx # retry")).toBe(true)
    expect(escalationCommandsAreSimilar("rm -rf /srv/old", "rm -rf /srv/old >/tmp/log")).toBe(true)
    expect(escalationCommandsAreSimilar("systemctl stop nginx", "systemctl stop nginx ; true")).toBe(true)
    // Same-request normalization still applies.
    expect(escalationCommandsAreSimilar("sudo apt-get install curl", "apt install curl")).toBe(true)
  })

  test("a retry disguised with a comment is refused without a reviewer call", async () => {
    const mock = await startReviewer(() => ({ content: "deny" }))
    const h = await startPlugin({
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    const first = await runBefore(h, "s1", {
      command: escalation("host", "restart service", "systemctl stop nginx"),
    })
    expect(first).toContain("denied this one-time request")
    expect(mock.requests).toHaveLength(1)
    const second = await runBefore(h, "s1", {
      command: escalation("host", "different wording", "systemctl stop nginx # retry"),
    })
    expect(second).toMatch(/[Ee]scalation denied|similar/)
    expect(mock.requests).toHaveLength(1)
  })
})

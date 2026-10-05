import { afterAll, beforeEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_MARKER,
  JUSTIFICATION_HEADER_PREFIX,
  parseEscalation,
} from "../src/security/escalation"
import { BYPASS_CATEGORIES } from "../src/categories"
import { resetEscalationReviewLimiter } from "../src/security/escalation-reviewer"

// Regression coverage for the `escalationEnabled` toggle (round-3 F):
// when disabled, a `# - REQUIRE_ESCALATION` header is an inert shell comment —
// the command is classified normally, no reviewer is consulted, no failure is
// recorded, and no agent-facing block text ever mentions the mechanism.

let workdir: string | undefined
const scopes: Scope.Closeable[] = []
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "escalation-disabled-"))
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

type Harness = {
  executeBefore: HookCb
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

async function startReviewer(): Promise<{ endpoint: string; requests: CapturedRequest[] }> {
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
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content: "allow_once" } }] }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  servers.push(server)
  const port = (server.address() as AddressInfo).port
  return { endpoint: `http://127.0.0.1:${port}/v1`, requests }
}

async function startPlugin(options: Record<string, unknown>): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  let contextCalls = 0

  const ctx = {
    options: {
      failPolicy: "fail_close",
      logReviewerTrace: false,
      sandbox: { enabled: false },
      // The dynamic (auditor) reviewer is stubbed in-process so the HTTP mock
      // only ever sees dedicated escalation-reviewer traffic.
      reviewCommand: async () => ({ decision: "ALLOW" as const, categories: [] }),
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
    command: { transform: () => Effect.void },
    permission: { hook: () => Effect.void },
    session: {
      // Context hook registrar stub: attachSessionContextHook
      // registers here; state notices are a no-op for these tests.
      hook: () => Effect.void,
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      context: () =>
        Effect.sync(() => {
          contextCalls += 1
          return [{ type: "user", text: "do the thing" }]
        }),
      synthetic: () => Effect.void,
    },
    rpc: { register: () => Effect.succeed({ events: { emit: () => Effect.void } }) },
    event: { subscribe: () => Stream.fromIterable([]) },
  }

  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )
  return { executeBefore: collected["execute.before"]!, contextCalls: () => contextCalls }
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

describe("escalationEnabled: false removes the escalation channel entirely", () => {
  test("a valid header is treated as a normal command — classified, never reviewed", async () => {
    const mock = await startReviewer()
    const h = await startPlugin({
      escalationEnabled: false,
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    // The header is a leading comment; `rm -rf /` underneath hits the
    // unconditional floor like any plain submission.
    const blocked = await runBefore(h, "s1", {
      command: escalation("filesystem", "maintenance", "rm -rf /"),
    })
    expect(blocked).toBeDefined()
    expect(mock.requests).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
    // Zero agent-facing mention of the mechanism.
    expect(blocked!.toLowerCase()).not.toContain("escalat")
    expect(blocked).not.toContain(ESCALATION_MARKER)
  })

  test("a blocked command gets terminal-style /bypass guidance with no escalation pointer", async () => {
    const mock = await startReviewer()
    const h = await startPlugin({
      escalationEnabled: false,
      failPolicy: "fail_close",
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
      // The dynamic reviewer denies, exercising the fail-closed policy block.
      reviewCommand: async () => ({ decision: "DENY" as const, categories: ["secret"] }),
    })
    // A statically denied command: the block must not mention escalation.
    const denied = await runBefore(h, "s1", { command: "rm -rf /" })
    expect(denied).toBeDefined()
    expect(denied).toContain("session surface")
    expect(denied!.toLowerCase()).not.toContain("escalat")
    expect(denied).not.toContain("resubmit the command once")
    // A dynamically denied command: same guarantee — the policy block points
    // at /bypass, never at the escalation channel.
    const blocked = await runBefore(h, "s1", { command: "cat /etc/shadow" })
    expect(blocked).toBeDefined()
    expect(blocked!.toLowerCase()).not.toContain("escalat")
    expect(blocked).toContain("session surface")
    expect(mock.requests).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
  })

  test("a malformed header is also inert — no 'malformed escalation' rejection", async () => {
    const mock = await startReviewer()
    const h = await startPlugin({
      escalationEnabled: false,
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    const blocked = await runBefore(h, "s1", {
      command: [ESCALATION_MARKER, "# - JUSTIFICATION: x", "echo hi"].join("\n"),
    })
    // Plain comments + `echo hi` classify fine; nothing is blocked and no
    // reviewer traffic or context reads happen.
    expect(blocked).toBeUndefined()
    expect(mock.requests).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
  })

  test("enabled (default) keeps the existing escalation flow and wording", async () => {
    const mock = await startReviewer()
    const h = await startPlugin({
      dynamicReview: { baseURL: mock.endpoint, model: "m", apiKey: "k", timeoutMs: 5000, maxRounds: 1 },
    })
    const blocked = await runBefore(h, "s1", { command: "rm -rf /" })
    expect(blocked).toBeDefined()
    expect(blocked!.toLowerCase()).toContain("escalat")
    // And a real header still reaches the reviewer exactly once, granting
    // `secret` for this call so the statically-blocked read proceeds.
    const allowed = await runBefore(h, "s1", {
      command: escalation("secret", "need to inspect the file", "cat /etc/shadow"),
    })
    expect(allowed).toBeUndefined()
    expect(mock.requests).toHaveLength(1)
    expect(h.contextCalls()).toBe(1)
  })
})

describe("escalation categories: dynamic and slow are never grantable (F1)", () => {
  // The same grantable list the plugin passes to parseEscalation.
  const grantable = BYPASS_CATEGORIES.filter((c) => c !== "dynamic" && c !== "slow")

  test("requests for dynamic or slow are rejected at parse time", () => {
    for (const categories of ["dynamic", "slow", "host,dynamic", "sandbox,slow"]) {
      const text = escalation(categories, "need it", "echo hi")
      const parsed = parseEscalation(text, grantable)
      expect(parsed.status).toBe("malformed")
      if (parsed.status === "malformed") expect(parsed.code).toBe("unknown-category")
    }
  })

  test("the rejection names the accurate grantable category list", () => {
    const parsed = parseEscalation(escalation("dynamic", "x", "echo hi"), grantable)
    expect(parsed.status).toBe("malformed")
    if (parsed.status !== "malformed") return
    for (const category of grantable) expect(parsed.reason).toContain(category)
    expect(parsed.reason).not.toMatch(/\bdynamic\b[^ ]* categories/)
    expect(parsed.reason).not.toContain("slow")
  })

  test("sandbox stays grantable; user-side /bypass categories are unaffected", () => {
    const ok = parseEscalation(escalation("sandbox", "need host-direct", "echo hi"), grantable)
    expect(ok.status).toBe("valid")
    // The user-facing category universe still includes dynamic and slow.
    expect(BYPASS_CATEGORIES).toContain("dynamic")
    expect(BYPASS_CATEGORIES).toContain("slow")
  })
})

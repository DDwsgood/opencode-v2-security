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
} from "../src/security/escalation"
import { resetEscalationReviewLimiter } from "../src/security/escalation-reviewer"

// Automatic assessment report + admission integration tests.
//
// Contract under test (post-research host shape):
//   * the FIRST risk classification produces a complete minimal category set
//     in a cached assessment report;
//   * a raw allow_once escalation is the admission for that call — the
//     ordinary dynamic reviewer never re-judges it and never adds categories;
//   * unconditional native floor (static DENY) still refuses even with a
//     reviewer in play;
//   * the permission ceiling (readonly) is independent of any grant;
//   * ask_user/collect_evidence never reach a human — bounded evidence,
//     one resubmit, then a named-limitation denial;
//   * no agent-facing text asks a human to authorize anything;
//   * bypass/perm state is published through the no-wake context hook —
//     ctx.session.synthetic is never used for state notices.
//
// All reviewer traffic is mocked (injected dynamic review + a loopback
// escalation HTTP endpoint); no fixture command is executed.

let workdir: string | undefined
const scopes: Scope.Closeable[] = []
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "auto-assess-"))
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

type CapturedRequest = { body: Record<string, unknown>; authorization: string | undefined }
type Responder = (body: Record<string, unknown>) => { status?: number; content?: string }

async function startReviewer(responder: Responder) {
  const requests: CapturedRequest[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on("data", (chunk: Buffer) => chunks.push(chunk))
    req.on("end", () => {
      let body: Record<string, unknown> = {}
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>
      } catch { /* assertion side reports */ }
      requests.push({ body, authorization: req.headers.authorization })
      const answer = responder(body)
      const status = answer.status ?? 200
      const payload =
        status === 200
          ? JSON.stringify({ choices: [{ message: { role: "assistant", content: answer.content ?? "deny" } }] })
          : JSON.stringify({ error: "mock reviewer error" })
      res.writeHead(status, { "Content-Type": "application/json" })
      res.end(payload)
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  servers.push(server)
  const port = (server.address() as AddressInfo).port
  return { endpoint: `http://127.0.0.1:${port}/v1`, requests }
}

type DynamicReviewResult = {
  decision: "ALLOW" | "DENY" | string
  categories: string[]
  secondary_categories?: string[]
  bypassing?: boolean
}
type DynamicCall = { command: string; userBypass?: string[] }
type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>

type Harness = {
  executeBefore: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string; description?: string }>
  dynamicCalls: DynamicCall[]
  notice: (sessionID: string) => Promise<string>
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

const escalation = (categories: string, justification: string, command: string) =>
  [ESCALATION_MARKER, `${CATEGORY_HEADER_PREFIX} ${categories}`, `${JUSTIFICATION_HEADER_PREFIX} ${justification}`, command].join("\n")

async function startPlugin(
  options: Record<string, unknown>,
  mock: { endpoint: string; requests: CapturedRequest[] },
  review: (request: { command?: string; userBypass?: string[] }) => DynamicReviewResult,
): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  const dynamicCalls: DynamicCall[] = []
  let contextCb:
    | ((ev: { sessionID: string; system: Array<{ type: string; text: string }> }) => Effect.Effect<void>)
    | undefined

  let h!: Harness
  const reviewCommand = async (request: { command?: string; userBypass?: string[] }) => {
    h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
    return review(request)
  }

  const ctx = {
    options: {
      failPolicy: "fail_close",
      logReviewerTrace: false,
      sandbox: { enabled: false },
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "auto-assess-model",
        apiKey: "auto-assess-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand,
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
    permission: {
      hook: () => Effect.void,
    },
    session: {
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      context: () => Effect.succeed([{ type: "user", text: "run the task's build" }]),
      synthetic: (input: { sessionID: string; text: string; description?: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
      hook: (name: string, cb: (ev: { sessionID: string; system: Array<{ type: string; text: string }> }) => Effect.Effect<void>) => {
        if (name === "context") contextCb = cb
        return Effect.void
      },
    },
    rpc: {
      register: () =>
        Effect.succeed({
          events: { emit: () => Effect.void },
        }),
    },
    event: { subscribe: () => Stream.fromIterable([]) },
  }

  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )

  h = {
    executeBefore: collected["execute.before"]!,
    commands,
    synthetic,
    dynamicCalls,
    notice: async (sessionID: string) => {
      const event = { sessionID, system: [{ type: "text", text: "base" }] }
      if (contextCb) await Effect.runPromise(contextCb(event as never))
      return event.system.map((p) => p.text).join("\n")
    },
  }
  return h
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

const invoke = (h: Harness, name: string, sessionID: string, text = "") =>
  failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))

const decision = (word: "allow_once" | "deny" | "collect_evidence"): Responder => () => ({ content: word })

// ---------------------------------------------------------------------------

describe("assessment report admission", () => {
  test("first deny reports the complete minimal category set; allow_once admits with no second review", async () => {
    // Dynamic reviewer: first verdict denies the compound command with its
    // complete primary set (filesystem+secret), secondary hint excluded.
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return {
        decision: "DENY",
        categories: ["filesystem", "secret"],
        secondary_categories: ["network"],
      }
    })

    // 1. First classification: dynamic DENY names the complete minimal set —
    //    secondary hints never reach the escalation-facing category list.
    const cmd = "cat secrets.txt && cp secrets.txt /tmp/out.txt"
    const denied = await runBefore(h, "s1", { command: cmd })
    expect(denied).toContain("Blocked by dynamic classifier")
    expect(denied).toContain("filesystem")
    expect(denied).toContain("secret")
    // Secondary families are diagnostics, not billed risk.
    expect(denied).not.toContain("Risk categories: filesystem, network, secret")
    expect(calls).toBe(1)

    // 2. Identical denied command replays the cached report — no second review.
    const again = await runBefore(h, "s1", { command: cmd })
    expect(again).toContain("Blocked by dynamic classifier")
    expect(calls).toBe(1)

    // 3. allow_once under the full report's categories admits the call; the
    //    ordinary dynamic reviewer is not consulted again.
    const escalated = {
      command: escalation("filesystem,secret", "read the file the task needs", cmd),
    }
    expect(await runBefore(h, "s1", escalated)).toBeUndefined()
    expect(escalated.command).toBe(cmd)
    expect(mock.requests).toHaveLength(1)
    expect(calls).toBe(1) // still one dynamic review — no re-attribution
  })

  test("unconditional floor refuses before any reviewer is consulted", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))

    // Force-recursive root delete is a native floor rule — no grant can lift
    // it, and neither reviewer is even asked.
    const blocked = await runBefore(h, "s1", {
      command: escalation("filesystem", "clean the disk", "rm -rf /"),
    })
    expect(blocked).toBeDefined()
    expect(blocked).toContain("cannot be escalated")
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)
    // Terminal floor text never routes through a human.
    expect(blocked).not.toContain("ask the user")
  })

  test("readonly permission ceiling denies before escalation review", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))
    await invoke(h, "perm", "s1", "ro")

    // A write-shaped command in a read-only session dies at the ceiling; the
    // escalation reviewer is never called and no human-confirmation text is
    // emitted.
    const blocked = await runBefore(h, "s1", {
      command: escalation("filesystem", "write the config", "echo x > /etc/app.conf"),
    })
    expect(blocked).toBeDefined()
    expect(mock.requests).toHaveLength(0)
  })

  test("collect_evidence auto-collects, resubmits once, and denies with a named limitation", async () => {
    // First verdict asks for evidence; the resubmitted verdict still cannot
    // decide — the denial names the limitation, no human is involved.
    let round = 0
    const mock = await startReviewer(() => ({ content: round++ === 0 ? "collect_evidence" : "collect_evidence" }))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))

    const blocked = await runBefore(h, "s1", {
      command: escalation("host", "restart the service", "systemctl restart appd"),
    })
    expect(blocked).toBeDefined()
    expect(blocked).toContain("could not be authorized automatically")
    // Nothing collectable: the limitation names what was missing.
    expect(blocked).toContain("nothing further to collect")
    // One review call only — the empty collection denies before resubmitting.
    expect(mock.requests).toHaveLength(1)
    expect(blocked).not.toContain("ask the user")
  })

  test("no bypass/perm notice ever lands in the synthetic inbox", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))

    await invoke(h, "bypass", "s1", "filesystem")
    await invoke(h, "perm", "s1", "ro")
    await invoke(h, "perm", "s1", "rwx")

    // State is published through the context hook, not inbox admissions.
    const armed = await h.notice("s1")
    expect(armed).toContain("opencode-v2-security:")
    for (const s of h.synthetic) {
      expect(s.text).not.toContain("temporarily allowed")
      expect(s.text).not.toContain("permission ceiling changed")
    }
  })

  test("a protocol-error verdict fails closed without faking a model denial", async () => {
    const mock = await startReviewer(decision("allow_once"))
    // Malformed dynamic verdict: unknown decision word → protocol fail-close,
    // not a fabricated deny with categories.
    const h = await startPlugin({}, mock, () => ({
      decision: "MAYBE_LATER",
      categories: ["host"],
    }))

    const blocked = await runBefore(h, "s1", { command: "cat secrets.txt && rm /tmp/x" })
    expect(blocked).toBeDefined()
    expect(blocked).toContain("Blocked by policy classifier")
    // The invalid verdict is reported as a review failure, not a policy deny.
    expect(blocked).not.toContain("Risk categories: host")
  })
})

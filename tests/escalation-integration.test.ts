import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { BYPASS_CATEGORIES } from "../src/categories"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_MARKER,
  JUSTIFICATION_HEADER_PREFIX,
} from "../src/security/escalation"
import { resetEscalationReviewLimiter } from "../src/security/escalation-reviewer"

// --- fixtures ----------------------------------------------------------------
// The test session's workspace: a real directory so ctx.session.get can report
// it as the session's location. Kept under /tmp/opencode (the sandbox scratch
// hierarchy) so fixture commands must not target it when asserting denials —
// scratch writes are deliberately exempt from the RO write gate.
let workdir: string | undefined
const scopes: Scope.Closeable[] = []
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "escalation-int-"))
  return workdir
}

beforeEach(() => {
  // The escalation reviewer has a process-wide rolling limiter (2 starts per
  // 3s). Reset between tests so cross-test plumbing never slows the suite.
  resetEscalationReviewLimiter()
})

afterAll(async () => {
  for (const scope of scopes) {
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

// --- local OpenAI-compatible escalation reviewer mock -------------------------
// The escalation reviewer is a direct Python child posting ONE
// chat-completions request per escalation attempt to `dynamicReview.baseURL`.
// A responder decides the verdict; every request body is captured so tests can
// assert on what the reviewer was shown. Bound to 127.0.0.1 on an ephemeral
// port; no real network is involved.

type CapturedRequest = {
  body: Record<string, unknown>
  authorization: string | undefined
}

type MockReviewer = {
  endpoint: string
  requests: CapturedRequest[]
  close: () => Promise<void>
}

type Responder = (body: Record<string, unknown>) => { status?: number; content?: string }

async function startReviewer(responder: Responder): Promise<MockReviewer> {
  const requests: CapturedRequest[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on("data", (chunk: Buffer) => chunks.push(chunk))
    req.on("end", () => {
      let body: Record<string, unknown> = {}
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>
      } catch {
        // leave body empty; the assertion side reports the raw failure
      }
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
  return {
    endpoint: `http://127.0.0.1:${port}/v1`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

const decision = (word: "allow_once" | "ask_user" | "deny"): Responder => () => ({ content: word })

// --- minimal host-context harness --------------------------------------------
// Same approach as tests/bypass-rework.test.ts but standalone: only the ctx
// slices the plugin calls are faked.
//
// On the real V2 effect plugin, `ctx.session.context({ sessionID })` resolves
// directly to a `SessionMessage.Info[]`. The HTTP `{ data }` envelope is already
// unwrapped by the effect client before the host hands the value to the plugin
// (see packages/plugin/src/effect/session.ts, packages/core/src/plugin/host.ts,
// and the generated EndpointSessionContext). The default harness therefore
// returns the array directly, so the core payload/context test exercises the
// production branch. `{ data }` remains available only as an explicitly
// selected legacy-compatibility case.
//
// Messages use the durable transcript shape (user.text, assistant.content[].type)
// so escalationContextFromMessages can extract prose.

type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>
type DynamicReviewResult = {
  decision: "ALLOW" | "DENY"
  categories: string[]
  secondary_categories?: string[]
  bypassing?: boolean
}
type DynamicCall = { command: string; userBypass?: string[] }
type ContextShape = "array" | "envelope"

type Harness = {
  executeBefore: HookCb
  executeAfter: HookCb
  createBefore: HookCb
  evalHook: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string; description?: string }>
  rpcEvents: Array<{ name: string; data: unknown }>
  dynamicCalls: DynamicCall[]
  contextCalls: () => number
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

const CURRENT_USER_INPUT = "Please just install the missing dependency"
const RECENT_USER_TEXT = "Deploy the staging build to the test server"
const RECENT_ASSISTANT_TEXT = "The deploy script needs elevated privileges."

const SESSION_MESSAGES = [
  { type: "user", text: RECENT_USER_TEXT },
  {
    type: "assistant",
    content: [
      { type: "reasoning", text: "hidden chain-of-thought" },
      { type: "text", text: RECENT_ASSISTANT_TEXT },
      { type: "tool", state: { status: "completed", content: "leaked tool output" } },
    ],
  },
  { type: "user", text: CURRENT_USER_INPUT },
]

function startPlugin(
  options: Record<string, unknown>,
  mock: MockReviewer,
  messages: readonly unknown[] = SESSION_MESSAGES,
  contextShape: ContextShape = "array",
): Promise<Harness> {
  return startPluginRaw({
    // Every option below overrides the package-root config.json field of the
    // same name; unspecified fields (strictness LOOSE etc.) stay as configured.
    failPolicy: "fail_close",
    logReviewerTrace: false,
    sandbox: { enabled: false },
    dynamicReview: {
      baseURL: mock.endpoint,
      model: "escalation-test-model",
      apiKey: "escalation-test-key",
      timeoutMs: 15000,
      maxRounds: 1,
    },
    ...options,
  }, messages, contextShape)
}

type DynamicReviewResponder = (request: { command?: string; userBypass?: string[] }) => DynamicReviewResult

async function startPluginWithReview(
  options: Record<string, unknown>,
  mock: MockReviewer,
  contextShape: ContextShape = "array",
  review: DynamicReviewResponder = () => ({ decision: "ALLOW", categories: [] }),
): Promise<Harness> {
  // Inject the normal-pipeline dynamic reviewer so an allow_once's second
  // pass is captured deterministically — and so auditor HTTP calls can never
  // pollute the escalation request count. The escalation reviewer itself is a
  // direct Python child configured via dynamicReview and still hits the mock.
  let h!: Harness
  const reviewCommand = async (request: { command?: string; userBypass?: string[] }) => {
    h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
    return review(request)
  }
  h = await startPlugin({ reviewCommand, ...options }, mock, SESSION_MESSAGES, contextShape)
  return h
}

async function startPluginRaw(
  options: Record<string, unknown>,
  messages: readonly unknown[],
  contextShape: ContextShape = "array",
): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const evalHooks: HookCb[] = []
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  const rpcEvents: Harness["rpcEvents"] = []
  const dynamicCalls: DynamicCall[] = []
  let contextCalls = 0

  const ctx = {
    options,
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
      hook: (name: string, cb: HookCb) => {
        evalHooks.push(cb)
        return Effect.void
      },
    },
    session: {
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      // Production returns a direct SessionMessage.Info[]; the envelope shape is
      // only produced when a test explicitly opts into the legacy fallback.
      context: () =>
        Effect.sync(() => {
          contextCalls += 1
          return contextShape === "envelope" ? { data: messages } : messages
        }),
      synthetic: (input: { sessionID: string; text: string; description?: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
      // Context hook registrar (session-notifications channel): captured so
      // the plugin's attach returns true and no fallback warning fires.
      hook: () => Effect.void,
    },
    rpc: {
      register: () =>
        Effect.succeed({
          events: {
            emit: (name: string, data: unknown) =>
              Effect.sync(() => {
                rpcEvents.push({ name, data })
              }),
          },
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

  return {
    executeBefore: collected["execute.before"]!,
    executeAfter: collected["execute.after"]!,
    createBefore: collected["shell.create.before"]!,
    evalHook: evalHooks[0]!,
    commands,
    synthetic,
    rpcEvents,
    dynamicCalls,
    contextCalls: () => contextCalls,
  }
}

/** execute.before driver; returns the block message, or undefined on allow. */
const runBefore = (h: Harness, tool: string, sessionID: string, input: Record<string, unknown>) =>
  failureMessage(
    h.executeBefore({
      tool,
      sessionID,
      agent: "test",
      messageID: "m1",
      id: `call-${Math.random()}`,
      input,
    } as never),
  )

/** /perm or /bypass invocation; returns the error message on failure. */
const invoke = (h: Harness, name: string, sessionID: string, text = "") =>
  failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))

const escalation = (categories: string, justification: string, command: string) =>
  [ESCALATION_MARKER, `${CATEGORY_HEADER_PREFIX} ${categories}`, `${JUSTIFICATION_HEADER_PREFIX} ${justification}`, command].join("\n")

/** Pull the first user-message text out of a captured chat-completions body. */
function userPromptOf(body: Record<string, unknown>): string {
  const messages = body.messages as Array<{ role?: string; content?: unknown }> | undefined
  const user = (messages ?? []).find((m) => m.role === "user")
  return typeof user?.content === "string" ? user.content : ""
}

function systemPromptOf(body: Record<string, unknown>): string {
  const messages = body.messages as Array<{ role?: string; content?: unknown }> | undefined
  const system = (messages ?? []).find((m) => m.role === "system")
  return typeof system?.content === "string" ? system.content : ""
}

/** Mirror of the reviewer's `_data` framing so tests can assert the exact
 * currentUserInput/recentContext values that reached the payload. */
const untrusted = (text: string) => `<data>\n[untrusted data]\n${text}\n</data>`

// --- tests -------------------------------------------------------------------

describe("escalation allow_once", () => {
  test("strips the three header lines and runs the real command through the normal pipeline", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    const input = { command: escalation("secret", "read the file requested for the audit", "cat /etc/shadow") }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()

    // The real command — not the header — is what remains for the tool call.
    expect(input.command).toBe("cat /etc/shadow")
    expect(input.command).not.toContain(ESCALATION_MARKER)

    // The escalation reviewer was consulted exactly once.
    expect(mock.requests).toHaveLength(1)

    // allow_once IS this call's assessment report and admission: the
    // ordinary dynamic reviewer does NOT re-judge the granted command (no
    // second attribution, no fresh categories). The unconditional layers
    // (floor, permission ceiling, routing) still ran.
    expect(h.dynamicCalls).toHaveLength(0)
  })

  test("an allow_once does not form a lease: later commands need their own review", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    const first = { command: escalation("secret", "read credential file", "cat /etc/shadow") }
    expect(await runBefore(h, "shell", "s1", first)).toBeUndefined()
    expect(mock.requests).toHaveLength(1)

    // Same session, same command, no header: the category grant was per-call,
    // so the normal pipeline treats it as unbypassed (static ASK -> dynamic
    // review, no userBypass).
    const second = { command: "cat /etc/shadow" }
    expect(await runBefore(h, "shell", "s1", second)).toBeUndefined()
    expect(mock.requests).toHaveLength(1) // no second escalation review
    expect(h.dynamicCalls).toHaveLength(1)
    expect(h.dynamicCalls[0].userBypass ?? []).not.toContain("secret")
    expect(second.command).toBe("cat /etc/shadow")

    // No bypass reminder was emitted to the agent or the user channel.
    expect(h.synthetic.some((s) => s.text.includes("temporarily allowed"))).toBe(false)
    expect(h.rpcEvents.some((e) => e.name === "changed")).toBe(false)
  })

  test("reviewer sees currentUserInput, recent context, permScope and canonical categories (direct array context)", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    const input = { command: escalation("secret,filesystem", "needed for the requested audit", "cat /etc/shadow") }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    // The plugin read the session context exactly once, from the production
    // direct-array branch (`Array.isArray(payload)`), never the { data } fallback.
    expect(h.contextCalls()).toBe(1)
    expect(mock.requests).toHaveLength(1)

    const body = mock.requests[0].body
    expect(body.model).toBe("escalation-test-model")
    expect(mock.requests[0].authorization).toBe("Bearer escalation-test-key")
    // One system + one user message; no response_format (single-word protocol).
    const messages = body.messages as Array<{ role?: string }>
    expect(messages.map((m) => m.role)).toEqual(["system", "user"])
    expect(body.response_format).toBeUndefined()

    const system = systemPromptOf(body)
    expect(system).toContain("allow_once")
    expect(system).toContain("ask_user")
    expect(system).toContain("deny")

    const user = userPromptOf(body)
    // currentUserInput is exactly the last durable user message.
    expect(user).toContain(`Explicit current user input:\n\n${untrusted(CURRENT_USER_INPUT)}`)
    // recentContext carries each earlier human/model prose message, in order,
    // with the exact text that escalationContextFromMessages extracted.
    expect(user).toContain(`role=user text=${untrusted(RECENT_USER_TEXT)}`)
    expect(user).toContain(`role=assistant text=${untrusted(RECENT_ASSISTANT_TEXT)}`)
    expect(user).toContain(`role=user text=${untrusted(CURRENT_USER_INPUT)}`)
    // Reasoning and tool parts never become reviewer context.
    expect(user).not.toContain("hidden chain-of-thought")
    expect(user).not.toContain("leaked tool output")
    // The reviewed command, justification and categories are canonical.
    expect(user).toContain("cat /etc/shadow")
    expect(user).toContain("needed for the requested audit")
    expect(user).toContain('"secret"')
    expect(user).toContain('"filesystem"')
    expect(user).toContain("Execution cwd:")
    expect(user).toContain("Execution worktree:")
    expect(user).toContain(await ensureWorkdir())
    // Permission scope booleans are passed through verbatim (default = rwx).
    expect(user).toMatch(/"r"\s*:\s*true/)
    expect(user).toMatch(/"w"\s*:\s*true/)
    expect(user).toMatch(/"x"\s*:\s*true/)
  })

  test("five user turns survive intervening assistant messages in the wire request", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const messages: unknown[] = [{ type: "user", text: "obsolete task" }]
    for (let index = 0; index < 5; index++) {
      messages.push({ type: "user", text: `user task ${index}` })
      for (let reply = 0; reply < 4; reply++) {
        messages.push({ type: "assistant", content: [{ type: "text", text: `step ${index}.${reply}` }] })
      }
    }
    const h = await startPlugin({
      reviewCommand: async () => ({ decision: "ALLOW", categories: [] }),
    }, mock, messages)
    const input = { command: escalation("secret", "inspect requested account metadata", "cat /etc/shadow") }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    const user = userPromptOf(mock.requests[0].body)
    for (let index = 0; index < 5; index++) expect(user).toContain(untrusted(`user task ${index}`))
    expect(user).not.toContain("obsolete task")
    expect(user).toContain(untrusted("step 4.3"))
  })

  test("a denied ask_user escalates nothing: the command never reaches the pipeline", async () => {
    const mock = await startReviewer(decision("ask_user"))
    const h = await startPluginWithReview({}, mock)

    const input = { command: escalation("host", "restart service for the user", "kill 4242") }
    const blocked = await runBefore(h, "shell", "s1", input)
    // ask_user resolves automatically: one bounded evidence pass finds
    // nothing to add, so the denial names the evidence limitation — the
    // plugin never waits on a human.
    expect(blocked).toContain("could not be authorized automatically")
    expect(blocked).toContain("nothing further to collect")
    // The agent-facing refusal must not leak the internal decision enum.
    expect(blocked).not.toContain('"ask_user"')
    // The command must not run; the header was stripped but nothing executed.
    expect(input.command).toBe("kill 4242")
    expect(h.dynamicCalls).toHaveLength(0)
    expect(mock.requests).toHaveLength(1)
  })
})

describe("legacy session-context envelope compatibility", () => {
  test("a raw { data } envelope is still unwrapped for older hosts", async () => {
    // Older hosts handed the plugin the raw HTTP envelope. The plugin keeps a
    // narrow fallback for that shape; this test covers only the fallback, so the
    // core allow_once assertions stay on the production direct-array branch.
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock, "envelope")

    const input = { command: escalation("secret", "read the file requested for the audit", "cat /etc/shadow") }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    expect(h.contextCalls()).toBe(1)
    expect(mock.requests).toHaveLength(1)

    const user = userPromptOf(mock.requests[0].body)
    expect(user).toContain(`Explicit current user input:\n\n${untrusted(CURRENT_USER_INPUT)}`)
    expect(user).toContain(`role=assistant text=${untrusted(RECENT_ASSISTANT_TEXT)}`)
    expect(user).not.toContain("leaked tool output")
  })
})

describe("unconditional static floor still applies after allow_once", () => {
  test("rm -rf / is denied even with an approved filesystem escalation", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    const input = {
      command: escalation("filesystem,host", "maintenance", "rm -rf /"),
    }
    const blocked = await runBefore(h, "shell", "s1", input)
    expect(blocked).toMatch(/cannot be escalated/)
    // The floor pre-check refuses terminally: the reviewer is never consulted.
    expect(mock.requests).toHaveLength(0)
    // No dynamic review, no execution.
    expect(h.dynamicCalls).toHaveLength(0)
  })
})

describe("permission ceiling beats allow_once", () => {
  test("RO session: a write command stays denied after allow_once on filesystem+host", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({ permission: { default: "ro" } }, mock)

    // Outside the /tmp scratch carve-out so the RO write gate is what fires.
    const target = "/var/tmp/escalation-ro-target"
    const input = {
      command: escalation("filesystem,host", "clean stale probe directory", `rm -rf ${target}`),
    }
    const blocked = await runBefore(h, "shell", "s1", input)
    expect(blocked).toMatch(/cannot be escalated/)
    // The permission.write denial is unconditional: the pre-check refuses
    // terminally, so the reviewer is never consulted.
    expect(h.dynamicCalls).toHaveLength(0)
    expect(mock.requests).toHaveLength(0)
  })

  test("RW session: the same command is allowed once the required category is approved", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock) // default perm rwx

    const input = {
      command: escalation("filesystem", "clean stale probe directory", "rm -rf /var/tmp/escalation-rw-target"),
    }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    expect(input.command).toBe("rm -rf /var/tmp/escalation-rw-target")
    expect(mock.requests).toHaveLength(1)
    // allow_once is the admission report — no ordinary dynamic re-review.
    expect(h.dynamicCalls).toHaveLength(0)
  })
})

describe("sandbox category escalation rewrites the spawn per call", () => {
  test("allow_once with sandbox inserts a full marker that create.before strips", async () => {
    const mock = await startReviewer(decision("allow_once"))
    // rw + allowSudo = the host-direct route: markers are inserted even with no
    // usable kernel probe, so the marker lifecycle is observable without bwrap.
    const h = await startPluginWithReview({ sandbox: { enabled: true, mode: "rw", allowSudo: true } }, mock)
    const dir = await ensureWorkdir()

    const escalated = {
      command: escalation("host,sandbox", "restart the test service", "systemctl restart nginx"),
    }
    expect(await runBefore(h, "shell", "s1", escalated)).toBeUndefined()
    // Per-call "full" profile: the nonce marker rides input.command.
    expect(String(escalated.command)).toMatch(/^: opencode-sandbox [0-9a-f]{32}\n/)
    const createEv = {
      command: String(escalated.command),
      cwd: dir,
      shell: "/bin/bash",
      timeout: 60000,
      env: {} as Record<string, string | undefined>,
    }
    await Effect.runPromise(h.createBefore(createEv as never))
    // create.before strips the marker and leaves the spawn untouched.
    expect(createEv.command).toBe("systemctl restart nginx")
    expect(createEv.shell).toBe("/bin/bash")
    expect(createEv.env.OPENCODE_REAL_BASH).toBeUndefined()

    // Without the sandbox category the same allow_once keeps the rw wrap.
    const wrapped = {
      command: escalation("host", "restart the test service again", "systemctl restart nginx"),
    }
    expect(await runBefore(h, "shell", "s1", wrapped)).toBeUndefined()
    expect(String(wrapped.command)).toMatch(/^: opencode-sandbox [0-9a-f]{32}\n/)
    const createEv2 = {
      command: String(wrapped.command),
      cwd: dir,
      shell: "/bin/bash",
      timeout: 60000,
      env: {} as Record<string, string | undefined>,
    }
    await Effect.runPromise(h.createBefore(createEv2 as never))
    expect(createEv2.command).toBe("systemctl restart nginx")
    expect(createEv2.shell).not.toBe("/bin/bash") // wrapped by the helper
    expect(createEv2.env.OPENCODE_REAL_BASH).toBe("/bin/bash")
  })
})

describe("deny / ask_user records", () => {
  test("a deny is recorded; a semantically similar retry is refused without another HTTP call", async () => {
    const mock = await startReviewer(decision("deny"))
    const h = await startPluginWithReview({}, mock)

    const first = {
      command: escalation("host", "install the missing dependency", "sudo apt-get install curl"),
    }
    const blocked = await runBefore(h, "shell", "s1", first)
    expect(blocked).toContain("The escalation reviewer denied this one-time request")
    expect(blocked).not.toContain('"deny"')
    // Terminal ending: authorization can only come from the session surface;
    // the message must not suggest another escalation request.
    expect(blocked).toContain("armed bypass for categories host")
    expect(blocked).not.toContain("ask for escalation")
    expect(mock.requests).toHaveLength(1)
    expect(h.dynamicCalls).toHaveLength(0)

    // Same session, equivalent spelling via wrapper/alias removal
    // (sudo stripped, apt-get -> apt): denied locally, no second review.
    const second = {
      command: escalation("host", "trying again", "apt install curl"),
    }
    const blockedAgain = await runBefore(h, "shell", "s1", second)
    expect(blockedAgain).toMatch(/[Ee]scalation denied/)
    expect(blockedAgain).not.toContain("ask for escalation")
    expect(mock.requests).toHaveLength(1)
    expect(h.dynamicCalls).toHaveLength(0)
  })

  test("a similar retry after ask_user is also refused without another HTTP call", async () => {
    const mock = await startReviewer(decision("ask_user"))
    const h = await startPluginWithReview({}, mock)

    const first = {
      command: escalation("host", "restart nginx per request", "systemctl restart nginx"),
    }
    expect(await runBefore(h, "shell", "s1", first)).toContain("could not be authorized automatically")
    expect(mock.requests).toHaveLength(1)

    const second = {
      command: escalation("host", "different justification", "systemctl reload nginx"),
    }
    expect(await runBefore(h, "shell", "s1", second)).toMatch(/[Ee]scalation denied/)
    expect(mock.requests).toHaveLength(1)
  })

  test("a different session can escalate a similar command (failures are session-scoped)", async () => {
    const mock = await startReviewer(decision("deny"))
    const h = await startPluginWithReview({}, mock)

    const first = {
      command: escalation("host", "install dependency", "sudo apt-get install curl"),
    }
    expect(await runBefore(h, "shell", "s1", first)).toContain("denied this one-time request")
    expect(mock.requests).toHaveLength(1)

    // s2 has no recorded failure: the reviewer IS consulted again.
    const second = {
      command: escalation("host", "install dependency", "apt install curl"),
    }
    expect(await runBefore(h, "shell", "s2", second)).toContain("denied this one-time request")
    expect(mock.requests).toHaveLength(2)
  })
})

describe("malformed and forbidden headers never reach the reviewer", () => {
  test("forbidden wildcard categories are rejected with no HTTP call", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    for (const categories of ["all", "ALL", "*", "filesystem,all"]) {
      const input = { command: escalation(categories, "please", "cat /etc/shadow") }
      const blocked = await runBefore(h, "shell", "s1", input)
      expect(blocked).toMatch(/[Mm]alformed|[Bb]locked/)
      expect(input.command).toContain(ESCALATION_MARKER) // nothing was stripped
    }
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
  })

  test("a structurally malformed header fails closed with no HTTP call", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    // Reserved prefix with a misspelled marker line.
    const input = {
      command: `# - REQUIRE_ESCALATION_X\n${CATEGORY_HEADER_PREFIX} host\n${JUSTIFICATION_HEADER_PREFIX} x\necho hi`,
    }
    const blocked = await runBefore(h, "shell", "s1", input)
    expect(blocked).toMatch(/[Mm]alformed|[Bb]locked/)
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)
  })
})

describe("reviewer infrastructure failures fail closed but never stick", () => {
  test("HTTP 500 denies the call; the identical request may be retried", async () => {
    const mock = await startReviewer(() => ({ status: 500 }))
    const h = await startPluginWithReview({}, mock)

    const input = {
      command: escalation("secret", "read credential file", "cat /etc/shadow"),
    }
    const blocked = await runBefore(h, "shell", "s1", input)
    expect(blocked).toMatch(/[Ee]scalation|Blocked/)
    // Infra failure is not a terminal deny: the message offers a later retry
    // (and the user route) without claiming escalation is permanently closed.
    expect(blocked).toContain("retry the same escalation request later")
    expect(blocked).not.toContain("ask for escalation")
    expect(mock.requests).toHaveLength(1)
    expect(h.dynamicCalls).toHaveLength(0)

    // Infra failures are not recorded as ask_user/deny: the same command may
    // ask again, which burns another reviewer call (unlike a recorded denial).
    const retry = {
      command: escalation("secret", "read credential file", "cat /etc/shadow"),
    }
    const blockedAgain = await runBefore(h, "shell", "s1", retry)
    expect(blockedAgain).toMatch(/[Ee]scalation|Blocked/)
    expect(mock.requests).toHaveLength(2)
    expect(h.dynamicCalls).toHaveLength(0)
  })
})

describe("normal commands are unaffected by the escalation path", () => {
  test("a plain command never touches the reviewer and passes through verbatim", async () => {
    const mock = await startReviewer(decision("deny"))
    const h = await startPluginWithReview({}, mock)

    const input = { command: "echo hello" }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    expect(input.command).toBe("echo hello")
    expect(mock.requests).toHaveLength(0)
    expect(h.contextCalls()).toBe(0)
    expect(h.dynamicCalls).toHaveLength(0)
  })

  test("a static DENY without a header is a plain block, not an escalation path", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    const input = { command: "rm -rf /" }
    const blocked = await runBefore(h, "shell", "s1", input)
    expect(blocked).toMatch(/Blocked/)
    expect(input.command).toBe("rm -rf /")
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)
  })

  test("header-looking text mid-command is not parsed as an escalation", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock)

    const command = `echo start\n# - REQUIRE_ESCALATION\n${CATEGORY_HEADER_PREFIX} secret\n${JUSTIFICATION_HEADER_PREFIX} x\necho end`
    const input = { command }
    expect(await runBefore(h, "shell", "s1", input)).toBeUndefined()
    expect(input.command).toBe(command)
    expect(mock.requests).toHaveLength(0)
  })
})

// A dynamic DENY's "Risk categories:" hint must name only the risk families
// still needing a grant. A category already armed for this call (session
// lease or allow_once) is not outstanding risk — re-advertising it would loop
// the agent back to requesting the same approved label. The hint is
// presentation-only: the DENY stands either way and the recorded denial keeps
// the full judged category set for the escalation coverage gate.
describe("dynamic denial hint names only unarmed categories", () => {
  const denyIndirection: DynamicReviewResponder = () => ({
    decision: "DENY",
    categories: ["indirection"],
  })

  test("armed indirection lease + DENY [indirection]: still blocked, no repeat hint", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock, "array", denyIndirection)

    // A session lease arms indirection; the dynamic reviewer still runs,
    // sees the grant, and denies. The block message must not tell the agent
    // to escalate the category that is already armed.
    await invoke(h, "bypass", "s1", "indirection")
    const first = await runBefore(h, "shell", "s1", { command: "python3 helper.py" })
    expect(first).toContain("Blocked by dynamic classifier")
    expect(first).not.toContain("Risk categories")
    expect(h.dynamicCalls).toHaveLength(1)
    expect(h.dynamicCalls[0].command).toBe("python3 helper.py")
    expect(h.dynamicCalls[0].userBypass).toContain("indirection")

    // A retry re-denies without re-advertising the armed category.
    const second = await runBefore(h, "shell", "s1", { command: "python3 helper.py" })
    expect(second).toContain("Blocked by dynamic classifier")
    expect(second).not.toContain("Risk categories")
    expect(h.dynamicCalls).toHaveLength(2)

    // With nothing armed the same denial names indirection as outstanding.
    await invoke(h, "bypass", "s1", "off")
    const plain = await runBefore(h, "shell", "s1", { command: "python3 other.py" })
    expect(plain).toContain("Blocked by dynamic classifier")
    expect(plain).toContain("Risk categories: indirection")
    expect(h.dynamicCalls).toHaveLength(3)
    expect(h.dynamicCalls[2].userBypass ?? []).not.toContain("indirection")
  })

  test("a cached deny replay filters the armed category without a new review", async () => {
    const mock = await startReviewer(decision("allow_once"))
    // `cat /etc/shadow` is fully inspectable (no local scripts), so the deny
    // lands in the 90s report cache and the retry replays it.
    const h = await startPluginWithReview({}, mock, "array", () => ({
      decision: "DENY",
      categories: ["secret"],
    }))
    await invoke(h, "bypass", "s1", "secret")

    const first = await runBefore(h, "shell", "s1", { command: "cat /etc/shadow" })
    expect(first).toContain("Blocked by dynamic classifier")
    expect(first).not.toContain("Risk categories")
    expect(h.dynamicCalls[0].userBypass).toContain("secret")

    const second = await runBefore(h, "shell", "s1", { command: "cat /etc/shadow" })
    expect(second).toContain("Blocked by dynamic classifier")
    expect(second).not.toContain("Risk categories")
    // The replay came from the report cache — no second review call.
    expect(h.dynamicCalls).toHaveLength(1)
  })

  test("armed indirection + DENY [indirection,secret]: hint keeps only the unarmed risk", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({}, mock, "array", () => ({
      decision: "DENY",
      categories: ["indirection", "secret"],
    }))
    await invoke(h, "bypass", "s1", "indirection")

    const blocked = await runBefore(h, "shell", "s1", { command: "python3 helper.py" })
    expect(blocked).toContain("Blocked by dynamic classifier")
    expect(blocked).toContain("Risk categories: secret")
    expect(blocked).not.toContain("Risk categories: indirection")
    expect(h.dynamicCalls[0].userBypass).toContain("indirection")
  })

  test("HARD policy bypassing route: the armed category is filtered there too", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPluginWithReview({ strictness: "HARD" }, mock, "array", () => ({
      decision: "DENY",
      categories: ["indirection"],
      bypassing: true,
    }))
    await invoke(h, "bypass", "s1", "indirection")

    const blocked = await runBefore(h, "shell", "s1", { command: "python3 helper.py" })
    expect(blocked).toContain("Blocked by dynamic classifier")
    expect(blocked).not.toContain("Risk categories")
    expect(h.dynamicCalls[0].userBypass).toContain("indirection")
  })
})

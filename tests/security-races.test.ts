import { afterAll, beforeEach, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { resetEscalationReviewLimiter } from "../src/security/escalation-reviewer"
import { ESCALATION_MARKER, CATEGORY_HEADER_PREFIX, JUSTIFICATION_HEADER_PREFIX } from "../src/security/escalation"

type Hook = (event: any) => Effect.Effect<any, any>
const scopes: Scope.Closeable[] = []
const servers: Server[] = []
beforeEach(() => resetEscalationReviewLimiter())
afterAll(async () => {
  for (const scope of scopes) await Effect.runPromise(Scope.close(scope, undefined as never))
  for (const server of servers) await new Promise<void>((resolve) => server.close(() => resolve()))
})

async function errorOf(effect: Effect.Effect<unknown, unknown>) {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const error = Cause.findErrorOption(exit.cause)
  return Option.isSome(error) ? String(error.value) : String(exit.cause)
}

async function harness(options: Record<string, unknown> = {}, parents: Record<string, string> = {}) {
  const hooks: Record<string, Hook> = {}
  const commands: Record<string, Hook> = {}
  let getCalls = 0
  let getFails = false
  const ctx = {
    options: { sandbox: { enabled: false }, ...options },
    tool: { hook: (name: string, cb: Hook) => { hooks[name] = cb; return Effect.void } },
    shell: { hook: () => Effect.void },
    permission: { hook: (_: string, cb: Hook) => { hooks.evaluate = cb; return Effect.void } },
    command: { transform: (cb: any) => Effect.sync(() => cb({ add: (d: any) => { commands[d.name] = d.execute } })) },
    session: {
      get: ({ sessionID }: { sessionID: string }) => Effect.suspend(() => {
        getCalls++
        return getFails ? Effect.fail(new Error("lookup failed")) : Effect.succeed({
          id: sessionID, parentID: parents[sessionID], location: { directory: process.cwd() },
        })
      }),
      context: () => Effect.succeed([]),
      interrupt: () => Effect.void,
      synthetic: () => Effect.void,
    },
    // No created events at all: these tests cannot accidentally rely on their
    // consumption before the first tool/permission boundary.
    event: { subscribe: () => Stream.empty },
  }
  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise((plugin as any).effect(ctx).pipe(Scope.provide(scope)))
  const before = (sessionID: string, tool: string, input: any, id = crypto.randomUUID()) =>
    errorOf(hooks["execute.before"]({ sessionID, tool, input, id, agent: "test", messageID: "m" }))
  return {
    before,
    command: (sessionID: string, name: string, text: string) => errorOf(commands[name]({ sessionID, prompt: { text } })),
    async evaluate(sessionID: string, action: string) {
      const event = { sessionID, action, resources: [], effect: "allow" }
      await Effect.runPromise(hooks.evaluate(event))
      return event.effect
    },
    after: (id: string, child: string, outputChild = child) => Effect.runPromise(hooks["execute.after"]({
      sessionID: "parent", tool: "subagent", id, status: "completed",
      result: { metadata: { sessionID: child }, output: { sessionID: outputChild } },
    })),
    afterOutput: (id: string, child: string) => Effect.runPromise(hooks["execute.after"]({
      sessionID: "parent", tool: "subagent", id, status: "completed", result: { output: { sessionID: child } },
    })),
    getCalls: () => getCalls,
    failGet: (value: boolean) => { getFails = value },
  }
}

async function reviewer(respond: (index: number, finish: (content: string) => void) => void) {
  let calls = 0
  const server = createServer((req, res) => {
    req.resume()
    req.on("end", () => respond(++calls, (content) => {
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ choices: [{ message: { content } }] }))
    }))
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  servers.push(server)
  const address = server.address() as { port: number }
  return {
    calls: () => calls,
    options: { dynamicReview: {
      baseURL: `http://127.0.0.1:${address.port}/v1`,
      model: "race-test", apiKey: "test-only", timeoutMs: 15000, maxRounds: 1,
    } },
  }
}

const escalation = (command: string) => ({ command:
  `${ESCALATION_MARKER}\n${CATEGORY_HEADER_PREFIX} filesystem\n${JUSTIFICATION_HEADER_PREFIX} Required to complete the user request\n${command}`,
})

test("first boundary hydrates an RO ancestor without events; task is unknown write-class", async () => {
  const h = await harness({}, { child: "parent", grandchild: "child" })
  expect(await h.command("parent", "perm", "ro")).toBeUndefined()
  expect(await h.before("child", "shell", { command: "touch /home/security-race-proof" })).toBeDefined()
  expect(await h.evaluate("grandchild", "edit")).toBe("deny")
  expect(await h.evaluate("child", "task")).toBe("deny")
  expect(await h.evaluate("child", "subagent")).toBe("allow")
  expect(await h.evaluate("child", "read")).toBe("allow")
})

test("concurrent spawn declarations intersect until authoritative binding, not permanently", async () => {
  const h = await harness({}, { childRO: "parent", childRW: "parent" })
  expect(await h.before("parent", "subagent", { permission: "ro" }, "spawn-ro")).toBeUndefined()
  expect(await h.before("parent", "subagent", { permission: "rw" }, "spawn-rw")).toBeUndefined()
  expect(await h.before("childRO", "shell", { command: "touch /home/security-race-proof" })).toBeDefined()
  expect(await h.evaluate("childRO", "edit")).toBe("deny")
  expect(await h.evaluate("childRW", "edit")).toBe("deny")
  await h.after("spawn-rw", "childRW", "childRO")
  expect(await h.evaluate("childRW", "edit")).toBe("allow")
  expect(await h.evaluate("childRO", "edit")).toBe("deny")
  await h.afterOutput("spawn-ro", "childRO")
  expect(await h.evaluate("childRO", "edit")).toBe("deny")
})

test("failed hydration is retryable and cycles are bounded; RO reads/delegation remain available", async () => {
  const h = await harness()
  h.failGet(true)
  expect(await h.evaluate("missing", "edit")).toBe("deny")
  expect(await h.evaluate("missing", "read")).toBe("allow")
  expect(await h.evaluate("missing", "subagent")).toBe("allow")
  h.failGet(false)
  expect(await h.evaluate("missing", "edit")).toBe("allow")
  const cycle = await harness({}, { a: "b", b: "a" })
  expect(await cycle.evaluate("a", "edit")).toBe("deny")
  expect(cycle.getCalls()).toBe(2)
})

test("concurrent similar escalation cannot obtain a second allow_once review", async () => {
  let release!: () => void
  let started!: () => void
  const ready = new Promise<void>((resolve) => { started = resolve })
  const mock = await reviewer((index, finish) => {
    if (index === 1) { release = () => finish("deny"); started() }
    else finish("allow_once")
  })
  const h = await harness(mock.options)
  const first = h.before("s", "shell", escalation("touch /home/race-one"))
  await ready
  try {
    // Terminal ending: the pending message may name waiting, never re-escalation.
    const pending = await h.before("s", "shell", escalation("sudo touch /home/race-one"))
    expect(pending).toContain("pending")
    expect(pending).toContain("Wait for the pending request's result")
    expect(pending).not.toContain("ask for escalation")
    expect(mock.calls()).toBe(1)
  } finally { release() }
  const denied = await first
  expect(denied).toContain('denied this one-time request')
  // A reviewer verdict is terminal: /bypass the requested category or skip.
  expect(denied).toContain("/bypass filesystem")
  expect(denied).not.toContain("ask for escalation")
  expect(mock.calls()).toBe(1)
})

test("eight failures saturate the session without evicting its first rejection", async () => {
  const mock = await reviewer((_, finish) => finish("deny"))
  const h = await harness(mock.options)
  for (let i = 0; i < 8; i++) {
    resetEscalationReviewLimiter()
    expect(await h.before("s", "shell", escalation(`unique${i} target${i}`))).toContain('denied this one-time request')
  }
  expect(mock.calls()).toBe(8)
  for (const cmd of ["unique0 target0", "brand-new-operation"]) {
    const saturated = await h.before("s", "shell", escalation(cmd))
    expect(saturated).toContain("capacity")
    // Terminal ending: saturation cannot be fixed by re-requesting.
    expect(saturated).toContain("/bypass filesystem")
    expect(saturated).not.toContain("ask for escalation")
  }
  await h.command("s", "bypass", "filesystem")
  expect(await h.before("s", "shell", escalation("unique0 target0"))).toContain("capacity")
  expect(mock.calls()).toBe(8)
})

test("review protocol failure releases pending without recording permanent rejection", async () => {
  const mock = await reviewer((index, finish) => finish(index === 1 ? "invalid-verdict" : "deny"))
  const h = await harness(mock.options)
  const failed = await h.before("s", "shell", escalation("touch /home/retry"))
  expect(failed).toContain("failed")
  // Infra failures are retryable — the message must not claim a permanent deny.
  expect(failed).toContain("retry the same escalation request later")
  expect(failed).not.toContain("ask for escalation")
  expect(await h.before("s", "shell", escalation("touch /home/retry"))).toContain('denied this one-time request')
  expect(mock.calls()).toBe(2)
})

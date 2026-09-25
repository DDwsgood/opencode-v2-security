import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { BYPASS_CATEGORIES } from "../src/categories"
import { ESCALATION_MARKER, parseEscalation } from "../src/security/escalation"

// Full escalation guidance is attached only to the FIRST classifier block of a
// session's current context cycle; later blocks carry only BLOCK_SUFFIX. A
// completed compaction starts a new cycle, session.deleted and plugin unload
// clear the state, and claims are synchronous so concurrent blocks of one
// session cannot both show the full guide.

let workdir: string | undefined
const harnesses: Harness[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "escalation-guide-"))
  return workdir
}

/** Controllable wire-event feed: the plugin's `ctx.event.subscribe()` consumer
 * iterates this async iterable, so tests push durable events mid-run in
 * exactly the `{ type, data: { sessionID, ... } }` shape the host emits.
 * `close()` ends the iterable so the consumer fiber finishes and scope
 * finalization never blocks on a pending iterator pull. */
function eventFeed() {
  const pending: unknown[] = []
  const waiters: Array<() => void> = []
  let closed = false
  const stream = Stream.fromAsyncIterable(
    (async function* () {
      for (;;) {
        while (pending.length > 0) yield pending.shift()!
        if (closed) return
        await new Promise<void>((resolve) => waiters.push(resolve))
      }
    })(),
    (cause) => new Error(`event feed failed: ${String(cause)}`),
  )
  const push = (event: unknown) => {
    pending.push(event)
    const wake = waiters.shift()
    if (wake) wake()
  }
  const close = () => {
    closed = true
    for (const wake of waiters.splice(0)) wake()
  }
  return { stream, push, close }
}

afterAll(async () => {
  for (const harness of harnesses) {
    await harness.close().catch(() => {})
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>

type Harness = {
  executeBefore: HookCb
  commands: Map<string, CommandExec>
  status: (sessionID: string) => Promise<{ active: string[] }>
  close: () => Promise<void>
  push: (event: unknown) => void
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

async function startPlugin(extraOptions: Record<string, unknown> = {}): Promise<Harness> {
  const directory = await ensureWorkdir()
  const feed = eventFeed()
  const collected: Partial<Record<string, HookCb>> = {}
  const commands = new Map<string, CommandExec>()
  let statusHandler: ((input: { sessionID: string }) => Effect.Effect<unknown, unknown>) | undefined

  const ctx = {
    options: { sandbox: { enabled: false }, logReviewerTrace: false, ...extraOptions },
    tool: {
      hook: (name: string, cb: HookCb) => {
        collected[name] = cb
        return Effect.void
      },
      transform: () => Effect.void,
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
      synthetic: () => Effect.void,
    },
    rpc: {
      register: (_def: unknown, handlers: Record<string, unknown>) => {
        statusHandler = handlers.status as typeof statusHandler
        return Effect.succeed({ events: { emit: () => Effect.void } })
      },
    },
    event: { subscribe: () => feed.stream },
  }

  const scope = await Effect.runPromise(Scope.make())
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )

  const close = async () => {
    // End the event iterable first so the forked consumer fiber finishes
    // instead of blocking scope finalization on a pending iterator pull.
    feed.close()
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  const harness: Harness = {
    executeBefore: collected["execute.before"]!,
    commands,
    status: async (sessionID) =>
      (await Effect.runPromise(statusHandler!({ sessionID }))) as { active: string[] },
    close,
    push: feed.push,
  }
  harnesses.push(harness)
  return harness
}

/** execute.before driver; returns the block message, or undefined on allow. */
const runBefore = (h: Harness, sessionID: string, command: string) =>
  failureMessage(
    h.executeBefore({
      tool: "shell",
      sessionID,
      agent: "test",
      messageID: "m1",
      id: `call-${Math.random()}`,
      input: { command },
    } as never),
  )

const invoke = (h: Harness, name: string, sessionID: string, text = "") =>
  failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))

/** A block carries the full escalation guide iff it is the session's first
 * classifier block of the current context cycle. */
const hasFullGuide = (message: string | undefined) =>
  Boolean(message?.includes(ESCALATION_MARKER) && message.includes("Categories:"))
const isShortBlock = (message: string | undefined) =>
  Boolean(message?.includes("ask for escalation instead of trying alternative methods") && !message?.includes(ESCALATION_MARKER))

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

/** Poll until `condition` holds (bounded), so tests never depend on event-fiber
 * scheduling. */
async function until(condition: () => Promise<boolean>, ms = 5000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if (await condition()) return
    await delay(10)
  }
  throw new Error("condition not met within timeout")
}

/** Arm a throwaway probe session's bypass, push the events under test, then a
 * trailing session.deleted for the probe, and wait until that deletion's
 * cleanup becomes observable. Because the event consumer processes the stream
 * strictly in order, once the probe's deletion is observed, every event
 * pushed before it (the reset under test) was processed too. */
async function flushEventsAfterPush(h: Harness, probe: string, ...events: unknown[]) {
  expect(await invoke(h, "bypass", probe, "host")).toBeUndefined()
  expect((await h.status(probe)).active).toContain("host")
  for (const event of events) h.push(event)
  h.push({ type: "session.deleted", data: { sessionID: probe } })
  await until(async () => (await h.status(probe)).active.length === 0)
}

// `rm -rf /etc` / `rm -rf /usr` are unconditional static-floor DENYs (no
// dynamic review, no escalation reviewer) — pure static blocks.
const DENY_A = "rm -rf /etc"
const DENY_B = "rm -rf /usr"

describe("full escalation guidance: once per session per context cycle", () => {
  test("first block carries the full guide; the second carries only the short suffix", async () => {
    const h = await startPlugin()
    const first = await runBefore(h, "s1", DENY_A)
    expect(first).toMatch(/Blocked by static classifier/)
    // The ordinary block keeps the user-specified short suffix verbatim.
    expect(first).toContain(
      "Skip the step (if unnecessary) or ask for escalation instead of trying alternative methods to bypass the check.",
    )
    expect(hasFullGuide(first)).toBe(true)
    expect(first).toContain("Categories: filesystem (local file changes)")

    const second = await runBefore(h, "s1", DENY_B)
    expect(second).toMatch(/Blocked by static classifier/)
    expect(isShortBlock(second)).toBe(true)
  })

  test("another session's first block still carries the full guide", async () => {
    const h = await startPlugin()
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", DENY_B))).toBe(true)
    // s2 has its own per-session claim.
    expect(hasFullGuide(await runBefore(h, "s2", DENY_A))).toBe(true)
  })

  test("a malformed escalation static block carries the full guide only when first in the cycle", async () => {
    const h = await startPlugin()
    const malformed = await runBefore(h, "s1", "# - REQUIRE_ESCALATION")
    expect(malformed).toMatch(/Malformed escalation request/)
    expect(hasFullGuide(malformed)).toBe(true)

    expect(isShortBlock(await runBefore(h, "s1", DENY_A))).toBe(true)

    // First block of a fresh cycle in another session: full guide again.
    const malformed2 = await runBefore(h, "s2", "# - REQUIRE_ESCALATION\n# - CATEGORY: all\n# - JUSTIFICATION: x\necho hi")
    expect(malformed2).toMatch(/Malformed escalation request/)
    expect(hasFullGuide(malformed2)).toBe(true)
  })

  test("two concurrent blocks of one session: exactly one carries the full guide", async () => {
    const h = await startPlugin()
    const [a, b] = await Promise.all([runBefore(h, "s1", DENY_A), runBefore(h, "s1", DENY_B)])
    expect(a).toMatch(/Blocked by static classifier/)
    expect(b).toMatch(/Blocked by static classifier/)
    // The synchronous claim guarantees exactly one full guide, whichever
    // block constructs its message first.
    expect([hasFullGuide(a), hasFullGuide(b)].filter(Boolean)).toHaveLength(1)
    expect(isShortBlock(hasFullGuide(a) ? b : a)).toBe(true)
  })

  test("guidance names the canonical categories with terse meanings, one-call semantics, and no wildcard-forbidden wording", async () => {
    const h = await startPlugin()
    const first = await runBefore(h, "s1", DENY_A)
    // Only grantable categories are named: `dynamic` and `slow` are not
    // grantable via escalation (fix F1) — their glosses are absent.
    for (const category of BYPASS_CATEGORIES) {
      if (category === "dynamic" || category === "slow") continue
      expect(first).toContain(category)
    }
    expect(first).not.toContain("skip the dynamic reviewer")
    expect(first).not.toContain("skip slow-command checks")
    expect(first).toContain("resubmit the command once")
    expect(first).toContain("independent reviewer")
    expect(first).toContain("allow_once")
    expect(first).toContain("/bypass")
    // The guide explains an ask_user/deny outcome closes the category route:
    // a similar command must go to the user, not back to the reviewer.
    expect(first).toContain("cannot be escalated again in this session")
    expect(first).not.toContain("are forbidden")
    expect(first).not.toContain("all/*/ALL")

    // Parser safety is unchanged: wildcards stay rejected, case-sensitively for ALL.
    for (const categories of ["all", "*", "ALL", "host,all"]) {
      const text = [ESCALATION_MARKER, `# - CATEGORY: ${categories}`, "# - JUSTIFICATION: x", "echo hi"].join("\n")
      const parsed = parseEscalation(text, BYPASS_CATEGORIES)
      expect(parsed.status).toBe("malformed")
      if (parsed.status === "malformed") {
        expect(["forbidden-category", "unknown-category"]).toContain(parsed.code)
      }
    }
  })
})

describe("permission.write hard refuse", () => {
  // `bash -c` under an RO session is an unconditional permission.write static
  // deny (see tests/static-regressions.test.ts execution-channel matrix).
  const WRITE_SHAPED = "bash -c 'ls -la'"

  test("carries no escalation guidance and does not consume the cycle's full-guide slot", async () => {
    const h = await startPlugin()
    // Arm RO via the user-side /perm command; the effective ceiling is r-x.
    expect(await invoke(h, "perm", "s1", "ro")).toBeUndefined()

    const denied = await runBefore(h, "s1", WRITE_SHAPED)
    expect(denied).toMatch(/Blocked by static classifier/)
    expect(denied).toContain("permission ceiling")
    expect(denied).toContain("/perm +w or /perm rw")
    // Neither the escalation suffix nor the full guide is attached.
    expect(denied).not.toContain("ask for escalation")
    expect(denied).not.toContain(ESCALATION_MARKER)

    // The slot was not consumed: the next ordinary (non-write) static block
    // still carries the full guide. `shutdown` denies as system.shutdown —
    // under RO write-shaped commands would mask other floors as
    // permission.write, so a host deny is used here.
    expect(hasFullGuide(await runBefore(h, "s1", "shutdown -h now"))).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", "shutdown -r now"))).toBe(true)
  })

  test("an RW session's permission.write-free denies still use the ordinary suffix", async () => {
    const h = await startPlugin()
    const denied = await runBefore(h, "s1", DENY_A)
    expect(denied).toContain("ask for escalation instead of trying alternative methods")
  })
})

describe("escalation request terminal endings", () => {
  test("an unavailable escalation reviewer ends with /bypass guidance, not 'ask for escalation'", async () => {
    // `dynamicReview: {}` resolves as unavailable; no reviewer call is made.
    const h = await startPlugin({ dynamicReview: {} })
    const blocked = await runBefore(
      h,
      "s1",
      [ESCALATION_MARKER, "# - CATEGORY: host", "# - JUSTIFICATION: restart per request", "systemctl restart nginx"].join("\n"),
    )
    expect(blocked).toContain("Escalation review is unavailable")
    expect(blocked).toContain("dynamic review unavailable or invalid review configuration")
    // Internal config field names are folded out of the agent-facing reason.
    expect(blocked).not.toContain("dynamicReview.")
    expect(blocked).toContain("/bypass host")
    expect(blocked).not.toContain("ask for escalation")
  })
})

describe("dynamic bypass under a fail-closed policy", () => {
  // `cat /etc/shadow` is a LOOSE ASK: with the `dynamic` category armed the
  // reviewer is skipped and the call always takes the "unavailable +
  // fail_open" route (fix F2) — the configured failPolicy does not matter.
  const ASK_COMMAND = "cat /etc/shadow"

  test("fail_close + armed dynamic bypass allows the command (armed dynamic is fail-open)", async () => {
    const h = await startPlugin({ failPolicy: "fail_close" })
    expect(await invoke(h, "bypass", "s1", "dynamic")).toBeUndefined()

    expect(await runBefore(h, "s1", ASK_COMMAND)).toBeUndefined()
  })

  test("fail_open + armed dynamic bypass still allows the same command", async () => {
    const h = await startPlugin({ failPolicy: "fail_open" })
    expect(await invoke(h, "bypass", "s1", "dynamic")).toBeUndefined()
    expect(await runBefore(h, "s1", ASK_COMMAND)).toBeUndefined()
  })
})

describe("subagent permission arg validation", () => {
  test("an invalid permission is rejected with the current r/w-only wording (no r-x/octal range)", async () => {
    const h = await startPlugin()
    const denied = await failureMessage(
      h.executeBefore({
        tool: "subagent",
        sessionID: "s1",
        agent: "test",
        messageID: "m1",
        id: "call-1",
        input: { prompt: "x", permission: "r-x" },
      } as never),
    )
    expect(denied).toContain('Invalid subagent permission "r-x"')
    expect(denied).toContain("ro/4, rw/6, w/2, or none/0")
    expect(denied).toContain("x cannot be set")
    expect(denied).not.toContain("0-7")
  })
})

describe("context-cycle resets", () => {
  // Real durable wire event: `session.compaction.ended` with
  // { sessionID, reason, text, recent } (packages/schema/src/session-event.ts,
  // published by core session compaction on completion).
  const COMPACTION_ENDED = {
    type: "session.compaction.ended",
    data: { sessionID: "s1", reason: "auto", text: "summary of the session so far", recent: "recent transcript" },
  }

  test("session.compaction.ended starts a new cycle: the next block carries the full guide again", async () => {
    const h = await startPlugin()
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", DENY_B))).toBe(true)

    await flushEventsAfterPush(h, "probe", COMPACTION_ENDED)
    const third = await runBefore(h, "s1", DENY_A)
    expect(hasFullGuide(third)).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", DENY_B))).toBe(true)
  })

  test("the session.compacted schema-manifest alias also starts a new cycle", async () => {
    const h = await startPlugin()
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", DENY_B))).toBe(true)

    // Ephemeral alias declared in packages/schema/src/session-compaction-event.ts
    // ({ type, data: { sessionID } }); accepted for host builds that emit it.
    await flushEventsAfterPush(h, "probe", { type: "session.compacted", data: { sessionID: "s1" } })
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
  })

  test("a failed compaction does not start a new cycle", async () => {
    const h = await startPlugin()
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", DENY_B))).toBe(true)

    await flushEventsAfterPush(h, "probe", {
      type: "session.compaction.failed",
      data: { sessionID: "s1", reason: "auto", error: { type: "compaction.failed", message: "no summary" } },
    })
    expect(isShortBlock(await runBefore(h, "s1", DENY_A))).toBe(true)
  })

  test("session.deleted clears the cycle state", async () => {
    const h = await startPlugin()
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
    expect(isShortBlock(await runBefore(h, "s1", DENY_B))).toBe(true)

    await flushEventsAfterPush(h, "probe", { type: "session.deleted", data: { sessionID: "s1" } })
    expect(hasFullGuide(await runBefore(h, "s1", DENY_A))).toBe(true)
  })

  test("a plugin reload starts a fresh cycle (scope-local state, finalizer-cleared)", async () => {
    const first = await startPlugin()
    expect(hasFullGuide(await runBefore(first, "s1", DENY_A))).toBe(true)
    expect(isShortBlock(await runBefore(first, "s1", DENY_B))).toBe(true)
    await first.close()

    const second = await startPlugin()
    expect(hasFullGuide(await runBefore(second, "s1", DENY_A))).toBe(true)
    await second.close()
  })
})
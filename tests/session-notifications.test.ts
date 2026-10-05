import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import {
  applyNoticesToContext,
  attachSessionContextHook,
  createSessionStateNotices,
  type SessionContextEvent,
} from "../src/session-notifications"

// The whole point of the module: permission/bypass state reaches the next
// model call through the context hook — NEVER through session input APIs.
// The mocked host below records every synthetic/prompt/generate/interrupt/
// wait/resume touch; every assertion suite ends by checking the count is 0.

function makeHost() {
  const calls = {
    hookRegistrations: [] as string[],
    contextCb: undefined as
      | ((ev: SessionContextEvent) => Effect.Effect<void>)
      | undefined,
    synthetic: 0,
    prompt: 0,
    generate: 0,
    interrupt: 0,
    wait: 0,
    resume: 0,
  }
  const ctx = {
    session: {
      hook: (name: string, cb: (ev: SessionContextEvent) => Effect.Effect<void>) => {
        calls.hookRegistrations.push(name)
        calls.contextCb = cb
        return Effect.succeed({ dispose: Effect.void })
      },
      synthetic: () => (calls.synthetic++, Effect.void),
      prompt: () => (calls.prompt++, Effect.void),
      generate: () => (calls.generate++, Effect.void),
      interrupt: () => (calls.interrupt++, Effect.void),
      wait: () => (calls.wait++, Effect.void),
      resume: () => (calls.resume++, Effect.void),
    },
  }
  const silent = () =>
    expect(
      calls.synthetic + calls.prompt + calls.generate +
        calls.interrupt + calls.wait + calls.resume,
    ).toBe(0)
  return { calls, ctx, silent }
}

const buildContext = (sessionID: string): SessionContextEvent => ({
  sessionID,
  system: [{ type: "text", text: "base system prompt" }],
})

describe("session state notices (no-wake context injection)", () => {
  test("perm/bypass mutations never touch any session input API", async () => {
    const { calls, ctx, silent } = makeHost()
    const notices = createSessionStateNotices()
    const attached = await Effect.runPromise(attachSessionContextHook(ctx as never, notices))
    expect(attached).toBe(true)
    expect(calls.hookRegistrations).toEqual(["context"])

    notices.setPerm("s1", "PERM rw")
    notices.setBypass("s1", "BYPASS filesystem")
    notices.setBypass("s1", "BYPASS filesystem,network") // transition
    notices.setPerm("s1", undefined)                   // back to default
    notices.clear("s1")
    silent()
  })

  test("the next context build sees the latest state, nothing earlier", async () => {
    const { calls, ctx, silent } = makeHost()
    const notices = createSessionStateNotices()
    await Effect.runPromise(attachSessionContextHook(ctx as never, notices))

    notices.setPerm("s1", "This session's permission ceiling changed.\nCurrent permission: r--")
    notices.setPerm("s1", "This session's permission ceiling changed.\nCurrent permission: rw-")
    notices.setBypass("s1", "Some checks are bypassed: filesystem.")

    const ev = buildContext("s1")
    await Effect.runPromise(calls.contextCb!(ev))
    expect(ev.system).toHaveLength(2)
    const injected = ev.system[1]
    expect(injected.text).toContain("rw-")
    expect(injected.text).not.toContain("r--") // stale value not replayed
    expect(injected.text).toContain("filesystem")
    expect(injected.metadata?.["opencode-v2-security-session-state"]).toBe(true)
    silent()
  })

  test("default/baseline state injects no noise", async () => {
    const { calls, ctx, silent } = makeHost()
    const notices = createSessionStateNotices()
    await Effect.runPromise(attachSessionContextHook(ctx as never, notices))

    const ev = buildContext("s1") // nothing ever set
    await Effect.runPromise(calls.contextCb!(ev))
    expect(ev.system).toHaveLength(1)

    notices.setPerm("s1", "x")
    notices.setPerm("s1", undefined) // transition back to default clears
    const ev2 = buildContext("s1")
    await Effect.runPromise(calls.contextCb!(ev2))
    expect(ev2.system).toHaveLength(1)
    silent()
  })

  test("duplicate apply on one build updates in place, no stacking", async () => {
    const notices = createSessionStateNotices()
    notices.setPerm("s1", "PERM ro")
    const ev = buildContext("s1")
    applyNoticesToContext(notices, ev)
    notices.setPerm("s1", "PERM rw")
    applyNoticesToContext(notices, ev)
    expect(ev.system).toHaveLength(2)
    expect(ev.system[1].text).toContain("rw")
  })

  test("state is per-session: descendant/sibling sessions unaffected", async () => {
    const { calls, ctx, silent } = makeHost()
    const notices = createSessionStateNotices()
    await Effect.runPromise(attachSessionContextHook(ctx as never, notices))
    notices.setBypass("parent", "BYPASS all armed")
    const child = buildContext("child")
    await Effect.runPromise(calls.contextCb!(child))
    expect(child.system).toHaveLength(1)
    // expiry/restore is a caller-driven transition: clearing removes notice
    notices.setBypass("parent", undefined)
    const parent = buildContext("parent")
    await Effect.runPromise(calls.contextCb!(parent))
    expect(parent.system).toHaveLength(1)
    silent()
  })

  test("same-state rewrite is a deduped no-op; restore after clear reinjects", async () => {
    const notices = createSessionStateNotices()
    notices.setPerm("s1", "PERM ro")
    const before = notices.snapshot("s1")
    notices.setPerm("s1", "PERM ro")
    expect(notices.snapshot("s1")).toBe(before)
    notices.clear("s1")
    expect(notices.snapshot("s1")).toBeUndefined()
    notices.setPerm("s1", "PERM ro") // e.g. bypass kill-switch restored
    expect(notices.snapshot("s1")).toContain("PERM ro")
  })

  test("host without session.hook reports unattached instead of crashing", async () => {
    const notices = createSessionStateNotices()
    const attached = await Effect.runPromise(
      attachSessionContextHook({ session: {} } as never, notices),
    )
    expect(attached).toBe(false)
  })
})

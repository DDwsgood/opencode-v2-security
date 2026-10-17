import { describe, expect, test } from "bun:test"
import { createSessionStateNotices, type SessionStateNotification } from "../src/session-notifications"

function harness() {
  const history = [{ role: "user", text: "Original user request" }]
  const system = [{ type: "text", text: "Original system prompt" }]
  const notifications: SessionStateNotification[] = []
  const notices = createSessionStateNotices(async (notification) => {
    notifications.push(structuredClone(notification))
    history.push({ role: "user", text: notification.text })
  })
  return { notices, notifications, history, system }
}

describe("append-only user state notifications", () => {
  test("a state change alone admits nothing (no model request can start from it)", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Security mode: [Read only].")
    await host.notices.flush()
    expect(host.notifications).toHaveLength(0)
    expect(host.history).toHaveLength(1)
  })

  test("the next steering user prompt carries the latest notice, preserving the prefix", async () => {
    const host = harness()
    const prefix = structuredClone(host.history)
    const system = structuredClone(host.system)
    host.notices.setPerm("s1", "Security mode: [Read only].")
    await host.notices.deliverWithPrompt("s1", "steer")
    const first = structuredClone(host.history)
    host.notices.setPerm("s1", "Security mode: [Auto mode].")
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.system).toEqual(system)
    expect(host.history.slice(0, prefix.length)).toEqual(prefix)
    expect(host.history.slice(0, first.length)).toEqual(first)
    expect(host.history.at(-1)?.text).toContain("[Auto mode]")
    expect(host.notifications).toHaveLength(2)
    for (const notice of host.notifications) {
      expect(notice.resume).toBe(false)
      expect(notice.delivery).toBe("steer")
      expect(notice.metadata.securityStateNotice).toBe(true)
    }
  })

  test("a queued prompt does not carry the notice; the next steering prompt does", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Auto")
    await host.notices.deliverWithPrompt("s1", "queue")
    expect(host.notifications).toHaveLength(0)
    await host.notices.deliverWithPrompt("s1", undefined)
    expect(host.notifications).toHaveLength(1)
  })

  test("same-state refresh never repeats a notice on later prompts", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Read only")
    for (let i = 0; i < 5; i++) {
      host.notices.setPerm("s1", "Read only")
      await host.notices.deliverWithPrompt("s1", "steer")
    }
    expect(host.notifications).toHaveLength(1)
  })

  test("changes between prompts coalesce into one notice of the latest state", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Auto")
    host.notices.setBypass("s1", "filesystem")
    host.notices.setBypass("s1", "filesystem,network")
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.notifications).toHaveLength(1)
    expect(host.notifications[0].text).toBe("[opencode-v2-security] Auto\nfilesystem,network")
  })

  test("a state that returns to the delivered text before the next prompt adds nothing", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Auto")
    await host.notices.deliverWithPrompt("s1", "steer")
    host.notices.setPerm("s1", "Bypass")
    host.notices.setPerm("s1", "Auto")
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.notifications).toHaveLength(1)
  })

  test("deleting a session drops the undelivered notice without touching history", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Read only")
    await host.notices.deliverWithPrompt("s1", "steer")
    const history = structuredClone(host.history)
    host.notices.setPerm("s1", "Bypass")
    host.notices.clear("s1")
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.history).toEqual(history)
    expect(host.notices.snapshot("s1")).toBeUndefined()
  })

  test("notifications are isolated per session", async () => {
    const host = harness()
    host.notices.setPerm("parent", "Read only")
    host.notices.setPerm("child", "Auto")
    await host.notices.deliverWithPrompt("child", "steer")
    expect(host.notifications.map((notice) => notice.sessionID)).toEqual(["child"])
    expect(host.notices.snapshot("orphan")).toBeUndefined()
  })

  test("default state and bookkeeping clears append no empty message", async () => {
    const host = harness()
    host.notices.setPerm("s1", undefined)
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.notifications).toHaveLength(0)
    host.notices.setPerm("s1", "Auto")
    await host.notices.deliverWithPrompt("s1", "steer")
    host.notices.setPerm("s1", undefined)
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.notifications).toHaveLength(1)
  })

  test("an admission failure is not recorded as delivered", async () => {
    let fail = true
    const received: string[] = []
    const notices = createSessionStateNotices(async (notice) => {
      if (fail) throw new Error("host unavailable")
      received.push(notice.text)
    })
    notices.setPerm("s1", "Read only")
    await notices.deliverWithPrompt("s1", "steer")
    fail = false
    await notices.deliverWithPrompt("s1", "steer")
    expect(received).toEqual(["[opencode-v2-security] Read only"])
  })

  test("a transient model notice repeats until a real prompt durably admits it", async () => {
    const host = harness()
    expect(host.notices.forModelContext("s1")).toBeUndefined()
    host.notices.setPerm("s1", "Security mode: [Read only].")
    expect(host.notices.forModelContext("s1")).toBe("[opencode-v2-security] Security mode: [Read only].")
    expect(host.notices.forModelContext("s1")).toContain("[Read only]")
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.notifications).toHaveLength(1)
    expect(host.notices.forModelContext("s1")).toBeUndefined()
    host.notices.setPerm("s1", "Security mode: [Auto mode].")
    expect(host.notices.forModelContext("s1")).toContain("[Auto mode]")
  })

  test("a notice already admitted with a prompt is not repeated in model context", async () => {
    const host = harness()
    host.notices.setPerm("s1", "Read only")
    await host.notices.deliverWithPrompt("s1", "steer")
    expect(host.notices.forModelContext("s1")).toBeUndefined()
  })
})

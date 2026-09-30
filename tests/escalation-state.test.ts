import { describe, expect, test } from "bun:test"
import {
  escalationCommandsAreSimilar,
  escalationContextFromMessages,
  findSimilarFailedEscalation,
} from "../src/security/escalation-state"

describe("escalation retry families", () => {
  test("normalizes privilege wrappers and package-manager aliases", () => {
    expect(escalationCommandsAreSimilar("sudo apt-get install curl", "apt install curl")).toBe(true)
    expect(escalationCommandsAreSimilar("dnf install unzip", "yum install unzip")).toBe(true)
  })

  test("recognizes equivalent destructive and transfer commands", () => {
    expect(escalationCommandsAreSimilar("rm -rf /srv/old", "doas rm -r /srv/old")).toBe(true)
    expect(escalationCommandsAreSimilar("curl https://x/a -o /tmp/a", "wget https://x/a -O /tmp/a")).toBe(true)
  })

  test("does not merge unrelated command families", () => {
    expect(escalationCommandsAreSimilar("apt install curl", "systemctl restart nginx")).toBe(false)
    expect(escalationCommandsAreSimilar("cat README.md", "git status")).toBe(false)
  })

  test("finds a prior failed request", () => {
    const failure = {
      command: "sudo apt-get install curl",
      categories: ["host", "sandbox"],
      justification: "needed for test",
      decision: "deny" as const,
    }
    expect(findSimilarFailedEscalation("apt install curl", [failure])).toBe(failure)
  })
})

describe("escalation context extraction", () => {
  test("keeps only recent user and assistant prose", () => {
    const result = escalationContextFromMessages([
      { type: "synthetic", text: "plugin notice" },
      { type: "user", text: "Test the site" },
      {
        type: "assistant",
        content: [
          { type: "reasoning", text: "hidden" },
          { type: "text", text: "I need curl." },
          { type: "tool", state: { status: "completed", content: "secret output" } },
        ],
      },
      { type: "user", text: "Continue" },
    ])
    expect(result.currentUserInput).toBe("Continue")
    expect(result.recentContext).toEqual([
      { role: "user", text: "Test the site" },
      { role: "assistant", text: "I need curl." },
      { role: "user", text: "Continue" },
    ])
  })

  test("bounds message count and individual length", () => {
    const messages = Array.from({ length: 20 }, (_, index) => ({ type: "user", text: `${index}:${"x".repeat(9000)}` }))
    const result = escalationContextFromMessages(messages)
    expect(result.recentContext).toHaveLength(6)
    expect(result.recentContext.every((item) => item.text.length <= 4000)).toBe(true)
    expect(result.recentContext.reduce((sum, item) => sum + item.text.length, 0)).toBeLessThanOrEqual(24000)
    expect(result.currentUserInput.length).toBe(8000)
    expect(result.recentUserInputs).toHaveLength(5)
  })

  test("retains five user turns independently of assistant chatter", () => {
    const messages: unknown[] = [{ type: "user", text: "old request" }]
    for (let index = 0; index < 5; index++) {
      messages.push({ type: "user", text: `task ${index}` })
      for (let reply = 0; reply < 4; reply++) {
        messages.push({ type: "assistant", content: [{ type: "text", text: `step ${index}.${reply}` }] })
      }
    }
    const result = escalationContextFromMessages(messages)
    expect(result.recentUserInputs).toEqual(["task 0", "task 1", "task 2", "task 3", "task 4"])
    expect(result.recentContext).toHaveLength(16)
    expect(result.currentUserInput).toBe("task 4")
  })

  test("preserves trailing user restrictions when a message must be clipped", () => {
    const result = escalationContextFromMessages([
      { type: "user", text: `Install the dependency. ${"x".repeat(10000)} Do not delete my database.` },
    ])
    expect(result.currentUserInput.startsWith("Install the dependency.")).toBe(true)
    expect(result.currentUserInput.endsWith("Do not delete my database.")).toBe(true)
    expect(result.recentContext[0].text.endsWith("Do not delete my database.")).toBe(true)
    expect(result.currentUserInput).toContain("[context truncated]")
  })
})

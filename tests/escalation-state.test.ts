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
    const messages = Array.from({ length: 10 }, (_, index) => ({ type: "user", text: `${index}:${"x".repeat(900)}` }))
    const result = escalationContextFromMessages(messages)
    expect(result.recentContext).toHaveLength(6)
    expect(result.recentContext.every((item) => item.text.length <= 600)).toBe(true)
    expect(result.currentUserInput.length).toBe(600)
  })
})

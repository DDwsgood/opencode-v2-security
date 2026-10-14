import { expect, test } from "bun:test"
import { runtimeBlockedText, runtimeBoundaryTrigger } from "../src/agent-messages"
import type { RuntimeBoundaryEvent } from "../src/runtime-boundary"

test("runtimeBlockedText: all boundary phases use the same stopped outcome without exposing argv", () => {
  for (const atExit of [false, true, undefined]) {
    const event: RuntimeBoundaryEvent = {
      version: 1, type: "boundary", eventID: 1, pid: 123,
      syscall: "openat", kind: "write", operation: "open",
      targets: [{ path: "/home/user/.ssh/id_rsa", domain: "linux", exists: true }],
      details: { atExit, flags: "0x241", argv: ["python3", "secret-argument"] },
    }
    const text = runtimeBlockedText("Write protection: the target is protected", { trigger: runtimeBoundaryTrigger(event) })
    expect(text).toContain("Trigger: open for truncation (openat) on [credential path]")
    expect(text).toContain("The command was stopped.")
    expect(text).not.toMatch(/was not performed|earlier steps|rolled back|secret-argument|id_rsa/)
    expect(text).toContain("Report this block to the user.")
    expect(text).toContain("Do not automatically rerun.")
  }
})

test("runtimeBlockedText: non-boundary stops do not manufacture a trigger", () => {
  for (const reason of ["the broker channel closed (command cancelled)",
                        "the boundary review did not complete",
                        "the session's security mode or authorization changed while the command was running"]) {
    const text = runtimeBlockedText(reason)
    expect(text).toContain("The command was stopped")
    expect(text).not.toContain("was not performed")
    expect(text).not.toContain("Trigger:")
  }
})

import { expect, test } from "bun:test"
import { CANCEL_ADVICE, cancelledText, runtimeBlockedText, runtimeBoundaryTrigger } from "../src/agent-messages"
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

test("runtimeBlockedText: a cancelled run is never framed as a refusal", () => {
  for (const details of [{ cancelled: true }, { cancelled: true, advice: CANCEL_ADVICE }]) {
    const text = runtimeBlockedText("Cancellation: the call was cancelled", details)
    expect(text).toStartWith("Command cancelled.")
    expect(text).toContain("this is not a security denial")
    expect(text).not.toContain("Command blocked")
    expect(text).not.toContain("stopped")
    expect(text).not.toContain("Do not automatically rerun")
    expect(text).not.toContain("Do not restart")
    expect(text).not.toContain("was not performed")
  }
})

test("cancelledText: a pre-launch cancellation carries no refusal or retry protocol", () => {
  const text = cancelledText()
  expect(text).toContain("Command cancelled before launch.")
  expect(text).toContain("The whole command was not run.")
  expect(text).not.toContain("Command blocked")
  expect(text).not.toContain("stopped")
  expect(text).not.toContain("Do not automatically rerun")
  expect(text).not.toContain("Do not restart")
})

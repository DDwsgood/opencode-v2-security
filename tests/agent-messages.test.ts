import { expect, test } from "bun:test"
import { runtimeBlockedText } from "../src/agent-messages"

// Only an explicit entry-gate refusal may promise the boundary operation
// did not run; exit-side checks, running cancels and unknown phases must
// all say the command was stopped.
test("runtimeBlockedText: entry phase claims the op was not performed", () => {
  const text = runtimeBlockedText("the target path is denied", true)
  expect(text).toContain("Command blocked:")
  expect(text).toContain("was not performed")
  expect(text).toContain("Do not repeat")
})

test("runtimeBlockedText: non-entry phases only claim the command stopped", () => {
  for (const reason of ["the broker channel closed (command cancelled)",
                        "the boundary review did not complete",
                        "the session's security mode or authorization changed while the command was running"]) {
    const text = runtimeBlockedText(reason, false)
    expect(text).toContain("The command was stopped")
    expect(text).not.toContain("was not performed")
    expect(text).toContain("earlier steps")
  }
})

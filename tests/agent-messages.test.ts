import { expect, test } from "bun:test"
import {
  actionBeforeText,
  actionBlockedText,
  blockedText,
  CANCEL_ADVICE,
  cancelledText,
  isReviewerDenial,
  NO_REROUTE,
  RECHECK,
  reviewRefusal,
  runtimeBlockedText,
  runtimeBoundaryTrigger,
  slowCommandText,
} from "../src/agent-messages"
import type { RuntimeBoundaryEvent } from "../src/runtime-boundary"
import { EFFECTS_POLICY_VERSION, type EffectReviewResult } from "../src/security/effects-reviewer"

test("runtimeBlockedText: reviewDenied uses Command blocked while default runtime stops use Command failed", () => {
  for (const atExit of [false, true, undefined]) {
    const event: RuntimeBoundaryEvent = {
      version: 1, type: "boundary", eventID: 1, pid: 123,
      syscall: "openat", kind: "write", operation: "open",
      targets: [{ path: "/home/user/.ssh/id_rsa", domain: "linux", exists: true }],
      details: { atExit, flags: "0x241", argv: ["python3", "secret-argument"] },
    }
    const denied = runtimeBlockedText("Command review: unsafe effect", {
      trigger: runtimeBoundaryTrigger(event),
      reviewDenied: true,
    })
    expect(denied).toStartWith("[opencode-v2-security] Command blocked: runtime check.")
    expect(denied).toContain("Trigger: open for truncation (openat) on [credential path]")
    expect(denied).toContain("The command was stopped while running; execution may be partial and nothing was rolled back.")
    expect(denied).not.toMatch(/was not performed|secret-argument|id_rsa/)
    expect(denied).toContain("Do not bypass this denial. Skip the step or report this block to the user.")
    expect(denied).not.toContain("Do not automatically rerun.")

    const failed = runtimeBlockedText("Write protection: the target is protected", {
      trigger: runtimeBoundaryTrigger(event),
    })
    expect(failed).toStartWith("[opencode-v2-security] Command failed: runtime check.")
    expect(failed).not.toMatch(/Command blocked|Command denied|Do not automatically rerun|bypass this denial/)
  }
})

test("runtimeBlockedText: non-boundary stops do not manufacture a trigger or security denial", () => {
  for (const reason of ["the broker channel closed (command cancelled)",
                        "the boundary review did not complete",
                        "the session's security mode or authorization changed while the command was running"]) {
    const text = runtimeBlockedText(reason)
    expect(text).toStartWith("[opencode-v2-security] Command failed: runtime check.")
    expect(text).toContain("The command was stopped while running; execution may be partial and nothing was rolled back.")
    expect(text).not.toContain("was not performed")
    expect(text).not.toContain("Trigger:")
    expect(text).not.toMatch(/Command blocked|Do not automatically rerun|bypass this denial/)
  }
})

test("runtimeBlockedText: a cancelled run is never framed as a refusal", () => {
  for (const details of [{ cancelled: true }, { cancelled: true, advice: CANCEL_ADVICE }]) {
    const text = runtimeBlockedText("Cancellation: the call was cancelled", details)
    expect(text).toStartWith("[opencode-v2-security] Command failed: cancelled.")
    expect(text).toContain("this is not a security denial")
    expect(text).not.toContain("Command blocked")
    expect(text).not.toContain("stopped")
    expect(text).not.toContain("Do not automatically rerun")
    expect(text).not.toContain("Do not restart")
    expect(text).not.toContain("was not performed")
  }
})

test("cancelledText and pre-launch helpers keep Command failed and strip anti-reroute advice", () => {
  const text = cancelledText()
  expect(text).toStartWith("[opencode-v2-security] Command failed: cancelled before launch.")
  expect(text).toContain("The whole command was not run.")
  expect(text).not.toMatch(/Command blocked|stopped|Do not automatically rerun|Do not restart/)

  for (const preflight of [
    blockedText("static restriction", NO_REROUTE),
    actionBeforeText("review refusal", "native write", NO_REROUTE),
    actionBlockedText("permission changed", NO_REROUTE),
  ]) {
    expect(preflight).toStartWith("[opencode-v2-security] Command failed")
    expect(preflight).not.toMatch(/Command blocked|Command denied|bypass this denial|Do not automatically rerun/)
  }
  const slow = slowCommandText("sleep exceeds threshold")
  expect(slow).toStartWith("[opencode-v2-security] Command blocked as it seems to be slow and unnecessary.")
  expect(slow).toContain("not a security denial")
})

test("isReviewerDenial and reviewRefusal distinguish confirmed denials from unclear or evidence limits", () => {
  const base = {
    decision: "deny",
    floor: "no",
    coverage: "uncovered",
    gapReach: "no_blocking_gap",
    uncoveredOwner: "none",
    severity: {} as EffectReviewResult["severity"],
    answers: {},
    policyVersion: EFFECTS_POLICY_VERSION,
    source: "effect",
  } satisfies EffectReviewResult

  expect(isReviewerDenial(base)).toBe(true)
  expect(reviewRefusal(base).reason).toContain("risk category not determined: the command contains effects that are unsafe or unauthorized")
  expect(reviewRefusal({ ...base, severity: { filesystem: 0.39 } as EffectReviewResult["severity"] }).reason).toContain("risk category not determined")
  for (const probability of [0.4, 0.49, 0.8]) {
    expect(reviewRefusal({ ...base, severity: { filesystem: probability } as EffectReviewResult["severity"] }).reason).toContain("local durable content")
  }
  expect(reviewRefusal({ ...base, severity: { filesystem: 0.4, secret: 0.49 } as EffectReviewResult["severity"] }).reason).toContain("multiple effect categories")
  const effectDenial = { ...base, floor: "unclear" as const }
  const refusal = reviewRefusal(effectDenial)
  expect(refusal.reason).toContain("effects that are unsafe or unauthorized")
  const notice = runtimeBlockedText(refusal.reason, { reviewDenied: isReviewerDenial(effectDenial), advice: RECHECK })
  expect(notice).toContain(NO_REROUTE)
  expect(notice).not.toContain("then retry")
  for (const preflight of [
    blockedText(refusal.reason, RECHECK, true),
    actionBeforeText(refusal.reason, "native write", RECHECK, true),
  ]) {
    expect(preflight).toStartWith("[opencode-v2-security] Command blocked:")
    expect(preflight).toContain(NO_REROUTE)
    expect(preflight).not.toContain("then retry")
  }
  expect(isReviewerDenial({ ...base, source: "evidence_limit" })).toBe(false)
  expect(isReviewerDenial({ ...base, decision: "collect_evidence", floor: "unclear", source: "evidence" })).toBe(false)
  expect(isReviewerDenial({ ...base, source: "readonly", answers: { readonly_conformance: { choice: "unclear" } } })).toBe(false)
  expect(isReviewerDenial({ ...base, source: "readonly", answers: { readonly_conformance: { choice: "writes" } } })).toBe(true)
})

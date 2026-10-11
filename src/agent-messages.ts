import type { EffectReviewResult } from "./security/effects-reviewer"

export const NO_REROUTE = "Do not repeat the same effect through another tool, script, or wrapper."
export const RECHECK = "You may submit it again; it will be checked under the current state."
export const RETRY_LATER = "You may retry it later."
export const WITHIN_MODE = "Continue with work that this mode allows."

function sentence(reason: string): string {
  return reason.trim().replace(/\s+/g, " ").replace(/[.!?]+$/, "") || "the security check failed"
}

/** Only for refusals before the original operation starts. */
export function blockedText(reason: string, advice?: string): string {
  return `Command blocked: ${sentence(reason)}. The whole command was not run.${advice ? ` ${advice}` : ""}`
}

/** A later permission gate cannot prove that earlier tool steps did not run. */
export function actionBlockedText(reason: string): string {
  return `Action blocked: ${sentence(reason)}. This action was not performed; earlier steps of the same tool call may already have run.`
}

/** Runtime observation happens after the command started. Never claim that
 *  its earlier in-boundary steps did not run, and never replay the command.
 *  opNotPerformed must be true ONLY for entry-gate denials — an exit-side
 *  check (recvmsg cmsg), a cancel or a review failure must not claim the
 *  audited operation never happened. */
export function runtimeBlockedText(reason: string, opNotPerformed = true): string {
  const text = reason.trim().replace(/[.\s]+$/, "")
  const outcome = opNotPerformed
    ? "The blocked boundary operation was not performed"
    : "The command was stopped"
  return `Command blocked: ${text}. ${outcome}; earlier steps of this command may already have run. ${NO_REROUTE}`
}

export function subagentBlockedText(reason: string): string {
  return `Subagent call blocked: ${sentence(reason)}. The subagent was not started or resumed.`
}

export function permissionChangeRejectedText(reason: string): string {
  return `Permission change rejected: ${sentence(reason)}. Nothing was changed.`
}

export function reviewRefusal(result: EffectReviewResult): { reason: string; advice?: string } {
  if (result.source === "readonly") {
    return {
      reason: result.answers.readonly_conformance?.choice === "writes"
        ? "this session is in [Read only] mode and the review found the operation performs a write — user authorization cannot make a write acceptable in this mode"
        : "this session is in [Read only] mode and the review could not confirm the operation is free of writes",
      advice: WITHIN_MODE,
    }
  }
  if (result.floor === "yes") return {
    reason: "the safety review found a severe risk that no authorization in this session covers",
    advice: NO_REROUTE,
  }
  if (result.floor === "unclear") return {
    reason: "the safety review could not rule out a severe risk, even after checking local evidence",
    advice: NO_REROUTE,
  }
  if (result.source === "evidence_limit") return {
    reason: "the safety review needed facts it could not collect, and this setup blocks unresolved commands. This is not a risk judgment",
  }
  return {
    reason: "the safety review found effects that the user's request and authorizations do not cover",
    advice: NO_REROUTE,
  }
}

export function reviewUnavailableReason(kind: string): string {
  return `the safety review was unavailable (${kind} error), so the command could not be approved. This is not a judgment about the command`
}

export function accessErrorNote(hostDirect: boolean): string {
  return hostDirect
    ? "Note: this command ran directly on the host, and its output shows an operating-system access error. This is an OS result, not a plugin block. The plugin did not retry the command."
    : "Note: this call was launched through the plugin's OS sandbox because this session is in [Read only] mode, and its output shows an access error. The sandbox blocks writes in this mode. The plugin did not retry the command."
}

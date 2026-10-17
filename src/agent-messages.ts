import type { EffectReviewResult } from "./security/effects-reviewer"
import { observedNetworkEndpoint } from "./security/approval-cache"
import { embeddedCredentialFinding } from "./security/paths"
import type { RuntimeBoundaryEvent } from "./runtime-boundary"
import type { FileBoundaryPlan, NativeBoundaryTool } from "./tool-boundary"

export const REPORT_BLOCK = "Report this block to the user."
export const NO_REROUTE = "Do not bypass this denial. Skip the step or report this block to the user."
export const RECHECK = "Re-check the current session permissions, authorization, and any partial effects, then retry."
export const RETRY_LATER = "Restore or wait for the required check service, then retry."
export const WITHIN_MODE = "Continue with actions allowed by the current session mode and configured limits."
export const SLOW_COMMAND_ADVICE = "This is a slow-command check, not a security denial. Narrow the scope, set a reasonable timeout, or run in the background if the user needs a long-running command."
/** Cancellation is not a refusal: the same abort signal covers a user
 *  interrupt and a host deadline, so the notice neither frames a denial nor
 *  forbids a retry. */
export const CANCEL_ADVICE = "Tell the user the run was cancelled; this is not a security denial."

export type RuntimeBlockDetails = {
  trigger?: string
  advice?: string
  cancelled?: boolean
  reviewDenied?: boolean
}

function sentence(reason: string): string {
  return reason.trim().replace(/\s+/g, " ").replace(/[.!?]+$/, "") || "the security check failed"
}

function nonDenialAdvice(advice?: string, fallback = WITHIN_MODE): string {
  if (!advice || advice === NO_REROUTE) return fallback
  return advice
}

/** Only for pre-launch failures before the original operation starts. */
export function blockedText(reason: string, advice?: string): string {
  return `[opencode-v2-security] Command failed: before launch.\n${sentence(reason)}.\nThe whole command was not run.\n${nonDenialAdvice(advice)}`
}

export function slowCommandText(reason: string): string {
  return `[opencode-v2-security] Command blocked as it seems to be slow and unnecessary.\n${sentence(reason)}.\nThe whole command was not run.\n${SLOW_COMMAND_ADVICE}`
}

/** A later permission gate cannot prove that earlier tool steps did not run. */
export function actionBlockedText(reason: string, advice?: string): string {
  return `[opencode-v2-security] Command failed.\n${sentence(reason)}.\nThis action was not performed; earlier steps of this tool call may already have run. Nothing was rolled back.\n${nonDenialAdvice(advice, RECHECK)}`
}

export function actionBeforeText(reason: string, action: string, advice?: string): string {
  return `[opencode-v2-security] Command failed: before execution (${action}).\n${sentence(reason)}.\nThis action was not performed.\n${nonDenialAdvice(advice)}`
}

function diagnosticPath(target: string): string {
  if (embeddedCredentialFinding(target)) return "[credential path]"
  return JSON.stringify(target.slice(0, 256))
}

export function nativeActionTrigger(tool: NativeBoundaryTool, plan: FileBoundaryPlan): string {
  const targets = plan.targets.slice(0, 2).map((item) => diagnosticPath(item.resolved))
  let action = `native ${tool}`
  if (targets.length > 0) action += ` on ${targets.join(", ")}`
  if (plan.targets.length > 2) action += ` (+${plan.targets.length - 2} targets)`
  return action
}

/** All runtime stop phases use the same partial-execution outcome. Only a
 *  confirmed dynamic review denial uses `Command blocked` and anti-reroute
 *  guidance; other stops (ceiling, permission change, check failure,
 *  evidence limit, cancellation) use `Command failed`. */
export function runtimeBlockedText(reason: string, details: RuntimeBlockDetails = {}): string {
  const trigger = details.trigger ? `\nTrigger: ${details.trigger}.` : ""
  if (details.cancelled) {
    const advice = nonDenialAdvice(details.advice, CANCEL_ADVICE)
    return `[opencode-v2-security] Command failed: cancelled.${trigger}\n${sentence(reason)}.\nThe run was cancelled before it finished; execution may be partial and nothing was rolled back, and this is not a security denial.\n${advice}`
  }
  if (details.reviewDenied) {
    return `[opencode-v2-security] Command blocked: runtime check.${trigger}\n${sentence(reason)}.\nThe command was stopped while running; execution may be partial and nothing was rolled back.\n${NO_REROUTE}`
  }
  const advice = nonDenialAdvice(details.advice, RECHECK)
  return `[opencode-v2-security] Command failed: runtime check.${trigger}\n${sentence(reason)}.\nThe command was stopped while running; execution may be partial and nothing was rolled back.\n${advice}`
}

export function cancelledText(): string {
  return `[opencode-v2-security] Command failed: cancelled before launch.\nThe whole command was not run.\n${CANCEL_ADVICE}`
}

/** Do not expose argv, command bodies, credential filenames or arbitrary
 *  details. Quoted, bounded ordinary paths are data, never instructions. */
export function runtimeBoundaryTrigger(event: RuntimeBoundaryEvent): string {
  let effect = event.operation.replace(/[_-]/g, " ")
  if (["open", "openat", "openat2"].includes(event.syscall)) {
    effect = "open"
    const flags = typeof event.details.flags === "string" && /^0x[0-9a-f]+$/i.test(event.details.flags)
      ? Number.parseInt(event.details.flags.slice(2), 16) : undefined
    if (flags !== undefined) {
      if (flags & 0o1000) effect = "open for truncation"
      else if ((flags & 3) !== 0) effect = "open for writing"
    }
  } else if (event.syscall === "creat") {
    effect = "open for truncation"
  } else if (["truncate", "ftruncate"].includes(event.syscall)) {
    effect = "truncate"
  }
  let target = ""
  if (event.targets.length > 0) {
    const targets = event.targets.slice(0, 2).map((item) => diagnosticPath(item.path))
    target = ` on ${targets.join(", ")}`
    if (event.targets.length > 2) target += ` (+${event.targets.length - 2} targets)`
  } else if (event.kind === "network") {
    const endpoint = observedNetworkEndpoint(event.details)
    if (endpoint) {
      const host = endpoint.family === "AF_INET6" ? `[${endpoint.host}]` : endpoint.host
      target = ` on ${host}:${endpoint.port}`
    }
  }
  return `${effect} (${event.syscall})${target}`
}

export function subagentBlockedText(reason: string): string {
  return `[opencode-v2-security] Command failed: subagent call.\n${sentence(reason)}.\nThe subagent was not started or resumed.\n${WITHIN_MODE}`
}

export function permissionChangeRejectedText(reason: string): string {
  return `[opencode-v2-security] Command failed: Permission change rejected: ${sentence(reason)}. Nothing was changed. ${WITHIN_MODE}`
}

const REVIEW_CATEGORIES: Record<string, string> = {
  filesystem: "local durable content",
  secret: "credential or confidential-data exposure",
  host: "host operational integrity",
  privilege: "access or trust boundaries",
  network: "network traffic or connectivity",
  remote: "remote or shared-state effects",
  multiple: "multiple effect categories",
}

export function isReviewerDenial(result: EffectReviewResult): boolean {
  if (result.decision !== "deny") return false
  if (result.source === "readonly") {
    return result.floor === "yes" || result.answers.readonly_conformance?.choice === "writes"
  }
  return result.source === "floor" || result.source === "effect"
}

export function reviewRefusal(result: EffectReviewResult): { reason: string; advice?: string } {
  if (result.source === "readonly" && result.answers.readonly_conformance?.choice === "writes") {
    return {
      reason: "Command review — read-only limit: the review found writes outside this mode's allowance",
      advice: WITHIN_MODE,
    }
  }
  if (result.floor === "yes") return {
    reason: "Command review — safety floor: the review found a severe risk that session authorization cannot waive",
    advice: WITHIN_MODE,
  }
  if (result.source === "readonly") {
    return {
      reason: "Command review — read-only check incomplete: the review could not confirm read-only conformance from the available evidence; this is not a confirmed write or security denial",
      advice: RECHECK,
    }
  }
  if (result.floor === "unclear" && !isReviewerDenial(result)) return {
    reason: "Command review — safety floor: the review could not rule out a severe risk from the available evidence; this is not a confirmed security denial",
    advice: RECHECK,
  }
  if (result.source === "evidence_limit" || result.decision === "collect_evidence") return {
    reason: "Command review — evidence limit: required facts remained unavailable; policy requires resolved checks. This is not a safety verdict",
    advice: RECHECK,
  }
  const category = REVIEW_CATEGORIES[result.uncoveredOwner] ?? "risk category not determined"
  return {
    reason: `Command review - ${category}: the command contains effects that are unsafe or unauthorized`,
    advice: NO_REROUTE,
  }
}

export function reviewUnavailableReason(kind: string): string {
  return checkUnavailableReason(`review_${kind}`)
}

export function checkUnavailableReason(code: string): string {
  let reason = "the security check failed internally"
  if (code === "review_protocol") reason = "the review response could not be validated"
  else if (code.startsWith("review_")) reason = "the review service was unavailable"
  else if (code.startsWith("broker_") || code.startsWith("observer_")) reason = "the runtime boundary check could not complete"
  else if (code === "session_context" || code === "session_workspace") reason = "the session's authorization context was unavailable"
  else if (code === "target_changed") reason = "the target changed before verification completed"
  else if (code === "target_inspection" || code === "boundary_inspection") reason = "the target evidence could not be inspected"
  return `Check unavailable (${code}): ${reason}. Policy requires completed checks; this is not a safety verdict`
}

export function accessErrorNote(hostDirect: boolean): string {
  return hostDirect
    ? `[opencode-v2-security] Command failed: OS access error, not a reviewer denial. The command ran; execution may be partial and nothing was rolled back. The plugin did not retry it. ${RECHECK}`
    : `[opencode-v2-security] Command failed: OS access error while the command was running, not a reviewer denial. Execution may be partial and nothing was rolled back. The plugin did not retry it. ${RECHECK}`
}

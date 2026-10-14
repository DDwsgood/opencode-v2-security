import type { EffectReviewResult } from "./security/effects-reviewer"
import { observedNetworkEndpoint } from "./security/approval-cache"
import { embeddedCredentialFinding } from "./security/paths"
import type { RuntimeBoundaryEvent } from "./runtime-boundary"
import type { FileBoundaryPlan, NativeBoundaryTool } from "./tool-boundary"

export const REPORT_BLOCK = "Report this block to the user."
export const NO_REROUTE = `${REPORT_BLOCK} Do not bypass this denial through another tool or wrapper. Any revised request requires a fresh check.`
export const RECHECK = `${REPORT_BLOCK} Any resubmission requires a fresh check under the current permissions.`
export const RETRY_LATER = `${REPORT_BLOCK} Retry only after the check is available.`
export const WITHIN_MODE = `${REPORT_BLOCK} Do not bypass this limit. Continue only with actions allowed by the current mode and safety rules.`
export const CANCEL_ADVICE = `${REPORT_BLOCK} Do not restart without a new user instruction.`

export type RuntimeBlockDetails = {
  trigger?: string
  advice?: string
  cancelled?: boolean
}

function sentence(reason: string): string {
  return reason.trim().replace(/\s+/g, " ").replace(/[.!?]+$/, "") || "the security check failed"
}

/** Only for refusals before the original operation starts. */
export function blockedText(reason: string, advice?: string): string {
  return `Command blocked: before launch.\n${sentence(reason)}.\nThe whole command was not run.\n${advice ?? NO_REROUTE}`
}

/** A later permission gate cannot prove that earlier tool steps did not run. */
export function actionBlockedText(reason: string, advice = NO_REROUTE): string {
  return `Action blocked.\n${sentence(reason)}.\nThis action was not performed; earlier steps of this tool call may already have run. Nothing was rolled back.\n${advice}`
}

export function actionBeforeText(reason: string, action: string, advice = NO_REROUTE): string {
  return `Action blocked before execution: ${action}.\n${sentence(reason)}.\nThis action was not performed.\n${advice}`
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

/** All runtime phases use the same outcome. The trigger is an observation,
 *  not a claim that this effect alone caused the whole-command verdict. */
export function runtimeBlockedText(reason: string, details: RuntimeBlockDetails = {}): string {
  const heading = details.cancelled ? "Command cancelled." : "Command blocked: runtime check."
  const trigger = details.trigger ? `\nTrigger: ${details.trigger}.` : ""
  const advice = details.advice ?? NO_REROUTE
  return `${heading}${trigger}\n${sentence(reason)}.\nThe command was stopped.\nDo not automatically rerun. ${advice}`
}

export function cancelledText(): string {
  return `Command cancelled before launch.\nThe whole command was not run.\n${CANCEL_ADVICE}`
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
  return `Subagent call blocked.\n${sentence(reason)}.\nThe subagent was not started or resumed.\n${NO_REROUTE}`
}

export function permissionChangeRejectedText(reason: string): string {
  return `Permission change rejected: ${sentence(reason)}. Nothing was changed. ${REPORT_BLOCK}`
}

const REVIEW_CATEGORIES: Record<string, string> = {
  filesystem: "local durable content",
  secret: "credential or confidential-data exposure",
  host: "host operational integrity",
  privilege: "access or trust boundaries",
  network: "network traffic or connectivity",
  remote: "remote or shared-state effects",
  multiple: "multiple effect categories",
  none: "unclassified material effects",
}

export function reviewRefusal(result: EffectReviewResult): { reason: string; advice?: string } {
  if (result.source === "readonly") {
    return {
      reason: result.answers.readonly_conformance?.choice === "writes"
        ? "Command review — read-only limit: the review found writes outside this mode's allowance"
        : "Command review — read-only limit: the review could not confirm read-only conformance",
      advice: WITHIN_MODE,
    }
  }
  if (result.floor === "yes") return {
    reason: "Command review — safety floor: the review found a severe risk that session authorization cannot waive",
    advice: WITHIN_MODE,
  }
  if (result.floor === "unclear") return {
    reason: "Command review — safety floor: the review could not rule out a severe risk after the available checks",
    advice: WITHIN_MODE,
  }
  if (result.source === "evidence_limit") return {
    reason: "Command review — evidence limit: required facts remained unavailable; policy blocks unresolved checks. This is not a safety verdict",
    advice: RECHECK,
  }
  return {
    reason: `Command review - ${REVIEW_CATEGORIES[result.uncoveredOwner] ?? "unclassified material effects"}: the commands contains effects that is unsafe or unauthorized`,
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
  return `Check unavailable (${code}): ${reason}. Policy blocks incomplete checks; this is not a safety verdict`
}

export function accessErrorNote(hostDirect: boolean): string {
  return hostDirect
    ? "OS access error, not a plugin block. The command ran; execution may be partial. The plugin did not retry it."
    : "Access error while running in the read-only OS sandbox, which restricts writes. Execution may be partial. The plugin did not retry it."
}

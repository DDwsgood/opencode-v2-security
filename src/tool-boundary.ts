import { lstat, readlink, realpath, stat } from "node:fs/promises"
import { homedir } from "node:os"
import path from "node:path"
import { classifyPathTarget, embeddedCredentialFinding, extractReadPaths, extractWriteTargets } from "./security/paths"
import { ruleRequiredCategories } from "./security/bypass"
import { splitSimpleSegments } from "./security/classifier"
import { scan } from "./security/shell-scan"
import { inspectionErrorCode, isMissingPathError } from "./security/inspection"

export const NATIVE_BOUNDARY_TOOLS = new Set(["shell", "write", "edit", "patch", "read", "glob", "grep"])
export type NativeBoundaryTool = "shell" | "write" | "edit" | "patch" | "read" | "glob" | "grep"

/** Typed preflight failures keep invalid input/context drift separate from
 * unexpected internal failures, without exposing supplied private values. */
export class BoundaryPreparationError extends Error {
  constructor(message: string, readonly agentReason: string, readonly changed = false) {
    super(message)
    this.name = "BoundaryPreparationError"
  }
}

/** Routing policy, not a claim that the host supplies immutable producer identity. */
export function isBoundaryTool(
  tool: { id?: string; name?: string; options?: Record<string, unknown> },
  platform: string = process.platform,
): boolean {
  return platform === "linux" &&
    typeof tool.name === "string" && NATIVE_BOUNDARY_TOOLS.has(tool.name) &&
    tool.id === tool.name && tool.options?.codemode === false && tool.options.namespace === undefined
}

export interface BoundaryInvocation {
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
}

type FileMode = "read" | "write" | "delete"
type Identity = { dev: number; ino: number; size: number; mtimeMs: number }
export interface BoundaryFileTarget {
  mode: FileMode
  absolute: string
  resolved: string
  identity?: Identity
  inspectionError?: string
}
export interface FileBoundaryPlan {
  tool: Exclude<NativeBoundaryTool, "shell">
  /** A factual native-tool input record. It is deliberately not shell source. */
  command: string
  targets: BoundaryFileTarget[]
  resolvedWrites: string[]
  outsideWrites: string[]
  facts: string[]
  verdict: "ALLOW" | "ASK"
  /** Native glob/grep permission resources are patterns, not file paths. */
  searchPattern?: string
}

export function containsPath(root: string, target: string): boolean {
  const relative = path.relative(root, target)
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
}

export function nativeAbsolutePath(cwd: string, value: string): string {
  if (!value || value.includes("\0")) throw new BoundaryPreparationError("Invalid native-tool path", "the target path is empty or contains an invalid NUL character")
  const expanded = value === "~" ? homedir() : value.startsWith("~/") ? path.join(homedir(), value.slice(2)) : value
  return path.resolve(cwd, expanded)
}

/** Resolve missing leaves through their existing parents, including dangling symlinks. */
export async function canonicalBoundaryPath(absolute: string, depth = 0): Promise<string> {
  if (depth > 64) throw new BoundaryPreparationError("Native-tool path has an unresolved symlink chain", "a target path has a symbolic-link chain that cannot be resolved reliably")
  try {
    return await realpath(absolute)
  } catch (error) {
    if (error instanceof BoundaryPreparationError) throw error
    if (!isMissingPathError(error)) {
      throw new BoundaryPreparationError("Native-tool path inspection is unavailable", `the target path could not be resolved for inspection (${inspectionErrorCode(error)})`)
    }
    const leaf = await lstat(absolute).catch((failure: unknown) => {
      if (isMissingPathError(failure)) return undefined
      throw new BoundaryPreparationError("Native-tool path inspection is unavailable", `the target path metadata could not be inspected (${inspectionErrorCode(failure)})`)
    })
    if (leaf?.isSymbolicLink()) {
      const destination = await readlink(absolute).catch((failure: unknown) => {
        throw new BoundaryPreparationError("Native-tool link inspection is unavailable", `a symbolic-link target could not be inspected (${inspectionErrorCode(failure)})`)
      })
      return canonicalBoundaryPath(path.resolve(path.dirname(absolute), destination), depth + 1)
    }
    const parent = path.dirname(absolute)
    if (parent === absolute) throw new BoundaryPreparationError("Native-tool path inspection is unavailable", "the target path has no inspectable filesystem root")
    return path.join(await canonicalBoundaryPath(parent, depth + 1), path.basename(absolute))
  }
}

function patchTargets(text: string): Array<{ value: string; mode: FileMode }> {
  const trimmed = text.trim()
  // The host parser accepts this legacy envelope as patch data, not a shell.
  const body = trimmed.match(/^(?:cat\s+)?<<(['"]?)(\w+)\1\s*\n([\s\S]*?)\n\2\s*$/)?.[3] ?? trimmed
  const lines = body.split(/\r?\n/)
  if (lines[0]?.trim() !== "*** Begin Patch" || lines.at(-1)?.trim() !== "*** End Patch") {
    throw new BoundaryPreparationError("Invalid native patch boundary", "the patch input has no valid begin/end envelope")
  }
  const targets: Array<{ value: string; mode: FileMode }> = []
  for (let index = 1; index < lines.length - 1; index += 1) {
    const header = lines[index]!.trim()
    const match = /^\*\*\* (Add|Update|Delete) File: (.+)$/.exec(header)
    if (!match) continue
    const value = match[2]!.trim()
    const kind = match[1]!
    targets.push({ value, mode: kind === "Delete" ? "delete" : "write" })
    if (kind === "Update") {
      let nextIndex = index + 1
      while (lines[nextIndex]?.trimEnd() === "*** End of File") nextIndex += 1
      const next = lines[nextIndex]?.trimEnd()
      if (next === "*** Move to:" || next?.startsWith("*** Move to: ")) {
        const destination = next.slice("*** Move to:".length).trim()
        if (!destination) throw new BoundaryPreparationError("Invalid native patch move target", "the patch move destination is empty")
        // Move removes the old object as well as writing the destination.
        targets.push({ value, mode: "delete" }, { value: destination, mode: "write" })
        index = nextIndex
      }
    }
  }
  if (targets.length === 0) throw new BoundaryPreparationError("Native patch has no file targets", "the patch input has no file targets")
  return targets
}

async function targetIdentity(resolved: string, noFollow = false): Promise<Identity | undefined> {
  try {
    const info = await (noFollow ? lstat(resolved) : stat(resolved))
    return { dev: info.dev, ino: info.ino, size: info.size, mtimeMs: info.mtimeMs }
  } catch (error) {
    if (isMissingPathError(error)) return undefined
    throw new BoundaryPreparationError("Native-tool object inspection is unavailable", `the target object identity could not be inspected (${inspectionErrorCode(error)})`)
  }
}

async function inspectBoundaryTarget(absolute: string, mode: FileMode): Promise<BoundaryFileTarget> {
  let resolved = absolute
  try {
    resolved = mode === "delete"
      ? path.join(await canonicalBoundaryPath(path.dirname(absolute)), path.basename(absolute))
      : await canonicalBoundaryPath(absolute)
    const identity = await targetIdentity(resolved, mode === "delete")
    return { mode, absolute, resolved, ...(identity ? { identity } : {}) }
  } catch (error) {
    if (!(error instanceof BoundaryPreparationError)) throw error
    return { mode, absolute, resolved, inspectionError: error.agentReason }
  }
}

export async function planFileBoundary(
  tool: Exclude<NativeBoundaryTool, "shell">,
  input: unknown,
  options: { cwd: string; writableRoots: readonly string[]; bypassCategories?: ReadonlySet<string> },
): Promise<FileBoundaryPlan> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new BoundaryPreparationError("Invalid native-tool input", "the native tool input must be an object")
  const args = input as Record<string, unknown>
  if ((tool === "glob" || tool === "grep") && typeof args.pattern !== "string") {
    throw new BoundaryPreparationError(`Native ${tool} requires a pattern`, `the native ${tool} input requires a search pattern`)
  }
  let requested: Array<{ value: string; mode: FileMode }>
  if (tool === "patch") {
    if (typeof args.patchText !== "string") throw new BoundaryPreparationError("Native patch requires patchText", "the patch input requires patchText")
    requested = patchTargets(args.patchText)
  } else {
    const value = args.path ?? ((tool === "glob" || tool === "grep") ? "." : undefined)
    if (typeof value !== "string") throw new BoundaryPreparationError(`Native ${tool} requires a path`, `the native ${tool} input requires a target path`)
    requested = [{ value, mode: tool === "write" || tool === "edit" ? "write" : "read" }]
  }
  const targets: BoundaryFileTarget[] = []
  const facts: string[] = [`native_tool=${tool}; supplied input is a file operation, not executable shell code`]
  const roots = await Promise.all(options.writableRoots.map((root) => canonicalBoundaryPath(path.resolve(root))))
  const findings: string[] = []
  // A harmless search root does not make an explicitly sensitive selector safe.
  const selector = tool === "glob" ? args.pattern : tool === "grep" ? args.include : undefined
   // Glob only returns names; a key-shaped filename is not a credential read.
   const selectorFinding = tool === "grep" && typeof selector === "string" ? embeddedCredentialFinding(selector) : undefined
  if (selectorFinding && selectorFinding.kind !== "pass") {
    const categories = ruleRequiredCategories(selectorFinding.rule) ?? []
    if (categories.length && categories.every((category) => options.bypassCategories?.has(category))) {
      facts.push(`static category check skipped by user bypass: ${selectorFinding.rule}`)
    } else {
      findings.push(`${selectorFinding.rule}: native search explicitly selects sensitive names: ${JSON.stringify(selector)}`)
    }
  }
  for (const request of requested) {
    const absolute = nativeAbsolutePath(options.cwd, request.value)
    const target = await inspectBoundaryTarget(absolute, request.mode)
    const { resolved } = target
    targets.push(target)
    facts.push(target.inspectionError
      ? `${request.mode}: ${JSON.stringify(absolute)} has unavailable evidence: ${target.inspectionError}; the lexical path is not a canonical grant`
      : `${request.mode}: ${JSON.stringify(absolute)} resolves to ${JSON.stringify(resolved)}`)
    if (target.inspectionError) findings.push(target.inspectionError)
    const classificationPaths = absolute === resolved ? [absolute] : [absolute, resolved]
    const publicSshPattern = /\/\.ssh\/(?:config|known_hosts(?:\.old)?|authorized_keys(?:2)?|[^/]+\.pub)$/
    const publicSshResource = publicSshPattern.test(absolute) && publicSshPattern.test(resolved)
    const directoryListing = request.mode === "read" && (await stat(resolved).catch(() => undefined))?.isDirectory() === true
    // A lexical credential-store name and its real referent are both evidence;
    // resolving a symlink must not erase the sensitive origin of a read.
    for (const classificationPath of classificationPaths) {
      const finding = classifyPathTarget(classificationPath, request.mode, { cwd: options.cwd, worktree: options.cwd, strictness: "LOOSE" })
      if (finding.kind === "pass") continue
      const credentialRead = request.mode === "read" && finding.rule === "credentials.sensitive-access"
      const riskOnly = finding.rule === "filesystem.broad-scan" || finding.rule === "credentials.foreign-home" ||
        request.mode === "read" && (publicSshResource || directoryListing && !credentialRead ||
          absolute.startsWith("/proc/sys/") && resolved.startsWith("/proc/sys/")) ||
        finding.rule === "persistence.git-hooks" && roots.some((root) => containsPath(root, resolved))
      if (riskOnly) continue
      const categories = ruleRequiredCategories(finding.rule) ?? []
      const skipped = !credentialRead && categories.length > 0 && categories.every((category) => options.bypassCategories?.has(category))
      if (skipped) facts.push(`static category check skipped by user bypass: ${finding.rule}`)
      else if (finding.rule !== "filesystem.outside-write" || !roots.some((root) => containsPath(root, resolved))) {
        const description = `${finding.rule}: ${finding.reason}`
        if (!findings.includes(description)) findings.push(description)
      }
    }
    if (request.mode === "delete") {
      // Native patch reads the old contents for its preview before unlinking.
      // The unlink target and a symlink's read referent are different effects.
      const readTarget = await inspectBoundaryTarget(absolute, "read")
      const referent = readTarget.resolved
      if (readTarget.inspectionError) findings.push(readTarget.inspectionError)
      if (referent !== resolved) {
        targets.push(readTarget)
        facts.push(`patch deletion preview reads ${JSON.stringify(referent)}; only the link ${JSON.stringify(resolved)} is deleted`)
        const readFinding = classifyPathTarget(referent, "read", { cwd: options.cwd, worktree: options.cwd, strictness: "LOOSE" })
        if (readFinding.kind !== "pass") {
          const categories = ruleRequiredCategories(readFinding.rule) ?? []
          if (!(categories.length > 0 && categories.every((category) => options.bypassCategories?.has(category)))) {
            findings.push(`${readFinding.rule}: ${readFinding.reason}`)
          }
        }
      }
    }
  }
  const resolvedWrites = [...new Set(targets.filter((target) => target.mode !== "read").map((target) => target.resolved))]
  const outsideWrites = resolvedWrites.filter((target) => !roots.some((root) => containsPath(root, target)))
  facts.push(...findings)
  if (outsideWrites.length) facts.push(`workspace-write boundary requires a per-call exception for: ${JSON.stringify(outsideWrites)}`)
  return {
    tool,
    command: JSON.stringify({ tool, input: args }),
    targets,
    resolvedWrites,
    outsideWrites,
    facts,
    verdict: outsideWrites.length || findings.length ? "ASK" : "ALLOW",
    ...((tool === "glob" || tool === "grep") ? { searchPattern: args.pattern as string } : {}),
  }
}

/** Revalidate just before the original executor. This is a path gate, not atomic OS isolation. */
export async function verifyFileBoundaryPlan(plan: FileBoundaryPlan): Promise<void> {
  for (const target of plan.targets) {
    const inspected = await inspectBoundaryTarget(target.absolute, target.mode)
    if (inspected.inspectionError || target.inspectionError) {
      if (inspected.inspectionError === target.inspectionError && inspected.resolved === target.resolved) continue
      throw new BoundaryPreparationError("Native-tool inspection changed after review", "the target's inspection availability changed after this call was checked", true)
    }
    const resolved = inspected.resolved
    if (resolved !== target.resolved) throw new BoundaryPreparationError("Native-tool target changed after review", "a target path changed after this call was checked", true)
    if (target.mode === "read") {
      // The admission binds a read target's canonical path only — a
      // read-only object's mtime/size drifting during review (appended
      // logs, touched files) is not a fact the approval depended on, so
      // growth must not become a second veto.
      continue
    }
    // Write/delete targets stay bound to the OBJECT (dev+ino): a rename-
    // swap mid-review must not ride the approval, while same-inode content
    // growth (appended logs, in-place edits) remains admitted.
    const current = inspected.identity
    if (current?.dev !== target.identity?.dev || current?.ino !== target.identity?.ino) {
      throw new BoundaryPreparationError("Native-tool object changed after review", "a target file changed after this call was checked", true)
    }
  }
}

export interface ShellBoundaryPlan {
  targets: BoundaryFileTarget[]
  resolvedWrites: string[]
  outsideWrites: string[]
  writeRoots: string[]
  readPaths: string[]
  facts: string[]
  domain: string | null
  networkRequested: boolean
  unsupported: string[]
}

function literalShellOperand(value: string): string | undefined {
  if (!/['"\\]/.test(value)) return value
  const parsed = scan(`printf '%s' ${value}`)
  return parsed.kind === "scanned" && parsed.commands.length === 1 && parsed.commands[0]!.words.length === 3
    ? parsed.commands[0]!.words[2] : undefined
}

/** Literal preflight targets only. Opaque/dynamic targets never widen the kernel profile. */
export async function planShellBoundary(
  command: string,
  options: { cwd: string; shell: string; writableRoots: readonly string[] },
): Promise<ShellBoundaryPlan> {
  const segments = splitSimpleSegments(command, options.shell) ?? []
  const facts: string[] = ["Shell target enumeration is partial; runtime-only targets are not automatically authorized or retried"]
  const reads = new Set<string>()
  const writes = new Map<string, "write" | "delete">()
  const absoluteTargets = new Map<string, string>()
  const directoryWrites = new Set<string>()
  let networkRequested = false
  // A changing/unknown cwd invalidates relative target claims; absolute ones remain explicit.
  const movingBase = /(?:^|[\s;&|])(cd|pushd|popd)(?:\s|$)/.test(command)
  for (const segment of segments) {
    const extracted = extractWriteTargets(segment)
    const scanned = scan(segment)
    const removals: string[] = []
    if (scanned.kind === "scanned" && scanned.commands.length === 1) {
      const words = scanned.commands[0]!.words
      const leaf = path.basename(words[0] ?? "")
      if (["curl", "wget", "ssh", "scp", "sftp", "ftp", "ping"].includes(leaf) ||
        leaf === "git" && ["fetch", "pull", "push", "clone", "ls-remote"].includes(words[1] ?? "")) networkRequested = true
      if (leaf === "rm" || leaf === "mv") {
        let optionsEnded = false
        const operands = words.slice(1).filter((word) => {
          if (word === "--") { optionsEnded = true; return false }
          return optionsEnded || !word.startsWith("-")
        })
        removals.push(...(leaf === "mv" ? operands.slice(0, -1) : operands))
      }
    }
    for (const candidate of [
      ...extracted.targets.map((value) => ({ value: literalShellOperand(value), deleting: false })),
      ...removals.map((value) => ({ value, deleting: true })),
    ]) {
      const value = candidate.value
      if (value === undefined) {
        facts.push("A shell path operand could not be decoded literally")
        continue
      }
      if (/[`$*?\[\]{}]/.test(value) || (movingBase && !path.isAbsolute(value))) {
        facts.push(`Unresolved shell write target: ${JSON.stringify(value)}`)
        continue
      }
      const absolute = nativeAbsolutePath(options.cwd, value)
      const deleting = candidate.deleting
      const inspected = await inspectBoundaryTarget(absolute, deleting ? "delete" : "write")
      const resolved = inspected.resolved
      if (inspected.inspectionError) facts.push(`Uninspected shell write target ${JSON.stringify(absolute)}: ${inspected.inspectionError}`)
      if (resolved.startsWith("/dev/")) continue
      writes.set(resolved, deleting ? "delete" : "write")
      absoluteTargets.set(resolved, absolute)
      if (scanned.kind === "scanned" && scanned.commands.length === 1 &&
        path.basename(scanned.commands[0]!.words[0] ?? "") === "mkdir") directoryWrites.add(resolved)
    }
    if (extracted.unparseable) facts.push("A shell redirection could not be resolved literally")
    for (const rawRead of extractReadPaths(segment)) {
      const value = literalShellOperand(rawRead)
      if (value === undefined) continue
      if (/[`$*?\[\]{}]/.test(value) || (movingBase && !path.isAbsolute(value))) continue
      const inspected = await inspectBoundaryTarget(nativeAbsolutePath(options.cwd, value), "read")
      if (inspected.inspectionError) facts.push(`Uninspected shell read target ${JSON.stringify(inspected.absolute)}: ${inspected.inspectionError}`)
      else reads.add(inspected.resolved)
    }
  }
  const roots = await Promise.all(options.writableRoots.map((root) => canonicalBoundaryPath(root)))
  const resolvedWrites = [...writes.keys()]
  const targets: BoundaryFileTarget[] = await Promise.all(resolvedWrites.map(async (resolved) => {
    const mode = writes.get(resolved)!
    return inspectBoundaryTarget(absoluteTargets.get(resolved)!, mode)
  }))
  const outsideWrites = resolvedWrites.filter((value) => !roots.some((root) => containsPath(root, value)))
  const writeRoots = new Set<string>()
  const unsupported: string[] = []
  for (const target of outsideWrites) {
    const planned = targets.find((item) => item.resolved === target)
    if (planned?.inspectionError) {
      unsupported.push(`External target ${JSON.stringify(target)} could not be inspected; it cannot widen a writable-root grant`)
      continue
    }
    if (writes.get(target) === "delete") {
      // Capability note for the explicit-workspace contract only — never a
      // reviewed-facts entry (host-direct admission needs no parent grant).
      unsupported.push(`External deletion ${JSON.stringify(target)} needs parent removal rights; a singleton writable-root grant cannot authorize it`)
      if (!targets.find((item) => item.resolved === target)?.identity) {
        facts.push(`External delete target ${JSON.stringify(target)} does not exist at plan time`)
      }
      continue
    }
    if (!targets.find((item) => item.resolved === target)?.identity) {
      // Factual: the target did not exist at plan time (host-direct
      // execution creates it normally; the review sees the real state).
      facts.push(`External write target ${JSON.stringify(target)} does not exist at plan time`)
      unsupported.push(`External new target ${JSON.stringify(target)} does not exist; no host object exists to bind a singleton writable-root grant to`)
      continue
    }
    // Never widen a reviewed target to its parent. A deletion/rename that
    // cannot operate on an exact mount grant must fail honestly at runtime.
    const root = directoryWrites.has(target) ? `${target}/` : target
    writeRoots.add(root)
    facts.push(`Proposed per-call writable root ${JSON.stringify(root)} for literal target ${JSON.stringify(target)}`)
  }
  const domains = new Set<string>()
  for (const value of command.match(/https?:\/\/[^\s'"<>]+/g) ?? []) {
    try { domains.add(new URL(value).hostname) } catch { /* An opaque destination is not a domain grant. */ }
  }
  if (domains.size) networkRequested = true
  return { targets, resolvedWrites, outsideWrites, writeRoots: [...writeRoots], readPaths: [...reads], facts, domain: domains.size === 1 ? [...domains][0]! : null, networkRequested, unsupported }
}

/** Best-effort canonical/object recheck; this is not an atomic race guarantee.
 *  Write/delete targets bind their object (dev+ino) so a rename-swap cannot
 *  ride the approval, while same-inode growth (an appended log the review
 *  itself extended) stays admitted. Enumerated read paths bind only their
 *  canonical resolution — mtime drift on a read-only file is not a fact the
 *  approval depended on. Script-content binding lives in the separate
 *  fingerprint verification, not here. */
export async function verifyShellBoundaryPlan(plan: ShellBoundaryPlan): Promise<void> {
  for (const target of plan.targets) {
    const inspected = await inspectBoundaryTarget(target.absolute, target.mode)
    if (inspected.inspectionError || target.inspectionError) {
      if (inspected.inspectionError === target.inspectionError && inspected.resolved === target.resolved) continue
      throw new BoundaryPreparationError("Shell inspection changed after review", "the target's inspection availability changed after this call was checked", true)
    }
    const resolved = inspected.resolved
    if (resolved !== target.resolved) throw new BoundaryPreparationError("Shell target changed after review", "a target path changed after this call was checked", true)
    const identity = inspected.identity
    if (identity?.dev !== target.identity?.dev || identity?.ino !== target.identity?.ino) {
      throw new BoundaryPreparationError("Shell target object changed after review", "a target file changed after this call was checked", true)
    }
  }
  for (const readPath of plan.readPaths) {
    if (await canonicalBoundaryPath(readPath) !== readPath) {
      throw new BoundaryPreparationError("Shell read path changed after review", "a target path changed after this call was checked", true)
    }
  }
}

/** Only definite privilege launchers, not the whole privilege risk category. */
export function needsHostDirectPrivilege(command: string): boolean {
  const scanned = scan(command)
  return scanned.kind === "scanned" && scanned.commands.some((item) =>
    ["sudo", "sudoedit", "doas", "pkexec", "su", "runuser"].includes(path.basename(item.words[0] ?? "")))
}

/** Canonical user messages and completed user-question answers authorize;
 * ordinary tool output, synthetic messages and assistant text do not. */
export function boundarySessionContext(raw: unknown): { userRequest: string; context: string[] } {
  const messages = Array.isArray(raw) ? raw : raw && typeof raw === "object" && "data" in raw && Array.isArray(raw.data) ? raw.data : []
  const recent: string[] = []
  const userTurns: string[][] = []
  for (const value of messages) {
    if (!value || typeof value !== "object") continue
    const message = value as Record<string, unknown>
    if (message.type === "user" && typeof message.text === "string") {
      const text = message.text.split(/\n{2,}/).filter((block) => !block.trimStart().startsWith("[opencode-v2-security]")).join("\n\n").trim()
      if (message.synthetic === true || !text) continue
      userTurns.push([text])
      recent.push(`user: ${text.slice(-4_000)}`)
    } else if (message.type === "assistant" && Array.isArray(message.content)) {
      for (const item of message.content) {
        if (!item || typeof item !== "object") continue
        if (item.type === "text" && typeof item.text === "string") recent.push(`assistant: ${item.text.slice(-4_000)}`)
        if (item.type !== "tool" || !item.state || typeof item.state !== "object") continue
        const state = item.state as Record<string, unknown>
        const parts = Array.isArray(state.content) ? state.content : []
        const text = parts.filter((part) => part && part.type === "text" && typeof part.text === "string")
          .map((part) => part.text).join("\n").slice(-4_000)
        if (["question", "askUserQuestion"].includes(item.name) && state.status === "completed" && text.trim()) {
          const metadata = state.metadata && typeof state.metadata === "object" ? state.metadata as Record<string, unknown> : undefined
          const answers = metadata?.answers
          // Native question answers preserve empty/unanswered selections.
          const hasStructuredAnswers = Array.isArray(answers)
          const answered = !hasStructuredAnswers || answers.some((answer) =>
            Array.isArray(answer) && answer.some((selection) => typeof selection === "string" && selection.trim()))
          const formattedUserReply = text.startsWith("User has answered your questions:")
          if (answered && (hasStructuredAnswers || formattedUserReply)) {
            const response = `User response via trusted question tool ${JSON.stringify(item.name)}: ${JSON.stringify({
              question_input: state.input,
              ...(hasStructuredAnswers ? { user_answers: answers } : { formatted_user_response: text }),
            })}`
            if (!userTurns.length) userTurns.push([])
            userTurns.at(-1)!.push(response.slice(0, 4_000))
            recent.push(`user: ${response.slice(0, 4_000)}`)
            continue
          }
        }
        recent.push(`tool ${JSON.stringify(item.name)} (${String(state.status)}): ${text}`)
      }
    }
  }
  const context: string[] = []
  let remaining = 16_000
  for (const text of recent.slice(-12).reverse()) {
    // Do not slice off a role label to squeeze in an older message.
    if (text.length > remaining) break
    context.unshift(text)
    remaining -= text.length
  }
  const recentUserTurns = userTurns.slice(-5)
  const separatorCharacters = Math.max(0, recentUserTurns.length - 1) * 2
  const turnBudget = Math.min(3_998, Math.floor((12_000 - separatorCharacters) / Math.max(1, recentUserTurns.length)))
  const retainedTurns = recentUserTurns.map((turn) => {
    const text = turn.join("\n\n")
    if (text.length <= turnBudget) return text
    // Preserve both the opening scope and later restrictions/selected answers.
    const marker = "\n...[truncated user turn]...\n"
    const headCharacters = Math.floor((turnBudget - marker.length) / 2)
    const tailCharacters = turnBudget - marker.length - headCharacters
    return `${text.slice(0, headCharacters)}${marker}${text.slice(-tailCharacters)}`
  })
  const userRequest = retainedTurns.join("\n\n")
  // Remove only a complete, verbatim duplicate; truncated turns and question
  // answers keep their context entry so no authorization evidence is lost.
  const latestTurn = retainedTurns.at(-1)
  const duplicate = latestTurn === undefined ? -1 : context.lastIndexOf(`user: ${latestTurn}`)
  if (duplicate >= 0) context.splice(duplicate, 1)
  return { userRequest, context }
}

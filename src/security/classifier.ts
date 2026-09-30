import { createHash } from "node:crypto"
import type { Dirent } from "node:fs"
import { lstat, opendir, readFile, readdir, realpath, stat } from "node:fs/promises"
import path from "node:path"
import { STATIC_BYPASS_CATEGORIES, type BypassCategory } from "../categories"
import { ruleBypassed } from "./bypass"
import {
  analyzeSegmentPaths,
  checkPathSensitivity,
  extractReadPaths,
  extractRedirectTargets,
  extractWriteTargets,
  hasSensitiveEnvPrefix,
  hasUnquotedExpansion,
  resolveLexical,
  isWithinLexical,
  classifyPathTarget,
  sensitivePathFinding,
  segmentCommandLeaf,
  stripOutputRedirects,
  stripTrailingFdMerges,
  type PathContext,
  type PathFinding,
} from "./paths"

export type SecurityVerdict = "ALLOW" | "DENY" | "ASK"

export type ScriptFingerprint = {
  path: string
  size: number
  mtimeMs: number
  sha256: string
  /**
   * Present when the executed path was a symlink at classification time.
   * The post-check then verifies the link itself (dev/ino/mtime) is unchanged
   * and still resolves to the same canonical file, closing the symlink-swap
   * TOCTOU window.
   */
  linkPath?: string
  linkDev?: number
  linkIno?: number
  linkMtimeMs?: number
}

export type LocalScriptReviewContext = {
  path: string
  content: string
  sha256: string
}

export type DirectoryEntryReviewContext = {
  name: string
  type: "directory" | "file" | "symlink" | "other"
}

export type TargetDirectoryReviewContext = {
  path: string
  entries: DirectoryEntryReviewContext[]
  truncated: boolean
}

export type StaticReviewContext = {
  localScripts: LocalScriptReviewContext[]
  uninspectedLocalScripts: string[]
  targetDirectories: TargetDirectoryReviewContext[]
  uninspectedTargetDirectories: string[]
  referencedPaths: string[]
  referencedPathsTruncated: boolean
}

export type StaticSecurityDecision = {
  verdict: SecurityVerdict
  rules: string[]
  reason: string
  fingerprints: ScriptFingerprint[]
  reviewContext?: StaticReviewContext
}

export type Strictness = "LOOSE" | "HARD"

export type ClassifyShellCommandInput = {
  script: string
  cwd: string
  worktree: string
  shell: string
  nowMs?: number
  trustedTempRoot?: string
  strictness?: Strictness
  /** Bypass categories armed for this session; matching rule groups are
   * skipped except for the unconditional floor (root destruction, disk
   * destruction, fork bombs, kernel primitives, reverse shells). */
  bypassedCategories?: ReadonlySet<BypassCategory>
  /** Session rwx ceiling from the permission layer: a missing `x` denies shell
   * execution outright; a missing `w` denies write/delete segments. Orthogonal
   * to bypassedCategories (which only relaxes). */
  permScope?: { r: boolean; w: boolean; x: boolean }
  /** True when the kernel sandbox (ro profile) will actually enforce the
   *  read-only write boundary for THIS call — the plugin sets it only when
   *  the resolved profile is "ro", the helper probe reports a usable route,
   *  and the sandbox/`all` bypasses are not armed. Under LOOSE it lets the RO
   *  gate pass write/mutator/unproven shapes through (the kernel denies the
   *  syscalls); HARD always keeps the static gates. */
  roKernelEnforced?: boolean
  /** Scratch hierarchies the kernel leaves writable under the RO profile —
   *  the plugin's resolved sandbox.scratch (default /tmp). RO static denies
   *  exempt mutations whose targets are entirely confined to these roots. */
  roWritableRoots?: string[]
  /** Config denyWrite entries (sandbox.denyWrite): user-declared write freezes
   *  that override the scratch carve-out even for paths inside it. */
  sandboxDenyWrite?: string[]
  /** Working directory the shell tool will execute in (the tool call's
   * `workdir` argument), resolved against `cwd` when relative. Unlike `cwd` —
   * the verified session directory — this is a claim made by the tool input,
   * so it marks the tracked base unverified: it may resolve paths for
   * tightening checks but only produces temp-confined exemptions after the
   * base itself canonically lands inside a trusted temp root. */
  runtimeWorkdir?: string
}

type InternalClassifyInput = ClassifyShellCommandInput & {
  /** The effective working directory of this segment is not statically known. */
  cwdUnknown?: boolean
  /** The segment's base directory was established by a `cd` whose success is
   * not guaranteed for this segment (`;`/newline links, or an `||`/`|`/`&`
   * predecessor that may have left a different directory behind), so
   * temp-delete exemptions must re-verify the claimed base. */
  baseUnverified?: boolean
}

const MAX_COMMAND_CHARS = 32_768
const MAX_LOCAL_SCRIPT_BYTES = 256_000
const MAX_CLOUD_LOCAL_SCRIPT_CHARS = 256_000
const MAX_LOCAL_SCRIPTS = 8
const MAX_DECODED_PAYLOADS = 8
const MAX_TARGET_DIRECTORIES = 4
const MAX_REFERENCED_PATHS = 32
const MAX_DIRECTORY_ENTRIES = 200
const MAX_DIRECTORY_ENTRY_NAME_CHARS = 512
const MIN_BACKUP_AGE_MS = 2 * 60 * 1000
const PERMANENT_DELETE_GUIDANCE =
  "Permanent deletion is irreversible and can destroy data that cannot be recovered"

type Rule = {
  id: string
  reason: string
  test: (text: string) => boolean
}

const DATA_EXTENSION = /\.(?:csv|jsonl?|ya?ml|toml|ini|db|sqlite(?:3)?|sql|parquet|avro|xlsx?|docx?|pptx?|pdf|pem|key|p12|pfx|ppk|jks|keystore|kdbx|gpg|age|env|bak|backup)\b/i
const CRITICAL_DATA_EXTENSION = /\.(?:pem|key|p12|pfx|ppk|jks|keystore|kdbx|gpg|age)\b/i
const GENERAL_DATA_EXTENSION =
  /\.(?:csv|jsonl?|ya?ml|toml|ini|db|sqlite(?:3)?|sql|parquet|avro|xlsx?|docx?|pptx?|pdf)(?=$|[\s"';&|)])/i
const DELETE_PRIMITIVE =
  /\b(?:rm|ri|del|erase|rmdir|rd|remove-item|clear-content|unlink|unlinkSync|rmSync|rmtree|os\.remove|os\.unlink|shutil\.rmtree|shred|srm|wipe)\b|(?:^|\s)-delete(?:\s|$)|\.unlink\s*\(/i
const SCRIPT_DESTRUCTIVE_PRIMITIVE = new RegExp(
  [
    // Shell deletion / process-kill commands, matched on raw text including inside quoted string literals
    String.raw`\b(?:rm|rmdir|rd|del|erase|ri|remove-item|clear-content|shred|unlink|unlinksync|rmsync|rmtree|removedirs|rimraf|send2trash|kill|pkill|killall|taskkill|stop-process)\b`,
    String.raw`\b(?:trash-put|trash-cli|trash-empty|trash-rm)\b|\bgio\s+trash\b`,
    // Python / Node deletion and kill APIs
    String.raw`\bos\.(?:remove|unlink|rmdir|removedirs|kill)\b`,
    String.raw`\bshutil\.rmtree\b`,
    String.raw`\bfs(?:\.promises)?\.(?:rm|unlink|rmdir)(?:sync)?\s*\(`,
    String.raw`\.(?:unlink|rmdir|rmSync|unlinkSync|kill|terminate)\s*\(`,
    String.raw`(?:^|\s)-delete(?:\s|$)`,
  ].join("|"),
  "i",
)
const WRAPPER_PRIMITIVE =
  /\b(?:eval|invoke-expression|iex)\b|(?:\b(?:bash|sh|zsh|cmd(?:\.exe)?|powershell|pwsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node)\b[^\n]{0,80}(?:\s-c|\s\/c|\s-command|\s-encodedcommand|\s-enc|\s-e))\b/i
const SENSITIVE_ENV_FILE =
  /(?:^|[\\/\s"'=])(?:\.env(?:\.[A-Za-z0-9_-]+)*|[A-Za-z0-9_.-]+\.env)(?=$|[\\/\s"';&|)])/i
const BACKUP_SUFFIX_REFERENCE = /(?:\.backup|-backup|\.bak|-bak)\d*(?=$|[\\/\s"';&|])/m

const FORCED_RECURSIVE_COMMANDS = ["remove-item", "ri", "rm", "del", "erase", "rmdir", "rd"]
const CMD_STYLE_DELETE_COMMANDS = ["rmdir", "rd", "del", "erase"]
const CMD_DELETE_FLAGS = /^\/[sfq]+$/i

function forcedRecursiveShape(tokens: string[]) {
  const command = commandLeaf(stripMatchingQuotes(tokens[0] ?? ""))
  const flags = tokens
    .slice(1)
    .filter((token) => token.startsWith("-"))
    .map((token) => token.toLowerCase())
  const cmdFlags = CMD_STYLE_DELETE_COMMANDS.includes(command ?? "")
    ? tokens
        .slice(1)
        .filter((token) => CMD_DELETE_FLAGS.test(token))
        .map((token) => token.toLowerCase())
    : []
  const hasPowerShellPair =
    FORCED_RECURSIVE_COMMANDS.includes(command ?? "") &&
    flags.some((flag) => /^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$/.test(flag)) &&
    flags.some((flag) => /^-f(?:o(?:r(?:c(?:e)?)?)?)?$/.test(flag))
  const hasLongPair = flags.includes("--recursive") && flags.includes("--force")
  const shortLetters = command === "rm"
    ? flags.filter((flag) => /^-[dfirvR]+$/.test(flag)).join("")
    : ""
  const hasShortPair =
    (/r/i.test(shortLetters) || flags.includes("--recursive")) &&
    (/f/i.test(shortLetters) || flags.includes("--force"))
  const cmdHasS = cmdFlags.some((flag) => flag.includes("s"))
  const cmdHasQ = cmdFlags.some((flag) => flag.includes("q"))
  const cmdHasF = cmdFlags.some((flag) => flag.includes("f"))
  const hasCmdPair =
    ((command === "rmdir" || command === "rd") && cmdHasS && cmdHasQ) ||
    ((command === "del" || command === "erase") && cmdHasS && cmdHasQ && cmdHasF)
  const forced = hasPowerShellPair || hasLongPair || hasShortPair || hasCmdPair

  const targets: string[] = []
  if (forced) {
    for (let index = 1; index < tokens.length; index += 1) {
      const token = tokens[index]
      if (token === "--") continue
      if (token.startsWith("-")) continue
      if (CMD_STYLE_DELETE_COMMANDS.includes(command ?? "") && CMD_DELETE_FLAGS.test(token)) continue
      if (isRedirectToken(token)) continue
      if (/^(?:\d*|&)>{1,2}$/.test(token)) { index += 1; continue }
      targets.push(token)
    }
  }
  return { forced, targets }
}

function hasForcedRecursiveDelete(text: string) {
  const invocations =
    text.match(/\b(?:remove-item|ri|rm|del|erase|rmdir|rd)\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []

  return invocations.some((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    if (tokens.length < 2) return false
    const shape = forcedRecursiveShape(tokens)
    return shape.forced && shape.targets.length > 0
  })
}

function hasForcedRecursiveDeleteLiteralTarget(text: string): boolean {
  const invocations =
    text.match(/\b(?:remove-item|ri|rm|del|erase|rmdir|rd)\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []

  return invocations.some((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    if (tokens.length < 2) return false
    const shape = forcedRecursiveShape(tokens)
    if (!shape.forced || shape.targets.length === 0) return false
    return shape.targets.every((t) => literalPathToken(t) !== undefined)
  })
}

function hasNamedTempPathSegment(target: string): boolean {
  const cleaned = stripMatchingQuotes(target).replaceAll("\\", "/")
  if (cleaned.split("/").some((segment) => segment === "..")) return false
  return cleaned
    .split("/")
    .filter((segment) => segment.length > 0)
    .some((segment) => {
      const lower = segment.toLowerCase()
      return lower === "temp" || lower === "tmp"
    })
}

async function canonicalProjectedPath(candidate: string) {
  let current = path.resolve(candidate)
  const suffix: string[] = []
  for (let index = 0; index < 128; index += 1) {
    try {
      const canonical = await realpath(current)
      return suffix.length === 0 ? canonical : path.join(canonical, ...suffix.reverse())
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return undefined
      suffix.push(path.basename(current))
      current = parent
    }
  }
  return undefined
}

/**
 * Removes the worktree prefix from a canonical path so named-temp checks judge
 * only the target's own segments. Without this, a worktree that itself lives
 * under /tmp (sandboxes, scratch projects) contributes a `tmp` segment to every
 * candidate and the whole whitelist fires for arbitrary deletes.
 */
async function withoutWorktreePrefix(canonical: string, worktree: string | undefined): Promise<string> {
  if (!worktree) return canonical
  const bases = [path.resolve(worktree)]
  try {
    bases.push(await realpath(path.resolve(worktree)))
  } catch {
    // Lexical worktree path only.
  }
  const norm = canonical.replaceAll("\\", "/")
  for (const base of bases) {
    const b = base.replaceAll("\\", "/").replace(/\/+$/, "")
    if (b && norm.toLowerCase() === b.toLowerCase()) return ""
    if (b && norm.toLowerCase().startsWith((b + "/").toLowerCase())) return norm.slice(b.length + 1)
  }
  return norm
}

async function isNamedTempTargetResolved(target: string, base: string | undefined, worktree?: string) {
  if (base === undefined) return false
  const literal = literalPathToken(target)
  if (!literal) return false
  const cleaned = literal.replaceAll("\\", "/")
  if (cleaned.split("/").some((segment) => segment === "..")) return false
  const lexical = normalizeMsysPath(path.resolve(normalizeMsysPath(base), cleaned))
  const lexicalOwn = await withoutWorktreePrefix(lexical, worktree)
  if (!hasNamedTempPathSegment(lexicalOwn)) {
    // The target carries no temp segment of its own; accept it only when it
    // resolves OUTSIDE the worktree into a real temp location.
    const outside = await canonicalProjectedPath(lexical)
    if (!outside || !hasNamedTempPathSegment(outside) || isWithin(worktree ?? base, outside)) return false
    // Prevent symlink escape: lexical path within worktree that resolves outside
    if (isWithinLexical(worktree ?? base, lexical)) return false
    return true
  }
  const canonical = await canonicalProjectedPath(lexical)
  if (!canonical) return false
  // Prevent symlink escape: lexical path within worktree that resolves outside
  if (isWithinLexical(worktree ?? base, lexical) && !isWithin(worktree ?? base, canonical)) return false
  return hasNamedTempPathSegment(await withoutWorktreePrefix(canonical, worktree))
}

function isRedirectToken(token: string): boolean {
  if (/^\d*>&\d+$/.test(token)) return true
  if (/^(?:\d*|&)>{1,2}\S+$/.test(token)) return true
  if (/^(?:\d*|&)>{1,2}$/.test(token)) return true
  return false
}

function hasHostShutdownCommand(text: string): boolean {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) continue
    let stripped = trimmed.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*/, "")
    stripped = stripped.replace(/^(?:sudo\s+|runas\s+)/i, "")
    const firstToken = stripped.match(/^(\S+)/)?.[1] ?? ""
    const command = firstToken.replace(/\.(?:exe|cmd|bat|ps1)$/i, "").toLowerCase()
    if (["shutdown", "reboot", "poweroff", "halt"].includes(command)) return true
    if (/^stop-computer\b/i.test(stripped)) return true
    if (/\binit\s+[06]\b/i.test(stripped)) return true
    if (/\bsystemctl\s+(?:reboot|poweroff|halt|emergency|rescue)\b/i.test(stripped)) return true
  }
  return false
}

/** Network clients matched as command words only: a bare `\bssh\b` would also
 * hit paths like `~/.ssh/id_rsa` and wrongly defeat a secret bypass, while a
 * command-position anchor (line start or a separator before the word) keeps
 * `nohup curl`, `xargs curl`, and `echo a && curl` detected. */
const NETWORK_CLIENT_WORD = /(?:^|[\s;&|(])(?:curl|wget|invoke-webrequest|iwr|irm|rsync|ssh|scp)\b/i

function hasDeletePrimitive(text: string): boolean {
  const stripped = text.replace(/'[^']*'/g, "").replace(/"(?:[^"]|"")*"/g, "")
  return DELETE_PRIMITIVE.test(stripped)
}

// --- M2 (P1) helper predicates ---------------------------------------------

/** System-critical roots for the deletion floors (root-delete and
 * find-delete-root). One shared list so `rm -rf X` and `find X -delete` can
 * never disagree; `run`/`media` are intentionally excluded (runtime/mount
 * points, not system integrity). */
const SYSTEM_CRITICAL_ROOTS = ["etc", "usr", "bin", "sbin", "boot", "var", "home", "root", "opt", "lib", "lib64", "srv", "sys", "proc", "mnt"]

/** Lexically normalize `..`/`.` segments so `rm -rf /var/../etc` resolves to
 * `/etc` for the root-delete floor. */
function normalizeDots(operand: string): string {
  const out: string[] = []
  for (const segment of operand.replaceAll("\\", "/").split("/")) {
    if (segment === "..") out.pop()
    else if (segment !== "." && segment !== "") out.push(segment)
  }
  return `/${out.join("/")}`
}

/** Every path operand of every `rm` invocation, dot-normalized, each rebuilt
 * as its own pseudo-invocation so the per-operand regex shape applies: the
 * root-delete floor must see all operands (`rm -rf /var/tmp/foo /etc`) and
 * traversal forms (`rm -rf /var/../etc` → `/etc`), not only the first one. */
function normalizedRootDeleteText(text: string): string {
  const invocations = text.match(/\brm\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []
  const allOperands = invocations.flatMap((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    return tokens
      .slice(1)
      .filter((token) => !token.startsWith("-"))
      .map(stripMatchingQuotes)
      .filter(Boolean)
      .map(normalizeDots)
  })
  return allOperands.map((operand) => `rm -rf ${operand}`).join("\n")
}

function isDangerousFindRoot(root: string): boolean {
  const r = root.replaceAll("\\", "/")
  if (r === "~" || r.startsWith("~/")) return true
  if (r === ".." || r.startsWith("../")) return true
  const lower = r.toLowerCase()
  if (lower === "/") return true
  return SYSTEM_CRITICAL_ROOTS.some(
    (p) => lower === `/${p}` || lower.startsWith(`/${p}/`),
  )
}

function findDangerousDeleteRoot(text: string): boolean {
  const match = text.match(/\bfind\s+(\S+)[\s\S]*?(?:\s|^)-(?:delete|exec|execdir|ok|okdir)(?:\s|$)/im)
  if (!match) return false
  return isDangerousFindRoot(match[1] ?? "")
}

/** Kernel-floor write detection for a /proc target path: `> file` / `of=file`
 * redirects, and command-position `tee`/`cp`/`mv`/`rsync`/`install` with the
 * target as the trailing destination. Command-position anchoring (the command
 * word starts the trailing command of a line/pipe side) keeps `echo tee ...`
 * inert-text mentions from matching; the trailing-destination requirement
 * keeps reads (`cp /proc/sysrq-trigger /tmp/x`) from matching. */
function kernelWriteTest(text: string, target: string): boolean {
  const escapedTarget = target.replace(/\//g, "\\/")
  if (new RegExp(`(?:>\\s*|\\bof=)[^\\n]*${escapedTarget}\\b`, "i").test(text)) return true
  // `tee` as a command word (its file argument is always a write). Prefixes
  // that still make it the command word: sudo (+flags/`-u user`), command,
  // builtin, busybox, `env VAR=…`, and leading shell assignments.
  const commandPrefix = "(?:sudo(?:\\s+-{1,2}[\\w-]+|\\s+\\S+)*\\s+|command\\s+|builtin\\s+|busybox\\s+|env\\s+(?:\\w+=\\S+\\s+)*|\\w+=\\S+\\s+|\\\\\\s*)*"
  const teeCommand = new RegExp(
    `(?:^|[\\n;|&])\\s*(?:${commandPrefix})tee\\b[^\\n]*${escapedTarget}\\b`,
    "i",
  )
  if (teeCommand.test(text)) return true
  // `#` comments and `\d*>` redirections are valid after a destination, but
  // only with separating whitespace: `trigger2>` and `trigger#x` are literal
  // filenames (shell-verified), not a redirection or comment.
  const dest = new RegExp(`\\s["']?${escapedTarget}["']?(?:\\s(?:[#>|&;\\n]|\\d*>)|$)`, "i")
  const writers = /\b(?:cp|mv|rsync|install)\b/gi
  const writerPrefix = /(?:^|[\n;|&])\s*(?:sudo(?:\s+-{1,2}[\w-]+|\s+\S+)*\s+|command\s+|builtin\s+|busybox\s+|env\s+(?:\w+=\S+\s+)*|(?:\w+=\S+\s+)*|(?:\\\s*)?)$/
  let match: RegExpExecArray | null
  while ((match = writers.exec(text)) !== null) {
    // Only a trailing command of the line counts: `echo x && cp ...` is a
    // write; `echo cp ...` is inert text.
    const before = text.slice(Math.max(0, match.index - 200), match.index)
    if (!writerPrefix.test(before)) continue
    const after = text.slice(match.index, match.index + 300)
    if (dest.test(after)) return true
  }
  return false
}

function hasForkBomb(text: string): boolean {
  // Neutralize quoted spans instead of deleting the quotes: text inside
  // quotes is data (`echo "x | x"`), never real pipe/background operators.
  // Single quotes have no escapes (backslash is ordinary), double quotes and
  // backticks honor backslash escapes.
  const stripped = text
    .replace(/"(?:[^"\\]|\\.)*"/g, " ")
    .replace(/'(?:[^'])*'/g, " ")
    .replace(/`(?:[^`\\]|\\.)*`/g, " ")
  // Linear scan for name(){ ...|...name...&... }...name fork-bomb patterns.
  const nameChars = /[\w:.*-]/
  let pos = 0
  for (;;) {
    const parenIdx = stripped.indexOf("(", pos)
    if (parenIdx === -1) break
    pos = parenIdx + 1
    if (stripped[parenIdx + 1] !== ")") continue
    let nameEnd = parenIdx
    while (nameEnd > 0 && /[\s]/.test(stripped[nameEnd - 1])) nameEnd -= 1
    let nameStart = nameEnd
    while (nameStart > 0 && nameChars.test(stripped[nameStart - 1])) nameStart -= 1
    const name = stripped.slice(nameStart, nameEnd)
    if (!name) continue
    let braceIdx = parenIdx + 2
    while (braceIdx < stripped.length && /[\s]/.test(stripped[braceIdx])) braceIdx += 1
    if (braceIdx >= stripped.length || stripped[braceIdx] !== "{") continue
    let depth = 1
    let closeIdx = braceIdx + 1
    while (closeIdx < stripped.length && depth > 0) {
      if (stripped[closeIdx] === "{") depth += 1
      else if (stripped[closeIdx] === "}") depth -= 1
      if (depth === 0) break
      closeIdx += 1
    }
    if (depth !== 0 || closeIdx >= stripped.length) continue
    const body = stripped.slice(braceIdx + 1, closeIdx)
    if (!body.includes("|")) continue
    // Recursion core: the function's own name is the command word of either
    // side of a pipe in the body (`:(){ :|:& };:`, one-sided `f(){ f | g; };
    // f`). The command word is the first token of the side's trailing
    // command, so the name as a mere argument (`npm run build | tee log`) is
    // not recursion.
    const nameWord = new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w:.*-])`)
    // The command word of a pipe side is the first token of its last
    // non-empty `;`/`&`-separated command (`f;` ends AT the `;`, so the
    // command is `f` itself, not whatever follows). `||` is a list operator,
    // not a pipe, and `2>&1`/`&>` are redirections — mask both before
    // splitting so they cannot fake separators or pipe sides.
    const sideRecurses = (side: string) => {
      const masked = side.replace(/\|\|/g, " ").replace(/\d*>&\d/g, " ").replace(/&>/g, " ")
      const lastCommand = masked
        .split(/[;&]/)
        .map((piece) => piece.trim())
        .filter(Boolean)
        .pop()
      return lastCommand !== undefined && nameWord.test(lastCommand)
    }
    const sides = body.replace(/\|\|/g, " ").split("|")
    let recurses = false
    for (let index = 0; index < sides.length - 1; index += 1) {
      if (sideRecurses(sides[index]!) || sideRecurses(sides[index + 1]!)) {
        recurses = true
        break
      }
    }
    if (!recurses) continue
    if (body.includes("&")) return true
    const after = stripped.slice(closeIdx + 1).replace(/^[\s;&]*/, "")
    if (nameWord.test(after)) return true
  }
  // `:` and `]` are non-word chars: a single trailing `\b` never matches after
  // them, so each while-condition alternative needs its own boundary.
  if (
    /\bwhile\s+(?:(?:true|1)(?![\w:.*-])|:(?=\s*;)|\[[^\]]*\](?=\s*;))[^;]*;\s*do\s+[^;]*\$0\s*&/.test(
      stripped,
    )
  )
    return true
  // pipe self-reference: name | name & (linear scan, no backreference)
  let pipePos = 0
  for (;;) {
    const pipeIdx = stripped.indexOf("|", pipePos)
    if (pipeIdx === -1) break
    pipePos = pipeIdx + 1
    let leftEnd = pipeIdx
    while (leftEnd > 0 && /[\s]/.test(stripped[leftEnd - 1])) leftEnd -= 1
    let leftStart = leftEnd
    while (leftStart > 0 && nameChars.test(stripped[leftStart - 1])) leftStart -= 1
    const leftName = stripped.slice(leftStart, leftEnd)
    if (!leftName) continue
    let rightStart = pipeIdx + 1
    while (rightStart < stripped.length && /[\s]/.test(stripped[rightStart])) rightStart += 1
    let rightEnd = rightStart
    while (rightEnd < stripped.length && nameChars.test(stripped[rightEnd])) rightEnd += 1
    const rightName = stripped.slice(rightStart, rightEnd)
    if (!rightName || leftName !== rightName) continue
    let afterIdx = rightEnd
    while (afterIdx < stripped.length && /[\s]/.test(stripped[afterIdx])) afterIdx += 1
    if (afterIdx < stripped.length && stripped[afterIdx] === "&") return true
  }
  return false
}

function hasDestructiveOneLiner(text: string): boolean {
  const interpreter =
    /\b(?:python(?:3(?:\.\d+)?)?|py|node|perl|ruby|php)\b[^\n]{0,60}\s-(?:c|e|r|pe|escript)\b/i.test(text)
  if (!interpreter) return false
  const destructiveApi =
    /(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir|removedirs)\s*\(|fs(?:\.promises)?\.(?:rm|unlink|rmdir)(?:Sync)?\s*\(|rmSync\s*\(|File\.delete\s*\(|File\.unlink\s*\(|unlinkSync\s*\(|\bunlink\s+)/i.test(
      text,
    )
  if (!destructiveApi) return false
  return /['"`](\/|\/\*|\\|[\\/]etc[\\/]|[\\/]var[\\/]|[\\/]boot[\\/]|[\\/]usr[\\/]|[\\/]bin[\\/]|[\\/]sbin[\\/]|[\\/]home[\\/]|[\\/]root[\\/])/.test(
    text,
  )
}

function commandTokenUnquote(token: string): string {
  return token.replace(/^(["'])([\s\S]*)\1$/, "$2")
}

/** Conservative unescape/quote-removal for command name matching only (`r'm'`, `r\m`, `"r"m` → `rm`). */
function normalizeCommandNameToken(token: string): string {
  return token.replace(/['"\\]/g, "")
}

/**
 * Re-surfaces a segment whose first token, after removing quotes, is a
 * destructive command, so `'rm' -rf /` / `rm '-rf' /` / `r'm' -rf /` / `r\m -rf /`
 * are caught without flagging `echo 'rm -rf /'`.
 */
function quoteStrippedDeleteSurface(segment: string): string | undefined {
  const trimmed = segment.trim()
  if (!trimmed) return undefined
  const firstSpace = trimmed.search(/\s/)
  const firstWordRaw = firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace)
  const firstWord = normalizeCommandNameToken(firstWordRaw)
  const leaf = firstWord
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase()
  if (!leaf || !/^(?:rm|rmdir|rd|del|erase|remove-item|ri|shred|srm|wipe|unlink)\b/.test(leaf)) {
    return undefined
  }
  const rest = firstSpace === -1 ? "" : trimmed.slice(firstSpace)
  const tokens = simpleInvocationTokens(rest.trim())
  const stripped = firstWord + (tokens.length > 0 ? " " + tokens.map(commandTokenUnquote).join(" ") : "")
  return stripped.trim() === trimmed ? undefined : stripped
}

function decodeAnsiCContent(script: string): string[] {
  const decoded: string[] = []
  const matches = script.matchAll(/\$'([^']*)'/g)
  for (const match of matches) {
    const raw = match[1] ?? ""
    let out = ""
    for (let i = 0; i < raw.length; i += 1) {
      const ch = raw[i]
      if (ch !== "\\" || i + 1 >= raw.length) {
        out += ch
        continue
      }
      const next = raw[i + 1]
      if (next === "x" && i + 3 < raw.length) {
        const hex = raw.slice(i + 2, i + 4)
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16))
          i += 3
          continue
        }
      }
      const oct = raw.slice(i + 1).match(/^[0-7]{1,3}/)?.[0]
      if (oct) {
        out += String.fromCharCode(parseInt(oct, 8))
        i += oct.length
        continue
      }
      const escapes: Record<string, string> = { "\\": "\\", "'": "'", '"': '"', n: "\n", t: "\t", r: "\r", a: "\u0007", b: "\b", f: "\f", v: "\v" }
      out += escapes[next] ?? next
      i += 1
    }
    if (out.trim()) decoded.push(out)
  }
  return decoded
}

/** Expands `/{a,b}`/`src/{a,b}` style brace candidates used by a delete target. */
function braceExpansionCandidates(target: string): string[] {
  const open = target.indexOf("{")
  if (open === -1) {
    const close = target.indexOf("}")
    if (close === -1) return [target]
  }
  const close = target.indexOf("}", open + 1)
  if (open === -1 || close === -1) return [target]
  const prefix = target.slice(0, open)
  const suffix = target.slice(close + 1)
  return (target.slice(open + 1, close) ?? "")
    .split(",")
    .filter((item) => item.length > 0)
    .map((item) => `${prefix}${item}${suffix}`)
}

/** `rm -rf /{etc,var,home}` expands to a sensitive/root target. */
function hasDangerousBraceDelete(text: string): boolean {
  const invocations =
    text.match(/\b(?:rm|remove-item|ri|del|erase|rmdir|rd)\b[^\r\n;&|]*/gi) ?? []
  for (const invocation of invocations) {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    const shape = forcedRecursiveShape(tokens)
    if (!shape.forced || shape.targets.length === 0) continue
    for (const target of shape.targets) {
      if (!target.includes("{")) continue
      for (const candidate of braceExpansionCandidates(target)) {
        if (isDangerousFindRoot(candidate)) return true
      }
    }
  }
  return false
}

/** `D=rm; $D -rf /tmp/x` → surface with the variable substituted back. */
function substituteDeleteVars(script: string): string | undefined {
  const deleteCmds = ["rm", "shred", "srm", "wipe", "rmdir", "remove-item", "del", "erase", "unlink"]
  let result = script
  let changed = false
  let pos = 0
  for (;;) {
    const eq = script.indexOf("=", pos)
    if (eq === -1) break
    pos = eq + 1
    let start = eq
    while (start > 0 && /[\w]/.test(script[start - 1])) start -= 1
    if (start === eq || !/[A-Za-z_]/.test(script[start])) continue
    const name = script.slice(start, eq)
    const after = script.slice(eq + 1)
    for (const cmd of deleteCmds) {
      if (!after.toLowerCase().startsWith(cmd)) continue
      const nextChar = after[cmd.length]
      if (nextChar !== undefined && /[\w]/.test(nextChar)) continue
      if (new RegExp(`(?:^|[\\s;&|])[\\$]\\{?${name}\\}?(?=[\\s;&|])`, "i").test(script)) {
        result = result.replace(new RegExp(`[\\$]\\{?${name}\\}?`, "g"), cmd.toLowerCase())
        changed = true
      }
      break
    }
  }
  return changed ? result : undefined
}

function hasTarRemoveFiles(text: string): boolean {
  return /\btar\b[^\n;]*--remove-files\b/i.test(text)
}

/**
 * Remote Git history rewrite: force-push, mirror push, remote branch/tag
 * deletion, low-level ref rewrites, and history filters. These change shared
 * state beyond the machine, so they are definite denials in both policies.
 * Kept verbatim as the conservative fallback for text whose git invocation
 * cannot be resolved to literal argv (the primary path is the semantic
 * analyzeGitArgv check inside literalGitSegments).
 */
function legacyGitRemoteHistoryRewrite(text: string): boolean {
  if (/\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*(?:--force(?!-with-lease)\b|--mirror\b|--delete\b|\s-[a-zA-Z]*f[a-zA-Z]*\b)/i.test(text)) return true
  if (/\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*\s:[\w.-]+/.test(text)) return true
  // force-push refspec: +main or +refs/heads/main:refs/heads/main
  if (/\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*\s\+[^\s:]+(?::[^\s]+)?/i.test(text)) return true
  // low-level ref rewrite (allows global options like -C, --work-tree)
  if (/\bgit\b[^\n;|&]*\b(?:update-ref|filter-branch|filter-repo)\b/i.test(text)) {
    if (/(?:\s|^)--help(?:\s|$)/i.test(text) || /(?:\s|^)-h(?:\s|$)/i.test(text)) return false
    return true
  }
  return false
}

type LiteralArgv = {
  words: string[]
  /** Source offsets (delimiters included) of each quoted span per word —
   *  spans proven inert by the literal lexer: single-quoted, ANSI-C `$'…'`,
   *  and expansion-free double-quoted fragments. */
  spans: Array<Array<{ start: number; end: number }>>
}

/**
 * Resolve one simple command to literal argv: quotes and escapes are
 * removed, adjacent quoted/unquoted fragments of one word are joined
 * (`--fo"rce"`, `'-'f`), and ANSI-C `$'…'` escapes are decoded without
 * evaluating anything (`$` inside a `$'…'` word is literal text). Any
 * expansion, glob, substitution, redirect, or non-literal word makes the
 * whole command unresolved (undefined) — callers fall back to the
 * conservative text scan, never to silence.
 */
function literalShellArgvDetailed(segment: string): LiteralArgv | undefined {
  const words: string[] = []
  const spans: LiteralArgv["spans"] = []
  let i = 0
  const n = segment.length
  const isSpace = (ch: string | undefined) => ch === " " || ch === "\t" || ch === "\n" || ch === "\r"
  while (i < n) {
    if (isSpace(segment[i])) {
      i += 1
      continue
    }
    let word = ""
    const wordSpans: Array<{ start: number; end: number }> = []
    while (i < n && !isSpace(segment[i])) {
      const ch = segment[i]
      if (ch === "'") {
        const end = segment.indexOf("'", i + 1)
        if (end === -1) return undefined
        word += segment.slice(i + 1, end)
        wordSpans.push({ start: i, end: end + 1 })
        i = end + 1
        continue
      }
      if (ch === '"') {
        const start = i
        i += 1
        while (i < n && segment[i] !== '"') {
          const c = segment[i]
          if (c === "\\" && i + 1 < n && '\\"`$'.includes(segment[i + 1])) {
            word += segment[i + 1]
            i += 2
            continue
          }
          if (c === "\\" && i + 1 < n && segment[i + 1] === "\n") {
            i += 2
            continue
          }
          if (c === "$" || c === "`") return undefined // expansion inside quotes
          word += c
          i += 1
        }
        if (i >= n) return undefined
        i += 1 // closing quote
        wordSpans.push({ start, end: i })
        continue
      }
      if (ch === "\\") {
        if (i + 1 >= n) return undefined
        word += segment[i + 1]
        i += 2
        continue
      }
      if (ch === "$") {
        const next = segment[i + 1]
        if (next === "'") {
          // ANSI-C quoting: translate backslash escapes; the content is
          // literal data (no substitution is evaluated inside $'…').
          const start = i
          i += 2
          while (i < n && segment[i] !== "'") {
            const c = segment[i]
            if (c === "\\") {
              const e = segment[i + 1]
              if (e === undefined) return undefined
              const simple = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?", "0": "\0" }[e]
              if (simple !== undefined) {
                word += simple
                i += 2
                continue
              }
              if (e === "x") {
                const hex = /^[0-9A-Fa-f]{1,2}/.exec(segment.slice(i + 2, i + 4))
                if (!hex) return undefined
                word += String.fromCharCode(parseInt(hex[0], 16))
                i += 2 + hex[0].length
                continue
              }
              if (e === "u" || e === "U") {
                const len = e === "u" ? 4 : 8
                const hex = new RegExp(`^[0-9A-Fa-f]{1,${len}}`).exec(segment.slice(i + 2, i + 2 + len))
                if (!hex) return undefined
                word += String.fromCodePoint(parseInt(hex[0], 16))
                i += 2 + hex[0].length
                continue
              }
              if (/[0-7]/.test(e)) {
                const oct = /^[0-7]{1,3}/.exec(segment.slice(i + 1, i + 4))
                if (!oct) return undefined
                word += String.fromCharCode(parseInt(oct[0], 8) & 0xff)
                i += 1 + oct[0].length
                continue
              }
              if (e === "c") {
                // \cX control escapes (only when a control letter follows).
                const cx = segment[i + 2]
                if (cx !== undefined && /[a-zA-Z@\[\\\]^_?]/.test(cx)) {
                  word += String.fromCharCode(cx.toUpperCase().charCodeAt(0) & 0x1f)
                  i += 3
                  continue
                }
                word += "\\c"
                i += 2
                continue
              }
              // Unknown escapes keep the backslash verbatim in bash (`\/`
              // stays `\/`): still literal data, so preserve it.
              word += "\\" + e
              i += 2
              continue
            }
            word += c
            i += 1
          }
          if (i >= n) return undefined
          i += 1 // closing quote
          wordSpans.push({ start, end: i })
          continue
        }
        // `$"…"` is locale-translated double quoting (it can contain
        // substitutions) and every other `$`-form is an expansion: unresolved.
        return undefined
      }
      if (ch === "`") return undefined
      if (ch === "~" || ch === "*" || ch === "?" || ch === "[") return undefined
      if (ch === ">" || ch === "<" || ch === "&" || ch === "|" || ch === ";" || ch === "(" || ch === ")" || ch === "{" || ch === "}") {
        return undefined
      }
      if (ch === "#" && word === "") return undefined // comment start
      word += ch
      i += 1
    }
    words.push(word)
    spans.push(wordSpans)
  }
  return { words, spans }
}

function literalShellArgv(segment: string): string[] | undefined {
  return literalShellArgvDetailed(segment)?.words
}

/** git global options that take their value as the NEXT argv token. */
const GIT_GLOBAL_SEPARATE_VALUE = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"])
/** git global options whose value is only ever attached (`--git-dir=x`). */
const GIT_GLOBAL_ATTACHED_VALUE = ["--git-dir=", "--work-tree=", "--namespace=", "--config-env=", "--exec-path=", "--literal-pathspecs"]
/** Zero-arity git global options. */
const GIT_GLOBAL_FLAGS = new Set(["--version", "--help", "-h", "--html-path", "--man-path", "--info-path", "-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--bare"])

type GitArgvResult =
  | { kind: "push"; dangerous: boolean }
  | { kind: "rewrite-subcommand" }
  | { kind: "other" }

/** Semantic `git` argv analysis: finds the subcommand past global options
 *  (with correct arity) and judges `push` operands. Returns undefined when
 *  the option layout is unrecognized — the caller then falls back to the
 *  conservative text scan. */
function analyzeGitArgv(argv: string[]): GitArgvResult | undefined {
  let i = 0
  while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i])) i += 1
  if (commandLeaf(argv[i] ?? "") !== "git") return { kind: "other" }
  i += 1
  // Global options before the subcommand.
  for (; i < argv.length; i += 1) {
    const token = argv[i]
    if (token === "--") continue
    if (GIT_GLOBAL_SEPARATE_VALUE.has(token)) {
      i += 1
      if (i >= argv.length) return undefined // dangling option value
      continue
    }
    if (GIT_GLOBAL_FLAGS.has(token)) continue
    if (token.startsWith("-c") && token.length > 2) continue
    if (GIT_GLOBAL_ATTACHED_VALUE.some((prefix) => token.startsWith(prefix))) continue
    if (token.startsWith("-")) return undefined // unknown global option layout
    break
  }
  const sub = argv[i]?.toLowerCase()
  if (sub === undefined) return { kind: "other" }
  if (sub === "update-ref" || sub === "filter-branch" || sub === "filter-repo") {
    const rest = argv.slice(i + 1)
    return rest.some((token) => token === "--help" || token === "-h") ? { kind: "other" } : { kind: "rewrite-subcommand" }
  }
  if (sub !== "push") return { kind: "other" }

  // `git push` operands: options that consume the next token, options whose
  // value is attached, and the dangerous flag/refspec spellings.
  const PUSH_SEPARATE_VALUE = new Set(["-o", "--push-option", "--receive-pack", "--exec", "--repo"])
  const PUSH_FLAG_ONLY = new Set([
    "--all", "--tags", "--follow-tags", "--prune", "--porcelain", "--dry-run", "-n",
    "--verbose", "-v", "--quiet", "-q", "--progress", "--no-progress", "--verify", "--no-verify",
    "--ipv4", "-4", "--ipv6", "-6", "--atomic", "--no-atomic", "--thin", "--no-thin",
    "--signed", "--no-signed", "--recurse-submodules=check", "--recurse-submodules=on-demand",
    "--recurse-submodules=only", "--recurse-submodules=no", "--set-upstream", "-u",
  ])
  const rest = argv.slice(i + 1)
  let sawDashDash = false
  for (let k = 0; k < rest.length; k += 1) {
    const token = rest[k]
    if (!sawDashDash && token === "--") {
      sawDashDash = true
      continue
    }
    if (!sawDashDash && token.startsWith("-") && token !== "-") {
      if (token === "--force" || token === "--mirror" || token === "--delete") {
        return { kind: "push", dangerous: true }
      }
      if (token.startsWith("--force-with-lease") || token.startsWith("--force-if-includes")) {
        return { kind: "push", dangerous: true }
      }
      if (PUSH_SEPARATE_VALUE.has(token)) {
        k += 1
        if (k >= rest.length) return undefined
        continue
      }
      if (PUSH_FLAG_ONLY.has(token)) continue
      if (
        token.startsWith("--push-option=") ||
        token.startsWith("--receive-pack=") ||
        token.startsWith("--exec=") ||
        token.startsWith("--repo=") ||
        token.startsWith("--recurse-submodules=") ||
        token.startsWith("--signed=")
      ) {
        continue
      }
      if (token.startsWith("--")) return undefined // unknown long option
      if (/^-[a-zA-Z]*[fd][a-zA-Z]*$/.test(token)) return { kind: "push", dangerous: true }
      if (/^-[a-zA-Z]+$/.test(token)) continue // benign short cluster
      return undefined
    }
    // Refspecs and remote/ref names: `+` forces, leading `:` deletes.
    if (token.startsWith("+") || token.startsWith(":")) return { kind: "push", dangerous: true }
  }
  return { kind: "push", dangerous: false }
}

/**
 * Resolve literal argv to the position of the real command, following the
 * transparent launchers whose argv layout is understood (`sudo`, `doas`,
 * `env`, `nice`, `ionice`, `nohup`, `setsid`, `command`, `time`, `timeout`,
 * `busybox`). Executor leaves (`xargs`, `find -exec`, `ssh`, `sh -c`,
 * `eval`, `source`) resolve to their own index — their payloads are then
 * collected separately by nestedCommandStrings. Unknown flags on a launcher
 * report `unresolved` rather than guessing which token is the command.
 */
function resolveLiteralInvocation(argv: string[]): { index: number } | "unresolved" {
  let i = 0
  while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i])) i += 1
  for (let depth = 0; depth < 8; depth += 1) {
    const leaf = commandLeaf(argv[i] ?? "")
    if (!leaf) return "unresolved"
    if (leaf === "command") {
      const next = argv[i + 1]
      if (next === "-v" || next === "-V") return "unresolved"
      i += 1
      continue
    }
    if (leaf === "sudo" || leaf === "doas") {
      i += 1
      while (i < argv.length) {
        const token = argv[i]
        if (token === "--") {
          i += 1
          break
        }
        if (SUDO_OPERAND_FLAGS.has(token) || SUDO_OPERAND_FLAGS.has(token.toLowerCase())) {
          i += 2
          continue
        }
        if (token.startsWith("-")) {
          i += 1
          continue
        }
        break
      }
      if (i >= argv.length) return "unresolved"
      continue
    }
    if (leaf === "env") {
      i += 1
      while (i < argv.length) {
        const token = argv[i]
        if (token === "--") {
          i += 1
          break
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
          i += 1
          continue
        }
        if (ENV_OPERAND_FLAGS.has(token) || ENV_OPERAND_FLAGS.has(token.toLowerCase())) {
          i += 2
          continue
        }
        if (ENV_BOOL_FLAGS.has(token) || ENV_BOOL_FLAGS.has(token.toLowerCase())) {
          i += 1
          continue
        }
        if (token.startsWith("-")) return "unresolved"
        break
      }
      if (i >= argv.length) return "unresolved"
      continue
    }
    if (leaf === "timeout") {
      const remainder = strictTimeoutRemainder(argv.slice(i))
      if (remainder === undefined) return "unresolved"
      const inner = literalShellArgv(remainder)
      if (!inner || inner.length === 0) return "unresolved"
      argv = inner
      i = 0
      continue
    }
    if (leaf === "nohup" || leaf === "setsid" || leaf === "time") {
      i += 1
      while (i < argv.length && argv[i].startsWith("-")) {
        if (argv[i] === "--") {
          i += 1
          break
        }
        i += 1
      }
      if (i >= argv.length) return "unresolved"
      continue
    }
    if (leaf === "nice" || leaf === "ionice") {
      i += 1
      while (i < argv.length && argv[i].startsWith("-")) {
        const token = argv[i]
        if (token === "--") {
          i += 1
          break
        }
        if (leaf === "nice" && (token === "-n" || token === "--adjustment")) {
          i += 2
          continue
        }
        if (leaf === "ionice" && (token === "-c" || token === "-n" || token === "-p")) {
          i += 2
          continue
        }
        if (token === "-t" && leaf === "ionice") {
          i += 1
          continue
        }
        if (/^-\d+$/.test(token) || (leaf === "ionice" && /^-[cnpgt]\d*$/i.test(token))) {
          i += 1
          continue
        }
        return "unresolved"
      }
      if (i >= argv.length) return "unresolved"
      continue
    }
    if (leaf === "busybox") {
      i += 1
      continue
    }
    return { index: i }
  }
  return "unresolved"
}

/**
 * Command strings a resolved leaf hands to a child shell or process:
 * `find -exec`/`xargs` consumers, `ssh host cmd`, `sh -c`, `eval`/`source`
 * operands. The tokens are already literal words, so rejoining with spaces
 * re-lexes cleanly for the same bounded parser.
 */
function nestedCommandStrings(argv: string[], leafIndex: number): string[] {
  const leaf = commandLeaf(argv[leafIndex] ?? "")
  const args = argv.slice(leafIndex + 1)
  const out: string[] = []
  if (leaf === "find") {
    for (let j = 0; j < args.length; j += 1) {
      if (args[j] === "-exec" || args[j] === "-execdir" || args[j] === "-ok" || args[j] === "-okdir") {
        const consumer: string[] = []
        for (let k = j + 1; k < args.length && args[k] !== ";" && args[k] !== "+"; k += 1) {
          consumer.push(args[k])
        }
        if (consumer.length > 0) out.push(consumer.join(" "))
      }
    }
    return out
  }
  if (leaf === "xargs") {
    let j = 0
    for (; j < args.length; j += 1) {
      const token = args[j]
      if (token === "--") {
        j += 1
        break
      }
      if (XARGS_OPERAND_FLAGS.has(token) || XARGS_OPERAND_FLAGS.has(token.toLowerCase())) {
        j += 1
        continue
      }
      if (token.startsWith("-")) continue
      break
    }
    if (j < args.length) out.push(args.slice(j).join(" "))
    return out
  }
  if (leaf === "ssh" || leaf === "mosh") {
    // First non-option operand is the host; the rest is the remote command.
    let positionals = 0
    for (let j = 0; j < args.length; j += 1) {
      const token = args[j]
      if (token === "--") continue
      if (SSH_VALUE_FLAGS.has(token.toLowerCase()) || SSH_LONG_VALUE_FLAGS.has(token.toLowerCase())) {
        j += 1
        continue
      }
      if (token.startsWith("-") && token.length > 1) continue
      positionals += 1
      if (positionals >= 2) {
        out.push(args.slice(j).join(" "))
        break
      }
    }
    return out
  }
  if (["sh", "bash", "zsh", "dash", "ksh"].includes(leaf)) {
    for (let j = 0; j < args.length; j += 1) {
      const token = args[j]
      if (token === "-c" || /^-[a-z]*c[a-z]*$/i.test(token)) {
        if (args[j + 1] !== undefined) out.push(args[j + 1])
        return out
      }
    }
    return out
  }
  if (leaf === "eval" || leaf === "exec" || leaf === "source" || leaf === ".") {
    const rest = args.filter((token) => token !== "--")
    if (rest.length > 0) out.push(rest.join(" "))
    return out
  }
  return out
}

/** Every literal argv in `text` that sits in a position where it is
 *  executed: top-level segments plus the payloads understood executors run
 *  (xargs/find/ssh consumers and `sh -c`/`eval`/`source` operands). Returns
 *  undefined when the text cannot be lexed into literal argv at all — the
 *  caller then keeps the conservative whole-text scan. */
function literalInvocationArgvList(text: string, depth = 0): string[][] | undefined {
  if (depth > 4) return undefined
  const segments = splitSimpleSegments(text, "/bin/bash")
  if (!segments) return undefined
  const out: string[][] = []
  for (const segment of segments) {
    const argv = literalShellArgv(segment)
    if (!argv) return undefined
    if (argv.length === 0) continue
    const resolved = resolveLiteralInvocation(argv)
    if (resolved === "unresolved") return undefined
    const tail = argv.slice(resolved.index)
    if (tail.length === 0) return undefined
    out.push(tail)
    for (const payload of nestedCommandStrings(argv, resolved.index)) {
      const nested = literalInvocationArgvList(payload, depth + 1)
      if (!nested) return undefined
      out.push(...nested)
    }
  }
  return out
}

// --- proven-data literal masking (fix D) ------------------------------------
// Positive allowlist only: bare grep/egrep/fgrep, non-preprocessor rg, and
// `git commit` message arguments. Anything else — other leaves, env
// assignments, launchers, unrecognized option layouts, redirects, expansions
// — leaves the text untouched. Masking blanks proven-inert quoted spans in
// place (offsets preserved); it never adds, removes, or reorders characters.

/** `git commit` words whose quoted fragments may be masked as message data.
 *  Returns the indexes of `-m`/`--message` value words, or undefined when the
 *  invocation is not a recognizable commit. Only quoted fragments inside
 *  those words are masked — every other operand stays raw. */
function gitCommitMessageWordIndexes(argv: string[]): Set<number> | undefined {
  let i = 1 // argv[0] is `git`
  for (; i < argv.length; i += 1) {
    const token = argv[i]
    if (GIT_GLOBAL_SEPARATE_VALUE.has(token)) {
      i += 1
      continue
    }
    if (
      GIT_GLOBAL_FLAGS.has(token) ||
      (token.startsWith("-c") && token.length > 2) ||
      GIT_GLOBAL_ATTACHED_VALUE.some((prefix) => token.startsWith(prefix))
    ) {
      continue
    }
    if (token.startsWith("-")) return undefined
    break
  }
  if ((argv[i] ?? "").toLowerCase() !== "commit") return undefined
  const messageWords = new Set<number>()
  const VALUE_OPTIONS = new Set(["-m", "--message", "-F", "--file", "-t", "--template", "-c", "--reuse-message", "--reedit-message", "-C", "--amend-object"])
  for (let j = i + 1; j < argv.length; j += 1) {
    const token = argv[j]
    if (token === "--") break
    if (token === "-m" || token === "--message") {
      if (argv[j + 1] === undefined) return undefined
      messageWords.add(j + 1)
      j += 1
      continue
    }
    if (token.startsWith("-m") || token.startsWith("--message=")) {
      messageWords.add(j)
      continue
    }
    if (VALUE_OPTIONS.has(token)) {
      if (argv[j + 1] === undefined) return undefined
      j += 1
      continue
    }
    if (token.startsWith("--")) {
      const name = token.slice(2).split("=", 1)[0]
      const known = new Set([
        "all", "amend", "verbose", "quiet", "dry-run", "status", "no-status",
        "signoff", "no-signoff", "verify", "no-verify", "edit", "no-edit",
        "no-gpg-sign", "allow-empty", "allow-empty-message",
        "cleanup", "date", "author", "fixup", "squash", "reset-author",
        "branch", "untracked-files", "no-untracked-files", "only", "include",
        "pathspec-from-file", "pathspec-file-nul",
      ])
      if (!known.has(name)) return undefined
      if (token.includes("=")) continue
      // Bare `--cleanup`/`--date`/… consume a following value.
      if (["cleanup", "date", "author", "fixup", "squash", "untracked-files", "pathspec-from-file"].includes(name)) {
        j += 1
      }
      continue
    }
    if (/^-[a-zA-Z]+$/.test(token)) {
      // Short-option cluster: the FIRST value-taking letter (m/F/t/c/C)
      // consumes the cluster remainder or the next word. Only `-m`/`--message`
      // values are message data.
      const cluster = token.slice(1)
      const firstValueIdx = cluster.search(/[mFtcC]/)
      if (firstValueIdx === -1) continue
      const letter = cluster[firstValueIdx]
      const attached = cluster.slice(firstValueIdx + 1)
      if (letter === "m") {
        if (attached) messageWords.add(j)
        else {
          if (argv[j + 1] === undefined) return undefined
          messageWords.add(j + 1)
          j += 1
        }
        continue
      }
      if (!attached) j += 1 // separate value for -F/-t/-c/-C
      continue
    }
    // Pathspec / other operand: not a message word.
  }
  return messageWords
}

/**
 * Return `segment` with proven-inert quoted data spans blanked to spaces,
 * or undefined when the segment is not eligible. Eligibility is per-command:
 * every argument must resolve through the literal lexer (no expansions,
 * redirects, globs, or substitutions anywhere in the command), and only the
 * allowlisted leaves qualify.
 */
function dataLiteralView(segment: string): string | undefined {
  const detailed = literalShellArgvDetailed(segment)
  if (!detailed || detailed.words.length === 0) return undefined
  const { words, spans } = detailed
  const leaf = words[0]
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(leaf)) return undefined // env assignment

  let maskWords: Set<number> | undefined
  if (leaf === "grep" || leaf === "egrep" || leaf === "fgrep") {
    // Every argument is data for grep — mask all proven-inert quoted spans.
    maskWords = new Set(words.map((_, index) => index))
    maskWords.delete(0)
  } else if (leaf === "rg") {
    if (rgExecHazard(words.slice(1)) !== undefined) return undefined
    maskWords = new Set(words.map((_, index) => index))
    maskWords.delete(0)
  } else if (leaf === "git") {
    maskWords = gitCommitMessageWordIndexes(words)
    if (!maskWords) return undefined
  } else {
    return undefined
  }
  if (!maskWords || maskWords.size === 0) return undefined

  // Blank every proven-inert quoted span in the eligible words.
  const chars = segment.split("")
  let masked = 0
  for (const index of maskWords) {
    for (const span of spans[index] ?? []) {
      for (let k = span.start; k < span.end; k += 1) chars[k] = " "
      masked += 1
    }
  }
  return masked > 0 ? chars.join("") : undefined
}

/**
 * Full-script rule view: the comment-neutralized script, data heredoc bodies
 * removed, and proven-inert data spans of eligible commands blanked. Every
 * connector, pipeline structure, substitution, redirect, and executor body
 * stays visible; anything not positively proven inert is untouched.
 * Returns undefined when the script cannot be lexed (opaque fallback).
 */
function dataLiteralScriptView(script: string, shell: string): string | undefined {
  if (shellEscapeCharacter(shell) !== "\\") return undefined // POSIX-shaped shells only
  const commentView = commentNeutralizedView(script, shell)
  if (commentView === undefined) return undefined
  // Eligibility is script-wide: a definition or alias that rebinds an
  // eligible leaf disqualifies the whole script.
  if (/(?:^|[\n;|&])\s*(?:alias\s+(?:grep|egrep|fgrep|rg|git)\b|\b(?:grep|egrep|fgrep|rg|git)\s*\(\s*\))/i.test(commentView)) {
    return undefined
  }
  const masked = maskHeredocDataBodies(commentView, shell)
  const segments = splitSimpleSegments(masked, shell)
  if (!segments) return undefined
  const out: string[] = []
  for (const segment of segments) {
    out.push(dataLiteralView(segment) ?? segment)
  }
  return out.join("\n")
}

function hasGitRemoteHistoryRewrite(text: string): boolean {
  const invocations = literalInvocationArgvList(text)
  if (invocations === undefined) {
    // The text cannot be resolved to literal argv: keep the conservative
    // whole-text patterns so an unresolved layout cannot evade the floor.
    return legacyGitRemoteHistoryRewrite(text)
  }
  for (const argv of invocations) {
    const analysis = analyzeGitArgv(argv)
    if (analysis === undefined) return legacyGitRemoteHistoryRewrite(text)
    if (analysis.kind === "rewrite-subcommand") return true
    if (analysis.kind === "push" && analysis.dangerous) return true
  }
  return false
}

// --- executor capability gate (fix C) ---------------------------------------
// `rg --pre`, `git grep -O/--open-files-in-pager`, and the sed `e` family run
// a child command inside an otherwise read-shaped tool. Neither the RW
// known-safe list nor the RO read-only authorization may trust the outer
// leaf alone.

type ExecutorHazard =
  | { kind: "executor"; payloads: string[] } // a statically known payload executes
  | { kind: "unproven" } // the tool may execute, but the payload is not extractable

/**
 * Scan a sed script for the `e` family: a command-position `e` executes the
 * rest of its line as a shell command, and the substitution `e` flag executes
 * the pattern space after the substitution. Addresses (numbers, `$`, `/re/`
 * and `\%re%`, `,`/`+`/`~` range parts), `w`/`r` file operands, `a`/`i`/`c`
 * one-line text, and labels are skipped; anything unrecognized makes the
 * script unproven rather than guessed-safe.
 */
function sedScriptExecScan(script: string): { payloads: string[]; unproven: boolean } {
  const payloads: string[] = []
  let unproven = false
  let i = 0
  const n = script.length

  const skipDelimited = (delim: string): boolean => {
    // Positioned just after the delimiter; consumes to the next unescaped
    // occurrence of it.
    while (i < n) {
      if (script[i] === "\\") {
        i += 2
        continue
      }
      if (script[i] === delim) {
        i += 1
        return true
      }
      i += 1
    }
    return false
  }
  const skipTo = (stops: string) => {
    while (i < n && !stops.includes(script[i])) i += 1
  }

  while (i < n) {
    // Separators and blanks between commands.
    while (i < n && (script[i] === ";" || script[i] === "\n" || script[i] === " " || script[i] === "\t")) i += 1
    if (i >= n) break
    // GNU sed comments: `#` at command position runs to the newline.
    if (script[i] === "#") {
      skipTo("\n")
      continue
    }
    // Addresses: line numbers, `$`, `/re/` and `\%re%`, and range/step
    // separators before the command letter.
    for (;;) {
      const ch = script[i]
      if (ch === undefined) break
      if (/[0-9$,+~\s]/.test(ch)) {
        i += 1
        continue
      }
      if (ch === "/") {
        i += 1
        if (!skipDelimited("/")) {
          unproven = true
          return { payloads, unproven }
        }
        while (i < n && /[IMc]/.test(script[i])) i += 1 // regex modifiers
        continue
      }
      if (ch === "\\" && i + 1 < n && script[i + 1] !== "\n") {
        // `\%re%` alternative-delimiter address.
        const delim = script[i + 1]
        i += 2
        if (!skipDelimited(delim)) {
          unproven = true
          return { payloads, unproven }
        }
        continue
      }
      break
    }
    if (i >= n) break
    const cmd = script[i]
    i += 1
    switch (cmd) {
      case "e": {
        // `e cmd` executes to the newline (or end of script); bare `e`
        // executes the pattern space, which is input data — unproven.
        const start = i
        skipTo("\n")
        const payload = script.slice(start, i).replace(/;+$/, "").trim()
        if (payload) payloads.push(payload)
        else unproven = true
        continue
      }
      case "s": {
        if (i >= n) {
          unproven = true
          continue
        }
        const delim = script[i]
        i += 1
        if (!skipDelimited(delim)) {
          unproven = true
          continue
        }
        const replacementStart = i
        if (!skipDelimited(delim)) {
          unproven = true
          continue
        }
        const replacement = script.slice(replacementStart, i - 1)
        // Flag letters: `e` runs the result as a command; `w` writes the
        // space-separated file operand that follows it.
        let execs = false
        let writes = false
        while (i < n && /[A-Za-z0-9%]/.test(script[i])) {
          if (script[i] === "e") execs = true
          if (script[i] === "w") writes = true
          i += 1
        }
        if (writes) skipTo(";\n")
        if (execs) {
          // The executed text is the post-substitution pattern space; the
          // literal replacement is the closest statically-known payload.
          if (replacement.trim()) payloads.push(replacement)
          else unproven = true
        }
        continue
      }
      case "y": {
        if (i >= n) {
          unproven = true
          continue
        }
        const delim = script[i]
        i += 1
        if (!skipDelimited(delim) || !skipDelimited(delim)) unproven = true
        continue
      }
      case "w":
      case "W":
      case "r":
      case "R": {
        // File operand runs to `;`/newline (whitespace-trimmed by sed).
        skipTo(";\n")
        continue
      }
      case "a":
      case "i":
      case "c": {
        // One-line text command: optional `\` then literal text to newline.
        if (script[i] === "\\") i += 1
        skipTo("\n")
        continue
      }
      case "b":
      case "t":
      case "T": {
        skipTo(";\n")
        continue
      }
      case "q":
      case "Q":
      case "z":
      case "l":
      case "L": {
        while (i < n && /[0-9]/.test(script[i])) i += 1
        continue
      }
      case "v": {
        while (i < n && /[0-9.]/.test(script[i])) i += 1
        continue
      }
      case "d":
      case "D":
      case "p":
      case "P":
      case "n":
      case "N":
      case "h":
      case "H":
      case "g":
      case "G":
      case "x":
      case "F":
      case "=":
      case "{":
      case "}":
        continue
      default:
        unproven = true
        continue
    }
  }
  return { payloads, unproven }
}

/** sed script arguments: `-e`/`--expression` values (attached or separate)
 *  plus the first positional operand. `-f`/`--file` scripts are external and
 *  uninspectable here, so they are unproven. */
function sedExecHazard(args: string[]): ExecutorHazard | undefined {
  const scripts: string[] = []
  let positionalSeen = false
  let operandsOnly = false
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]
    if (!operandsOnly && token === "--") {
      operandsOnly = true
      continue
    }
    if (!operandsOnly && (token === "-e" || token === "--expression")) {
      const value = args[i + 1]
      if (value === undefined) return { kind: "unproven" }
      scripts.push(value)
      i += 1
      continue
    }
    if (!operandsOnly && token.startsWith("--expression=")) {
      scripts.push(token.slice("--expression=".length))
      continue
    }
    if (!operandsOnly && token === "-f") {
      return { kind: "unproven" } // external script file is not inspectable
    }
    if (!operandsOnly && token.startsWith("--file")) {
      return { kind: "unproven" }
    }
    if (!operandsOnly && token.startsWith("-e") && token.length > 2) {
      scripts.push(token.slice(2))
      continue
    }
    if (!operandsOnly && token.startsWith("-f") && token.length > 2) {
      return { kind: "unproven" }
    }
    if (!operandsOnly && token.startsWith("-") && token !== "-") continue
    if (!positionalSeen) {
      positionalSeen = true
      scripts.push(token)
    }
  }
  const payloads: string[] = []
  for (const script of scripts) {
    const scan = sedScriptExecScan(script)
    if (scan.unproven) return { kind: "unproven" }
    payloads.push(...scan.payloads)
  }
  return payloads.length > 0 ? { kind: "executor", payloads } : undefined
}

/** rg `--pre <cmd>`/`--pre=<cmd>` (and the `-M` short form) spawn an external
 *  preprocessor; a missing value means the default preprocessor executes.
 *  `--pre-glob` only selects files, it does not make the preprocessor safe. */
function rgExecHazard(args: string[]): ExecutorHazard | undefined {
  const payloads: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]
    if (token === "--") break
    if (token === "--pre" || token === "-M") {
      const value = args[i + 1]
      if (value === undefined) return { kind: "unproven" }
      payloads.push(value)
      i += 1
      continue
    }
    if (token.startsWith("--pre=")) {
      payloads.push(token.slice("--pre=".length))
      continue
    }
    if (/^-M\S+/.test(token)) {
      payloads.push(token.slice(2))
      continue
    }
  }
  return payloads.length > 0 ? { kind: "executor", payloads } : undefined
}

/** `git grep -O[cmd]`/`--open-files-in-pager[=cmd]` pipes matches through an
 *  external pager/command — including the no-value default-pager form. */
function gitGrepExecHazard(args: string[]): ExecutorHazard | undefined {
  const payloads: string[] = []
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i]
    if (token === "--") break
    if (token === "-O" || token === "--open-files-in-pager") {
      // The pager value is optional and only ever ATTACHED (`-Ocmd`,
      // `--open-files-in-pager=cmd`); a bare flag runs the default pager —
      // executor with no extractable payload.
      return { kind: "unproven" }
    }
    if (token.startsWith("--open-files-in-pager=")) {
      payloads.push(token.slice("--open-files-in-pager=".length))
      continue
    }
    if (/^-O\S+/.test(token)) {
      payloads.push(token.slice(2))
      continue
    }
    if (/^-[a-zA-Z]*O[a-zA-Z]*/.test(token) && token.includes("O")) {
      // `-O` inside a short-option cluster (`git grep -iO less`).
      return { kind: "unproven" }
    }
  }
  return payloads.length > 0 ? { kind: "executor", payloads } : undefined
}

/** Conservative invocation-capability check shared by the RW known-safe
 *  path and the RO read-only gate. Operates on literal argv of the original
 *  segment (after transparent launchers); an invocation that cannot be
 *  resolved is unproven only when its leaf is one of the gated tools. */
function executorCapabilityHazard(segment: string): ExecutorHazard | undefined {
  const argv = literalShellArgv(stripOutputRedirects(segment) ?? segment)
  if (argv === undefined) {
    const leaf = commandLeaf(simpleInvocationTokens(segment)[0] ?? "")
    return leaf === "sed" || leaf === "gsed" || leaf === "rg" ? { kind: "unproven" } : undefined
  }
  if (argv.length === 0) return undefined
  const resolved = resolveLiteralInvocation(argv)
  if (resolved === "unresolved") return undefined
  const leaf = commandLeaf(argv[resolved.index] ?? "")
  const args = argv.slice(resolved.index + 1)
  if (leaf === "sed" || leaf === "gsed") return sedExecHazard(args)
  if (leaf === "rg") return rgExecHazard(args)
  if (leaf === "git") {
    // Reuse the global-option skip so `git -C x grep -O…` resolves too.
    for (let i = 0; i < args.length; i += 1) {
      const token = args[i]
      if (GIT_GLOBAL_SEPARATE_VALUE.has(token)) {
        i += 1
        continue
      }
      if (
        GIT_GLOBAL_FLAGS.has(token) ||
        (token.startsWith("-c") && token.length > 2) ||
        GIT_GLOBAL_ATTACHED_VALUE.some((prefix) => token.startsWith(prefix))
      ) {
        continue
      }
      if (token.startsWith("-")) return undefined
      if (token.toLowerCase() !== "grep") return undefined
      return gitGrepExecHazard(args.slice(i + 1))
    }
  }
  return undefined
}

/** Forced deletion whose target is an absolute or home glob outside temp areas (`rm -rf /etc*`, `rm -rf ~/*`). */
function hasRootGlobDelete(text: string): boolean {
  const invocations =
    text.match(/\b(?:rm|remove-item|ri|del|erase|rmdir|rd)\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []
  return invocations.some((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    if (tokens.length < 2) return false
    const shape = forcedRecursiveShape(tokens)
    if (!shape.forced || shape.targets.length === 0) return false
    return shape.targets.some((target) => {
      const literal = stripMatchingQuotes(target).replaceAll("\\", "/").toLowerCase()
      if (!/[*?\[]/.test(literal)) return false
      if (literal.startsWith("/")) {
        return !(literal === "/tmp*" || literal.startsWith("/tmp/*") || literal === "/var/tmp*" || literal.startsWith("/var/tmp/*"))
      }
      if (literal.startsWith("~/") || literal.startsWith("$home/")) return true
      return false
    })
  })
}

/** DENY-both rules that need filesystem context: compression of sensitive files, tar --remove-files. */
function compressionDestructionFinding(segment: string, ctx: PathContext): SegmentDecision | undefined {
  const command = segmentCommandLeaf(segment)
  if (["gzip", "bzip2", "xz", "zip", "7z", "rar"].includes(command)) {
    for (const raw of extractReadPaths(segment)) {
      if (checkPathSensitivity(raw, ctx).sensitive) {
        return {
          verdict: "DENY",
          rules: ["filesystem.compression-sensitive"],
          reason: "Compressing or archiving credential or system files requires explicit filesystem and secret authorization",
        }
      }
    }
    return undefined
  }
  if (hasTarRemoveFiles(segment)) {
    for (const raw of extractReadPaths(segment)) {
      if (checkPathSensitivity(raw, ctx).sensitive) {
        return {
          verdict: "DENY",
          rules: ["data.critical-delete"],
          reason: "tar --remove-files on credential or system files requires explicit filesystem and secret authorization",
        }
      }
    }
    return {
      verdict: "ASK",
      rules: ["filesystem.tar-remove-files"],
      reason: "tar --remove-files permanently removes the archived files and requires review",
    }
  }
  return undefined
}

function hasExfilOrDangerousPerms(segment: string, text: string, ctx: PathContext): string | undefined {
  // curl/wget upload of a sensitive file
  const uploadPaths: string[] = []
  const uploadPatterns = [
    /(?:-d|--data|--data-binary|--data-raw)(?:=|\s+)@?(['"]?)([^\s'"=<]+)\1/gi,
    /(?:-F|--form)[^\n]*?=@(['"]?)([^\s'"]+)\1/gi,
    /--post-file(?:=|\s+)(['"]?)([^\s'"]+)\1/gi,
    /(?:\s|^)(?:-T|--upload-file)(?:\s+|=[^\s]+)/gi,
  ]
  for (const pattern of uploadPatterns) {
    for (const match of text.matchAll(pattern)) {
      if (pattern === uploadPatterns[3]) {
        // -T/--upload-file form: inline value or next token; skip a following URL.
        const matchText = match[0]
        const afterMatch = text.slice((match.index ?? 0) + matchText.length)
        const inline = /(?:-T|--upload-file)=([^\s]+)/i.exec(matchText.trim())
        if (inline) {
          uploadPaths.push(stripMatchingQuotes(inline[1] ?? ""))
        } else {
          const next = afterMatch.match(/^\s*("[^"]*"|'[^']*'|[^\s'"]+)/)
          const value = next ? stripMatchingQuotes(next[1] ?? "") : ""
          if (value && !/^https?:/i.test(value)) uploadPaths.push(value)
        }
        continue
      }
      uploadPaths.push(match[2] ?? "")
    }
  }
  if (uploadPaths.some((p) => checkPathSensitivity(p, ctx).sensitive)) return "exfiltration.sensitive-data"

  // scp: local sources before the `user@host:` token
  if (/\bscp\b/i.test(text)) {
    const tokens = simpleInvocationTokens(segment)
    let hostIndex = -1
    for (let i = 0; i < tokens.length; i += 1) {
      if (/^[^@\s]+@[^:\s]+:/.test(tokens[i] ?? "")) {
        hostIndex = i
        break
      }
    }
    if (hostIndex > 0) {
      for (let i = 1; i < hostIndex; i += 1) {
        const token = tokens[i] ?? ""
        if (token.startsWith("-")) continue
        if (checkPathSensitivity(token, ctx).sensitive) return "exfiltration.sensitive-data"
      }
    }
  }

  // nc/ncat stream from a sensitive file
  if (/\b(?:nc|ncat|netcat)\b/i.test(text)) {
    const stream = text.match(/\b(?:nc|ncat|netcat)\b[^\n]*<\s*['"]?([^\s'";|&]+)/i)
    if (stream && checkPathSensitivity(stream[1] ?? "", ctx).sensitive) return "exfiltration.sensitive-data"
  }

  // chmod 000/777 on a sensitive/credential path
  if (/\bchmod\b[^\n]*\s(?:0{3}|777)\b/i.test(text)) {
    const tokens = simpleInvocationTokens(segment)
    const args = tokens
      .slice(1)
      .filter(
        (token) =>
          !/^-(?:R|v|c|f|h)$/.test(token) &&
          !/^\d{3,4}$/.test(token) &&
          !/^(?:u|g|o|a)?[+-]=?[rwxXst]{1,3}$/.test(token),
      )
    if (args.some((p) => checkPathSensitivity(p, ctx).sensitive)) return "permissions.sensitive-mode"
  }

  return undefined
}

// ===== M3 (P2) §4.9 dedicated-safe whitelist helpers =======================

function tarOrUnzipBaseWorktree(segment: string, cwd: string, worktree: string): boolean {
  // returns true when every -C / -d target (or the default cwd) is inside the worktree
  const dirs = [...segment.matchAll(/\s-C\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const unzipDirs = [...segment.matchAll(/\s-d\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const bases = dirs.length > 0 ? dirs : unzipDirs.length > 0 ? unzipDirs : ["."]
  if (bases.length === 0) return false
  return bases.every((dir) => {
    const resolved = resolveLexical(dir, cwd, expandHome("~"))
    return Boolean(resolved.absolute && isWithinLexical(worktree, resolved.absolute))
  })
}

function classifyTarExtractOrUnzip(
  segment: string,
  ctx: PathContext,
  strictness: "LOOSE" | "HARD",
  isUnzip: boolean,
): SegmentDecision | undefined {
  const isExtract = isUnzip ? /^unzip\b/i.test(segment) : /^tar\b/i.test(segment)
  if (!isExtract) return undefined
  if (!isUnzip && /(?:--absolute-names|--remove-files)\b/i.test(segment)) return undefined
  if (!tarOrUnzipBaseWorktree(segment, ctx.cwd, ctx.worktree)) {
    if (strictness === "HARD") {
      return {
        verdict: "DENY",
        rules: ["filesystem.tar-extract-system"],
        reason: "Extracting an archive into a non-worktree location is blocked by filesystem policy because it can write outside the tracked worktree",
      }
    }
    return {
      verdict: "ASK",
      rules: ["filesystem.tar-extract-system"],
      reason: "Extracting an archive outside the working tree requires review",
    }
  }
  // Check -C/-d targets (or default ".") with classifyPathTarget for git-hooks/sensitive writes
  const dirs = [...segment.matchAll(/\s-C\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const unzipDirs = [...segment.matchAll(/\s-d\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const hasExplicitTarget = isUnzip ? unzipDirs.length > 0 : dirs.length > 0
  const targets = hasExplicitTarget ? (isUnzip ? unzipDirs : dirs) : ["."]
  for (const dir of targets) {
    const targetFinding = classifyPathTarget(dir, "write", ctx)
    if (targetFinding.kind === "deny") return { verdict: "DENY", rules: [targetFinding.rule], reason: targetFinding.reason }
    if (targetFinding.kind === "ask") return { verdict: "ASK", rules: [targetFinding.rule], reason: targetFinding.reason }
  }
  // Extract without explicit -C/-d: archive content can't be proven safe, so don't ALLOW
  const isExtractMode = isUnzip || /^tar\s+x/i.test(segment) || /(?:^|\s)-\w*x/i.test(segment) || /--extract|--get/i.test(segment)
  if (isExtractMode && !hasExplicitTarget) {
    return { verdict: "ASK", rules: ["operation.archive-extract"], reason: "Archive extraction target is unscoped; contents cannot be verified" }
  }
  const finding = analyzeSegmentPaths(segment, ctx)
  if (finding.kind === "pass") {
    return {
      verdict: "ALLOW",
      rules: ["operation.archive-extract"],
      reason: "Archive extracts into a recognized working-tree location",
    }
  }
  return { verdict: finding.kind === "deny" ? "DENY" : "ASK", rules: [finding.rule], reason: finding.reason }
}

function isSafeDownloadTarget(segment: string, ctx: PathContext): boolean {
  // curl/wget writing a worktree file from an https URL, no upload / eval flags
  if (!/^curl\b|^wget\b/i.test(segment)) return false
  if (/\b(?:-d|--data(?:\-raw|\-binary)?|-F|--form|--post-file|--upload-file|-T)\b/i.test(segment)) return false
  if (/-A\b|--user-agent\b/.test(segment)) return false
  if (!/\shttp(s)?:\/\/|^curl\b[^\n]*https?:\/\//i.test(segment)) return false
  if (!/(?:^|\s)-(?:o|O)\b|\s--(?:output|remote-name)\b/.test(segment)) return false
  if (!tarOrUnzipBaseWorktree(segment, ctx.cwd, ctx.worktree)) return false
  return analyzeSegmentPaths(segment, ctx).kind === "pass"
}

function safeChmodSegment(segment: string, cwd: string, worktree: string): boolean {
  const tokens = simpleInvocationTokens(segment.trim())
  if (commandLeaf(tokens[0] ?? "") !== "chmod") return false
  if (/\b-R\b|--recursive\b/i.test(segment)) return false
  const modeIndex = tokens.findIndex((t) => /^[0-7]{3,4}$/.test(t) || /^[ugoa]*[+-=][rwxXst]+$/.test(t))
  if (modeIndex === -1) return false
  const mode = tokens[modeIndex] ?? ""
  const safeOctal = /^(?:600|640|644|700|750|755|660)$/.test(mode)
  const safeSymbolic = /^\+x$/.test(mode) || /^-[xw]+$/.test(mode)
  if (!safeOctal && !safeSymbolic) return false
  const targets = tokens.slice(modeIndex + 1).filter((t) => !/^-[A-Za-z]/.test(t) && !t.startsWith("--"))
  if (targets.length === 0) return false
  return targets.every((t) => {
    if (t.startsWith("~") || t.startsWith("$HOME")) return true
    const resolved = resolveLexical(t, cwd, expandHome("~"))
    return Boolean(resolved.absolute && isWithinLexical(worktree, resolved.absolute))
  })
}

// Locate simple shell substitutions without treating single-quoted examples as
// execution. Escaped/nested legacy backticks stay conservative rather than
// guessing their special quote-removal semantics.
function substitutionSpans(text: string): Array<{ start: number; end: number; body: string }> {
  const spans: Array<{ start: number; end: number; body: string }> = []
  let quote = ""
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quote === "'") { if (c === "'") quote = ""; continue }
    if (c === "\\") { i++; continue }
    if (c === "'" && !quote) { quote = c; continue }
    if (c === '"') { quote = quote === '"' ? "" : '"'; continue }
    if (c === "`") {
      const end = text.indexOf("`", i + 1)
      if (end < 0) return []
      const body = text.slice(i + 1, end)
      if (body.includes("\\")) return []
      spans.push({ start: i, end: end + 1, body }); i = end
    } else if (c === "$" && text[i + 1] === "(" && text[i + 2] !== "(") {
      let depth = 1, innerQuote = "", j = i + 2
      for (; j < text.length; j++) {
        const ch = text[j]
        if (innerQuote === "'") { if (ch === "'") innerQuote = ""; continue }
        if (ch === "\\") { j++; continue }
        if (ch === "'" && !innerQuote) { innerQuote = ch; continue }
        if (ch === '"') { innerQuote = innerQuote === '"' ? "" : '"'; continue }
        if (innerQuote) continue
        if (ch === "(") depth++
        if (ch === ")" && --depth === 0) break
      }
      if (depth !== 0) return []
      spans.push({ start: i, end: j + 1, body: text.slice(i + 2, j) }); i = j
    }
  }
  return spans
}

function commandSubstitutionBodies(text: string): string[] {
  return substitutionSpans(text).map((span) => span.body)
}

function maskCommandSubstitutions(text: string): string {
  let out = "", end = 0
  for (const span of substitutionSpans(text)) {
    out += text.slice(end, span.start) + "x"
    end = span.end
  }
  return out + text.slice(end)
}

function isSafeSubstitutionSurface(text: string, shell: string, ctx: PathContext, depth = 0): boolean {
  if (depth > 6) return false
  if (shellEscapeCharacter(shell) === "`" && text.includes("`")) return false
  const subs = commandSubstitutionBodies(text)
  const masked = maskCommandSubstitutions(text)
  const stripped = stripOutputRedirects(masked) ?? masked
  if (analyzeSegmentPaths(masked, ctx).kind !== "pass") return false
  // Substitution output is unknown: do not feed it to a file-reading command.
  if (subs.length && !/^(?:echo|printf|ls)\b/.test(masked.trim())) return false
  const pieces = splitSimpleSegments(stripped, shell)
  if (!pieces?.length || pieces.some((piece) =>
    !/^(?:echo|printf|pwd|date|uname|hostname|whoami|ls|head|tail|wc|grep|rg|basename|dirname)\b/.test(piece.trim()) ||
    !isKnownSafeSegment(piece) || analyzeSegmentPaths(piece, ctx).kind !== "pass"
  )) return false
  if (hasUnquotedExpansion(maskHeredocDataBodies(stripped, shell), shell)) return false
  if (hasSensitiveEnvPrefix(stripped)) return false
  if (analyzeSegmentPaths(stripped, ctx).kind !== "pass") return false
  for (const body of subs) {
    if (!isSafeSubstitutionSurface(body, shell, ctx, depth + 1)) return false
  }
  return true
}

const DISPOSABLE_DIR_NAMES = [
  "node_modules", "dist", "build", "coverage", "target", ".cache", ".pytest_cache",
  "__pycache__", ".venv", ".next", ".turbo", ".nuxt", "out", ".gradle",
  // Generated-artifact directories commonly produced by toolchains.
  "venv", ".tox", ".mypy_cache", ".ruff_cache", ".nyc_output", ".parcel-cache",
  ".sass-cache", "storybook-static", "playwright-report", "test-results",
  ".angular", ".dart_tool", "htmlcov", ".eggs",
]
const DISPOSABLE_NAME_SOURCE = DISPOSABLE_DIR_NAMES.join("|")
const DISPOSABLE_TARGET_PATTERN = new RegExp(
  `^(?:\\.?[\\\\/])?(?:${DISPOSABLE_NAME_SOURCE})[\\\\/]?$`,
  "i",
)

type RecursiveForceDeletion = { targets: string[] }

/**
 * Parses `rm`/`Remove-Item` invocations that are provably recursive+force,
 * whatever the flag spelling (`-rf`, `-r -f`, `--recursive --force`,
 * `-Recurse -Force`, interleaved clusters). Unknown flags make the whole
 * invocation unparseable so it can never reach the cleanup exemption.
 */
function parseRecursiveForceDeletion(segment: string): RecursiveForceDeletion | undefined {
  const match = segment.match(/^(?:rm|remove-item|ri)\s+([^;&|]+)$/i)
  if (!match) return undefined
  const tokens = match[1].match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
  let sawRecursive = false
  let sawForce = false
  const targets: string[] = []
  const valueFlags = new Set([
    "-erroraction", "-warningaction", "-informationaction",
    "-errorvariable", "-warningvariable", "-outvariable", "-outbuffer", "-pipelinevariable",
  ])
  for (let index = 0; index < tokens.length; index += 1) {
    const raw = tokens[index] ?? ""
    const flag = raw.toLowerCase()
    if (flag === "--") continue
    if (flag === "-path" || flag === "-literalpath") {
      const next = tokens[index + 1]
      if (!next) return undefined
      targets.push(next)
      index += 1
      continue
    }
    if (raw.startsWith("-")) {
      if (flag === "-r" || flag === "-recurse" || flag === "--recursive") sawRecursive = true
      else if (flag === "-f" || flag === "-force" || flag === "--force") sawForce = true
      else if (/^-[dfirvRI]+$/.test(raw)) {
        if (/[rR]/.test(raw.slice(1))) sawRecursive = true
        if (/f/i.test(raw.slice(1))) sawForce = true
      } else if (flag === "-confirm:$false") {
        // PowerShell confirmation suppressor, no value.
      } else if (valueFlags.has(flag)) {
        if (!tokens[index + 1]) return undefined
        index += 1
      } else {
        return undefined
      }
      continue
    }
    targets.push(raw)
  }
  if (!sawRecursive || !sawForce || targets.length === 0) return undefined
  return { targets }
}

/** A target qualifies when any of its own path segments is a disposable name. */
function disposableTargetEligible(literal: string): boolean {
  const normalizedTarget = literal.replaceAll("\\", "/").replace(/\/+$/, "")
  if (DISPOSABLE_TARGET_PATTERN.test(normalizedTarget)) return true
  return normalizedTarget.split("/").some((segment) => DISPOSABLE_DIR_NAMES.includes(segment.toLowerCase()))
}

async function validateDisposableLiteral(literal: string, cwd: string, worktree: string): Promise<boolean> {
  if (literal.split(/[\\/]/).includes("..")) return false
  if (!disposableTargetEligible(literal)) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  if (resolved.absolute === undefined || !isWithinLexical(worktree, resolved.absolute)) return false
  // Require the realpath of the target to be strictly within realpath(worktree),
  // preventing symlink-prefix escapes (link→/tmp then rm -rf link/node_modules).
  const canonical = await canonicalProjectedPath(resolved.absolute)
  if (!canonical) return false
  const worktreeReal = await canonicalProjectedPath(worktree)
  if (!worktreeReal) return false
  return isWithin(worktreeReal, canonical)
}

async function isDisposableCleanupTarget(target: string, cwd: string, worktree: string): Promise<boolean> {
  const trimmed = target.trim()
  const literal = literalPathToken(trimmed)
  if (literal) return validateDisposableLiteral(literal, cwd, worktree)
  // Brace-expanded targets fail literalPathToken ({} are rejected there);
  // expand and require every candidate to be an eligible disposable path.
  if (trimmed.includes("{") && trimmed.includes("}")) {
    const candidates = braceExpansionCandidates(trimmed)
    if (candidates.length === 0) return false
    for (const candidate of candidates) {
      const expanded = literalPathToken(candidate)
      if (expanded === undefined || !(await validateDisposableLiteral(expanded, cwd, worktree))) return false
    }
    return true
  }
  return false
}

async function isDisposableDirectoryDelete(script: string, cwd: string, worktree: string): Promise<boolean> {
  const value = stripLeadingDirectoryChanges(script).replace(/\s+/g, " ").trim()
  const deletion = parseRecursiveForceDeletion(value)
  if (!deletion) return false
  for (const t of deletion.targets) {
    if (!(await isDisposableCleanupTarget(t, cwd, worktree))) return false
  }
  return true
}

function classifySafeChmod(segment: string, ctx: PathContext, strictness: "LOOSE" | "HARD"): SegmentDecision | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  if (commandLeaf(tokens[0] ?? "") !== "chmod") return undefined
  if (safeChmodSegment(segment, ctx.cwd, ctx.worktree)) {
    return { verdict: "ALLOW", rules: ["permissions.lockdown"], reason: "Setting safe, standard file permissions" }
  }
  return undefined
}

const SECURITY_SIGNAL_RULES: Rule[] = [
  {
    id: "filesystem.find-delete",
    reason: "Recursive find deletion requires review",
    test: (text) => /\bfind\b[^\r\n;&|]*(?:^|\s)-delete(?:\s|$)/im.test(text),
  },
  {
    id: "process.termination",
    reason: "Process termination requires review",
    test: (text) => /\b(?:kill|pkill|killall|taskkill|stop-process)\b/i.test(text),
  },
  {
    id: "filesystem.forced-recursive-delete",
    reason: "Force-recursive directory deletion",
    test: hasForcedRecursiveDeleteLiteralTarget,
  },
  {
    id: "filesystem.root-delete",
    reason: "Attempts broad recursive deletion at a filesystem, home, or system-critical root",
    test: (text) =>
      // `rm -rf /`, `/etc`, `/usr`, `/boot`, ... — system-critical roots are
      // floor: never bypassable by the filesystem category. The system-root
      // alternative matches the bare root or a DIRECT glob over it
      // (`/etc/*`, `/etc*`), never a deeper path (`/var/tmp/...`,
      // `/home/user/project/...`) — those are scoped deletions the filesystem
      // bypass covers. Keep this list in sync with isDangerousFindRoot.
      /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--no-preserve-root\s+)?(?:\/|~\/?|\.\.?\/?|\*)(?:\s|$|[;&|])/im.test(
        text,
      ) ||
      new RegExp(
        `\\brm\\s+(?:-[a-z]*[rf][a-z]*\\s+)+(?:--no-preserve-root\\s+)?\\/(?:${SYSTEM_CRITICAL_ROOTS.join("|")})(?:\\*|\\/\\*|\\/)?(?=[\\s;&|]|$)`,
        "im",
      ).test(normalizedRootDeleteText(text)) ||
      /\b(?:rmdir|rd)\s+\/s\s+\/q\s+(?:[a-z]:\\|\\|\/|\.\.?|\*)(?:\s|$)/im.test(text) ||
      /\bdel\s+\/[a-z]*s[a-z]*\s+\/[a-z]*q[a-z]*\s+(?:[a-z]:\\|\\|\/|\*)(?:\s|$)/im.test(text) ||
      /\bremove-item\b[^\n]*(?:-recurse[^\n]*-force|-force[^\n]*-recurse)[^\n]*(?:[a-z]:\\(?:\*|$)|\/(?:\*|$)|~(?:\/|\s|$)|\.\.?(?:\/|\s|$)|\*)(?:\s|$)/im.test(
        text,
      ),
  },
  {
    id: "filesystem.disk-destruction",
    reason: "Attempts to format, overwrite, destroy a disk/filesystem, or create a device node",
    test: (text) =>
      /\b(?:mkfs(?:\.\w+)?|wipefs|fdisk|parted)\b/i.test(text) ||
      /\bmknod\b/i.test(text) ||
      /\bshred\b[^\n]*\/dev\/(?:sd|nvme|vd|hd|xvd|mmcblk|dasd)[a-z0-9-]*\b/i.test(text) ||
      /\bformat(?:\.com)?\s+[a-z]:/i.test(text) ||
      /\bdiskpart\b[\s\S]{0,500}\bclean(?:\s+all)?\b/i.test(text) ||
      /\bdd\b[^\n]*(?:if=\/dev\/(?:zero|urandom|random))[^\n]*of=\/dev\/(?:sd|nvme|vd|xvd)/i.test(text),
  },
  {
    id: "filesystem.backup-destruction",
    reason: "Attempts to delete snapshots, recovery data, or backup catalogs",
    test: (text) =>
      /\bvssadmin\b[^\n]*\bdelete\s+shadows\b/i.test(text) ||
      /\bwmic\b[^\n]*shadowcopy[^\n]*\bdelete\b/i.test(text) ||
      /\bwbadmin\b[^\n]*\bdelete\b/i.test(text) ||
      /\b(?:zfs\s+destroy|btrfs\s+subvolume\s+delete)\b/i.test(text),
  },
  {
    id: "system.service-destruction",
    reason: "Attempts to stop, disable, delete, or mask an operating-system service",
    test: (text) =>
      /\bsystemctl\s+(?:stop|disable|mask)\b/i.test(text) ||
      /\bservice\s+\S+\s+(?:stop|disable)\b/i.test(text) ||
      /\bsc(?:\.exe)?\s+(?:stop|delete|config)\b/i.test(text) ||
      /\b(?:stop-service|set-service)\b/i.test(text) ||
      /\blaunchctl\s+(?:unload|bootout|disable)\b/i.test(text),
  },
  {
    id: "system.shutdown",
    reason: "Attempts to shut down or reboot the host",
    test: hasHostShutdownCommand,
  },
  {
    id: "system.critical-process-kill",
    reason: "Attempts broad or critical forced process termination",
    test: (text) =>
      /\bkill\s+-(?:[a-z]*9|[A-Z]*KILL|TERM|INT|HUP)\s+(?:-1|0|1)\b/i.test(text) ||
      /\b(?:pkill|killall)\b[^\n]*(?:-9|-KILL)\b/i.test(text) ||
      /\b(?:pkill|killall)\b[^\n]*\s(?:systemd|init)\b/i.test(text) ||
      /\btaskkill\b[^\n]*\/f[^\n]*(?:\/im\s+\*|\/pid\s+(?:0|4)\b)/i.test(text),
  },
  {
    id: "database.destructive-statement",
    reason: "Attempts destructive database operations",
    test: (text) =>
      /\b(?:drop\s+(?:database|schema|table)|truncate\s+table|delete\s+from)\b/i.test(text) ||
      /\b(?:flushall|flushdb)\b/i.test(text) ||
      /\bdropDatabase\s*\(/i.test(text),
  },
  {
    id: "infrastructure.destructive-operation",
    reason: "Attempts destructive container, cluster, cloud, or infrastructure operations",
    test: (text) =>
      /\bterraform\s+destroy\b/i.test(text) ||
      /\bkubectl\s+delete\s+(?:namespace|ns|persistentvolume|pv|persistentvolumeclaim|pvc)\b/i.test(text) ||
      /\bdocker\s+(?:volume\s+rm|system\s+prune[^\n]*-a)\b/i.test(text) ||
      /\bdocker\s+(?:volume\s+prune\s+-a|image\s+prune\s+-a|rmi\s+-f\b)\b/i.test(text) ||
      /\baws\s+s3\s+rm\b[^\n]*--recursive\b/i.test(text) ||
      /\bgcloud\s+[^\n]*\bdelete\b[^\n]*(?:project|cluster|instance)\b/i.test(text),
  },
  {
    id: "filesystem.find-delete-root",
    reason: "Recursive find deletion under a system, home, or filesystem root",
    test: findDangerousDeleteRoot,
  },
  {
    id: "execution.xargs-destructive",
    reason: "Pipes files into a destructive command via xargs",
    test: (text) =>
      /\|\s*xargs\b[^\n]*\b(?:rm|shred|srm|wipe|unlink|rmdir|rd|del|erase|remove-item)\b/i.test(text) ||
      /\|\s*(?:remove-item|ri)\b/i.test(text),
  },
  {
    id: "execution.fork-bomb",
    reason: "Contains a shell fork-bomb (process storm) primitive",
    test: hasForkBomb,
  },
  {
    id: "filesystem.kernel-trigger",
    reason: "Attempts to write the kernel sysrq trigger or crash mechanisms",
    // Command-position anchored: redirect/dd-of writes (baseline form) plus
    // `tee`/`cp`/`mv`/`rsync`/`install` as the command word, with the trigger
    // as the trailing destination (optionally quoted, followed by end, a
    // separator, a comment, or a redirection). Command-word anchoring keeps
    // `echo tee /proc/...` from matching; the trailing-destination form keeps
    // `cp /proc/sysrq-trigger /tmp/x` (source read) from matching. Pipe forms
    // span `|` segment splits, so the full-script floor check runs these too.
    test: (text) => kernelWriteTest(text, "/proc/sysrq-trigger"),
  },
  {
    id: "filesystem.kernel-core-pattern",
    reason: "Attempts to set a piped core_pattern (kernel code execution)",
    // Any write to core_pattern is the floor: redirect/dd-of, tee, or copy
    // commands with it as the trailing destination, plus the sysctl spelling
    // (`sysctl -w kernel.core_pattern=...`), which is a kernel-execution
    // primitive the floor must not lose.
    test: (text) => kernelWriteTest(text, "/proc/sys/kernel/core_pattern") || /\bsysctl\s+(?:-[a-z]*w[a-z]*\s+)?kernel\.core_pattern\s*=/i.test(text),
  },
  {
    id: "permissions.root-recursive",
    reason: "Recursively locks or opens permissions on a system/root directory",
    test: (text) =>
      /\bchmod\b\s+-R\s+(?:0|000|777)\b[^\n]*\s+(?:\/|~\/?|\/etc\b|\/usr\b|\/bin\b|\/sbin\b|\/boot\b|\/var\b|\/home\b|\/root\b|\/opt\b)/i.test(
        text,
      ),
  },
  {
    id: "execution.kernel-module-load",
    reason: "Loads or removes a kernel module in the running kernel",
    test: (text) =>
      /\b(?:insmod|rmmod)\b/i.test(text) || /(?:^|[\s;])modprobe\b[^\n]*(?:\s+-\w+)*\s+(?!-)([A-Za-z0-9_+.:-]+)/i.test(text),
  },
  {
    id: "filesystem.compression-root",
    reason: "Recursively compressing the filesystem root is destructive",
    test: (text) => /\bgzip\b\s+(?:-\w+\s+)*-r\b\s+\//i.test(text),
  },
  {
    id: "execution.script-one-liner-destructive",
    reason: "A script one-liner performs destructive filesystem operations",
    test: hasDestructiveOneLiner,
  },
  {
    id: "filesystem.brace-root-delete",
    reason: "Forced-recursive deletion of brace-expanded system roots",
    test: hasDangerousBraceDelete,
  },
  {
    id: "git.irrecoverable-change",
    reason: "Attempts to discard local work or rewrite shared Git history",
    test: (text) =>
      /\bgit\s+clean\b(?=[^\n;|&]*\s-[a-z]*f)(?=[^\n;|&]*\s-[a-z]*d)(?=[^\n;|&]*\s-[a-z]*x)/i.test(text) ||
      /\bgit\s+reset\s+--hard\b/i.test(text) ||
      /\bgit\s+(?:checkout|restore)\s+-{0,2}\s*[.*]/i.test(text) ||
      /\bgit\s+branch\b[^\n;|&]*\s-D\b/.test(text) ||
      // Plain force push is covered by git.remote-history-rewrite (remote
      // category); only the safer --force-with-lease stays a review signal
      // here. Case-sensitive `-D`: lowercase -d only deletes merged branches.
      /\bgit\s+push\b[^\n]*--force-with-lease\b/i.test(text),
  },
  {
    id: "git.remote-history-rewrite",
    reason: "Attempts to rewrite or delete shared remote Git history",
    test: hasGitRemoteHistoryRewrite,
  },
  {
    id: "filesystem.root-glob-delete",
    reason: "Forced recursive deletion of an absolute glob path outside temp areas",
    test: hasRootGlobDelete,
  },
  {
    id: "execution.remote-pipe",
    reason: "Downloads remote content and immediately executes it",
    test: (text) =>
      /\b(?:curl|wget|invoke-webrequest|iwr|irm)\b[\s\S]{0,1000}(?:\||&&|;|\r?\n)[\s\S]{0,300}\b(?:bash|sh|zsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node|powershell|pwsh|invoke-expression|iex)\b/i.test(
        text,
      ),
  },
  {
    id: "permissions.world-writable",
    reason: "Attempts to grant dangerously broad filesystem permissions",
    test: (text) =>
      /\bchmod\b[^\n]*(?:-R\s+)?777\b/i.test(text) ||
      // World-writable octal modes: the last digit grants other-write
      // (666, 767, 0666, …). 644/750/4755 shapes stay out.
      /\bchmod\b[^\n]*\s[0-7]{1,3}[2367]\b/i.test(text) ||
      // Symbolic other-write grants: o+w, a+w, go+w, ugo+w, bare +w
      // (never u+w or g+w — no other-write there).
      /\bchmod\b[^\n]*\s(?:[oa]|go|ugo)?\+w\b/i.test(text) ||
      /\bicacls\b[^\n]*\/grant[^\n]*(?:Everyone|Users):\(?(?:F|M)\)?/i.test(text),
  },
  {
    id: "persistence.backdoor",
    reason: "Attempts to create a persistent scheduled or startup execution mechanism",
    test: (text) =>
      hasCrontabPersistence(text) ||
      /\bschtasks\b[^\n]*\/create\b/i.test(text) ||
      /\\CurrentVersion\\Run(?:Once)?\b/i.test(text) ||
      /\b(?:systemctl\s+enable|launchctl\s+enable)\b/i.test(text) ||
      /\b(?:at|systemd-run)\s+(?:now\b|--on-)/i.test(text),
  },
  {
    id: "network.reverse-shell",
    reason: "Contains a reverse-shell or remote-control primitive",
    test: (text) =>
      hasAttachedDevSocket(text) ||
      /\b(?:nc|ncat|netcat)\b[^\n]*(?:\s-e\s|\s--exec\s)/i.test(text) ||
      /\bsocat\b[^\n]*(?:\s(?:EXEC|SYSTEM|EXEC):)/i.test(text) ||
      /\bmkfifo\b[^\n]*(?:\|\s*(?:cat|sh|bash)[^\n]*\|\s*(?:nc|ncat|netcat))/i.test(text) ||
      /\bsocket\.connect\s*\([^)]*\)[^\n]{0,200}(?:subprocess|dup2|os\.system|popen)/i.test(text) ||
      /(?:subprocess\.(?:Popen|call|run)\s*\([^\n]*\/bin\/(?:sh|bash)|cp\.spawn\s*\(\s*["']sh["']|TCPSocket\.new\s*\([^)]*\)[^\n]{0,120}(?:IO\.popen|Kernel\.(?:system|exec))|fsockopen\s*\([^)]*\)[^\n]{0,120}(?:exec|system|popen)|TCPClient|Socket::And|exec\s*\(\s*["']\/bin\/sh[^)]*\))/i.test(
        text,
      ),
  },
  {
    id: "credentials.sensitive-access",
    reason: "Attempts to access credentials, private keys, process secrets, or credential material",
    test: hasSensitiveCredentialReference,
  },
  {
    id: "network.dev-socket",
    reason:
      "Opens a bash /dev/tcp or /dev/udp socket without attaching a shell; may be a benign connectivity probe and requires review",
    test: (text) => /\/dev\/(?:tcp|udp)\//i.test(text),
  },
  {
    id: "network.destructive-api",
    reason: "Attempts to invoke a destructive remote API operation",
    test: (text) =>
      /\brequests\.delete\s*\(/i.test(text) ||
      /\b(?:curl|Invoke-RestMethod|irm)\b[^\n]*(?:-X|--request|-Method)\s+DELETE\b/i.test(text),
  },
]

const DEFINITE_DESTRUCTIVE_RULES = new Set([
  "filesystem.forced-recursive-delete",
  "filesystem.root-delete",
  "filesystem.root-glob-delete",
  "filesystem.disk-destruction",
  "filesystem.backup-destruction",
  "system.service-destruction",
  "system.shutdown",
  "system.critical-process-kill",
  "database.destructive-statement",
  "infrastructure.destructive-operation",
  "network.reverse-shell",
  "filesystem.find-delete-root",
  "execution.xargs-destructive",
  "execution.fork-bomb",
  "filesystem.kernel-trigger",
  "filesystem.kernel-core-pattern",
  "permissions.root-recursive",
  "execution.kernel-module-load",
  "filesystem.compression-root",
  "execution.script-one-liner-destructive",
  "filesystem.brace-root-delete",
  "git.remote-history-rewrite",
])

/**
 * Rules that DENY in HARD mode and downgrade to an ASK review signal in LOOSE.
 * Mirrors the plan: destructive operations the HARD (injected-agent) model must
 * never auto-run, but good-faith LOOSE work may still be reviewed by the
 * dynamic layer (e.g. official installers).
 */
const HARD_DENY_LOOSE_ASK_RULES: { id: string; reason: string; test: (text: string) => boolean }[] = [
  {
    id: "execution.remote-pipe",
    reason: "Downloads remote content and immediately executes it",
    test: (text) =>
      /\b(?:curl|wget|invoke-webrequest|iwr|irm)\b[\s\S]{0,1000}(?:\||&&|;|\r?\n)[\s\S]{0,300}\b(?:bash|sh|zsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node|powershell|pwsh|invoke-expression|iex)\b/i.test(
        text,
      ),
  },
  {
    id: "kernel.sysctl-write",
    reason: "Modifying kernel parameters requires review",
    test: (text) => /\bsysctl\b[^\n]*\s-w\b/i.test(text),
  },
  {
    id: "infrastructure.privileged-container",
    reason: "Running a privileged container or mounting the Docker socket requires review",
    // Engine set and flag semantics mirror the sandbox privilege router:
    // docker/podman/nerdctl; `--privileged` is a boolean flag so an explicit
    // `--privileged=false` does not count; `--pid` accepts `=host` and the
    // space-separated `host` argument form.
    test: (text) =>
      /\b(?:docker|podman|nerdctl)\s+run\b[^\n]*(?:--privileged\b(?!\s*=\s*false\b)|--pid(?:=|\s+)host\b|-v\s+\/var\/run\/docker\.sock\b|--host=unix:\/\/\/var\/run\/docker\.sock\b)/i.test(
        text,
      ),
  },
  {
    id: "infrastructure.cluster-delete",
    reason: "Destructive cluster/container/cloud operation requires review",
    test: (text) =>
      /\bkubectl\s+delete\b[^\n]*(?:\sall\b|\s--all\b)|\bkubectl\s+drain\b[^\n]*--force\b|\bhelm\s+uninstall\b/i.test(text),
  },
  {
    id: "infrastructure.cloud-delete",
    reason: "Destructive cloud resource deletion requires review",
    test: (text) =>
      /\baws\s+s3\s+rb\b[^\n]*--force\b|\baws\s+(?:iam\s+delete-|ec2\s+terminate-instances|rds\s+delete-db-instance)\b|\bgcloud\b[^\n]*\bdelete\b[^\n]*(?:project|cluster|instance)\b|\baz\b[^\n]*\bdelete\b[^\n]*--yes\b/i.test(
        text,
      ),
  },
  {
    id: "permissions.setuid",
    reason: "Granting setuid/setcap capabilities requires review",
    test: (text) =>
      /\bchmod\b[^\n]*(?:\s[2467][0-7]{3}\b|\+s\b|u\+s\b|g\+s\b)|\bsetcap\b[^\n]*(?:cap_setuid|cap_all|cap_dac_read_search|cap_sys_admin)\+ep\b|\binstall\s+-m\s+[24][0-7]{3}\b/i.test(
        text,
      ),
  },
  {
    id: "network.firewall-mutate",
    reason: "Mutating firewall or network configuration requires review",
    test: (text) =>
      /\biptables\b[^\n]*\s-[FP]\b|\bnft\s+flush\s+ruleset\b|\bufw\s+(?:disable|reset)\b|\bip\s+(?:addr|route)\s+flush\b|\bifconfig\b[^\n]*\s+down\b/i.test(
        text,
      ),
  },
  {
    id: "namespace.escape",
    reason: "Entering or creating isolated namespaces requires review",
    test: (text) =>
      /\bnsenter\s+-t\s+1\b|\bunshare\b[^\n]*(?:--mount\b|--pid\b|--user\b|--mount-proc\b|\s-[a-z]*u[a-z]*\b)/i.test(text),
  },
  {
    id: "filesystem.tar-extract-system",
    reason: "Extracting an archive into a system directory requires review",
    test: (text) =>
      /\btar\b[^\n]*(?:-C\s+\/(?:etc|var|boot|usr|bin|sbin|home|root)\b|--absolute-names\b)/i.test(text),
  },
  {
    id: "forensic.history-clear",
    reason: "Clearing command history or disabling history recording requires review",
    test: (text) =>
      /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTFILE\s*=\s*(?:\/dev\/null|:)?\b|HISTSIZE\s*=\s*0\b/i.test(text),
  },
  {
    id: "forensic.journal-vacuum",
    reason: "Vacuuming or deleting journal/log data requires review",
    test: (text) => /\bjournalctl\b[^\n]*--vacuum/i.test(text),
  },
  {
    id: "exfiltration.dns",
    reason: "DNS-exfiltrating command output requires review",
    test: (text) => /\b(?:nslookup|dig|host)\b[^\n]*\$\(/i.test(text),
  },
  {
    id: "execution.encoded-shell",
    reason: "Executing an encoded PowerShell payload requires review",
    test: (text) => /\b(?:pwsh|powershell)(?:\.exe)?\b[^\n]*-(?:EncodedCommand|EncodedArguments|enc)\b/i.test(text),
  },
  {
    id: "forensic.var-log-delete",
    reason: "Deleting log output requires review",
    test: (text) => /\b(?:rm|shred|find)\b[^\n]*\/var\/log\b/i.test(text),
  },
]

function normalized(value: string) {
  return value.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
}

function hasSensitiveCredentialReference(text: string) {
  return (
    SENSITIVE_ENV_FILE.test(text) ||
    /(?:^|[\\/\s])\.ssh(?:[\\/\s]|$)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\/proc\/(?:self|\d+)\/environ|\blsass\b|\.aws[\\/](?:credentials|config)|\.npmrc\b|\.vercel[\\/]token/i.test(
      text,
    )
  )
}

/** True when a `/dev/tcp`/`/dev/udp` socket has a SHELL or stdio attached to
 *  it — the shapes that make a bash socket a remote-control channel:
 *  an interactive shell (`bash -i … /dev/tcp`), a shell reading its program
 *  from a socket fd (`sh <&3`), stdio redirected to the socket
 *  (`0</dev/tcp`, `exec <> /dev/tcp`, `>& /dev/tcp`, `&> /dev/tcp`), or
 *  stdin copied from an already-connected fd (`0>&3`, `0<&3`).
 *  A bare fd open used for probing (`exec 3<>/dev/tcp/127.0.0.1/9222`,
 *  `head -c 100 <&3`, `echo x > /dev/tcp/h/p`) does NOT match — it is
 *  ambiguous network I/O handled by the `network.dev-socket` review signal
 *  instead of the unconditional floor. */
function hasAttachedDevSocket(text: string): boolean {
  if (!/\/dev\/(?:tcp|udp)\//i.test(text)) return false
  const B = "(?:^|[\\s;&|(/'\"`>])"
  return (
    // Interactive shell anywhere a socket path is in play.
    new RegExp(B + "(?:ba|z|da|k|a)?sh\\b[^|\\n;]*\\s-i(?:[\\s'\";&|)/]|$)", "i").test(text) ||
    // Shell taking its input (program) from a socket fd: `sh <&3`, `bash 0<&3`.
    new RegExp(B + "(?:ba|z|da|k|a)?sh\\s+(?:0\\s*)?<\\s*&\\s*\\d", "i").test(text) ||
    // stdin redirected to the socket: `0</dev/tcp`, `exec < /dev/tcp`, `exec 0<>/dev/tcp`.
    new RegExp(B + "(?:0\\s*<|0?<>|<)\\s*/dev/(?:tcp|udp)/", "i").test(text) ||
    // stdout+stderr merged onto the socket: `>& /dev/tcp`, `&> /dev/tcp`,
    // `3>&/dev/tcp` — the `&` may be re-joined as a connector (`3> & /dev/tcp`),
    // so arbitrary whitespace around both operator chars is tolerated.
    new RegExp(B + "(?:\\d*\\s*>\\s*&|\\s*&\\s*>)\\s*/dev/(?:tcp|udp)/", "i").test(text) ||
    // stdin copied to/from a numbered fd while a socket is open: `0>&3`, `0<&3`.
    new RegExp(B + "0\\s*[<>]\\s*&\\s*\\d", "i").test(text)
  )
}

function hasCrontabPersistence(text: string) {
  const invocations = text.match(/\bcrontab\b[^\r\n;&|]*/gi) ?? []
  return invocations.some((invocation) => {
    const args = invocation.trim().split(/\s+/).slice(1)
    let listsOnly = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === "-l" || arg === "--list") {
        listsOnly = true
        continue
      }
      if (arg === "-u" || arg === "--user") {
        if (!args[index + 1]) return true
        index += 1
        continue
      }
      if (/^\d*(?:>{1,2}|<)/.test(arg)) continue
      return true
    }
    return !listsOnly
  })
}

function expandHome(value: string) {
  if (value === "~") return process.env.USERPROFILE ?? process.env.HOME ?? value
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    const home = process.env.USERPROFILE ?? process.env.HOME
    return home ? path.join(home, value.slice(2)) : value
  }
  return value
}

function isWithin(base: string, target: string) {
  const relative = path.relative(path.resolve(base), path.resolve(target))
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function commandLeaf(value: string) {
  return stripMatchingQuotes(value)
    .replaceAll("\\", "/")
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase()
}

function simpleInvocationTokens(segment: string) {
  return segment.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
}

/** Output redirects that discard output without touching a file: fd merges
 *  (`2>&1`, `>&-`), fd closes, and `>`/`>>`/`&>` to /dev/null|stdout|stderr
 *  (or PowerShell's $null/NUL). They are inert for the executable-resolution
 *  layer — a trailing `2>/dev/null` must not turn `node -v` into an
 *  "unproven" invocation — while real redirect targets keep flowing through
 *  `extractWriteTargets` unchanged. */
const INERT_REDIRECT_TARGET = /^(?:\/dev\/(?:null|stdout|stderr)|\$null|NUL)$/i
const INERT_REDIRECT_TOKEN = /^(?:\d+|&)?>{1,2}(?:\/dev\/(?:null|stdout|stderr)|\$null|NUL)$/i
const FD_MERGE_TOKEN = /^\d*>&-?\d+$|^\d*>&-$/

function dropInertRedirectTokens(tokens: string[]): string[] {
  const kept: string[] = []
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] ?? ""
    if (FD_MERGE_TOKEN.test(token) || INERT_REDIRECT_TOKEN.test(token)) continue
    if (/^(?:\d+|&)?>{1,2}$/.test(token) && INERT_REDIRECT_TARGET.test(stripMatchingQuotes(tokens[index + 1] ?? ""))) {
      index += 1
      continue
    }
    kept.push(token)
  }
  return kept
}

function literalPathToken(value: string) {
  const candidate = stripMatchingQuotes(value.trim())
  if (!candidate || /[*?[\]`$%{}]/.test(candidate) || /[<>|]/.test(candidate)) return undefined
  return candidate
}

function backupPathIdentity(candidate: string) {
  const normalizedPath = candidate.replace(/[\\/]+$/, "")
  const name = path.basename(normalizedPath)
  const match = name.match(/^(.*?)(?:\.backup|-backup|\.bak|-bak)\d*$/)
  if (!match?.[1]) return undefined
  return {
    backupName: name,
    originalName: match[1],
  }
}

// Backup words that mark a name as a backup when they appear as a complete
// separator-delimited token (`config.bak`, `db-backup-2026.sql`, `hosts.old`).
// A substring inside a larger word (`bakery.log`) never qualifies.
const BACKUP_NAME_WORDS = new Set(["bak", "bakup", "backup", "bkup", "bck", "bckup", "old", "orig", "original"])

function backupNameTokens(name: string) {
  return name.toLowerCase().split(/[._\s-]+/).filter((token) => token.length > 0)
}

function isBackupWordToken(token: string) {
  return BACKUP_NAME_WORDS.has(token.replace(/\d+$/, ""))
}

function obviousBackupIdentity(candidate: string) {
  const normalizedPath = candidate.replace(/[\\/]+$/, "")
  const name = path.basename(normalizedPath)
  const tokens = backupNameTokens(name)
  if (tokens.length === 0) return undefined
  const stemTokens = tokens.filter((token) => !isBackupWordToken(token))
  // A name that is only a backup word (`bak`, `backup`) has no stem and is
  // not recognizable as a backup of something.
  if (stemTokens.length === 0 || stemTokens.length === tokens.length) return undefined
  return { backupName: name, stem: stemTokens.join(".") }
}

function similarBackupSiblingTokens(name: string) {
  return backupNameTokens(name).filter((token) => !isBackupWordToken(token) && !/^\d+$/.test(token))
}

function hasSimilarBackupSibling(entries: Dirent[], targetName: string) {
  const targetTokens = similarBackupSiblingTokens(targetName)
  if (targetTokens.length === 0) return false
  return entries.some((entry) => {
    if (entry.name === targetName) return false
    const siblingTokens = similarBackupSiblingTokens(entry.name)
    return (
      siblingTokens.length === targetTokens.length &&
      siblingTokens.every((token, index) => token === targetTokens[index])
    )
  })
}

function isCriticalOriginalPath(candidate: string) {
  const original = path.basename(candidate.replace(/[\\/]+$/, "")).toLowerCase()
  return (
    /(?:^|\.)env(?:\.|$)/.test(original) ||
    /\.(?:key|pem|p12|pfx|ppk|jks|keystore|kdbx|gpg|age)$/.test(original) ||
    /^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$/.test(original) ||
    /^(?:\.ssh|\.gnupg)$/.test(original)
  )
}

function isCriticalBackupTarget(candidate: string) {
  const identity = backupPathIdentity(candidate)
  if (!identity) return false
  return isCriticalOriginalPath(identity.originalName)
}

type ParsedDeleteInvocation = {
  parseable: boolean
  targets: string[]
}

function parseDeleteInvocation(segment: string): ParsedDeleteInvocation | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  const command = commandLeaf(tokens[0] ?? "")
  if (!["rm", "remove-item", "del", "erase", "unlink", "rmdir", "rd", "ri", "shred", "srm", "wipe"].includes(command ?? "")) {
    return undefined
  }

  const targets: string[] = []
  const optionsWithValues = new Set([
    "-erroraction",
    "-warningaction",
    "-informationaction",
    "-errorvariable",
    "-warningvariable",
    "-outvariable",
    "-outbuffer",
    "-pipelinevariable",
    "-n",
    "--iterations",
    "-s",
    "--size",
  ])
  const optionsWithoutValues = new Set([
    "-f",
    "--force",
    "-r",
    "-R",
    "--recursive",
    "-d",
    "--dir",
    "-i",
    "-I",
    "-v",
    "--verbose",
    "--one-file-system",
    "-force",
    "-recurse",
    "-confirm:$false",
    "-u",
    "--remove",
    "-z",
    "--zero",
    "-x",
    "--exact",
  ])
  let optionsEnded = false

  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    const lower = token.toLowerCase()
    if (!optionsEnded && lower === "--") {
      optionsEnded = true
      continue
    }
    if (!optionsEnded && (lower === "-path" || lower === "-literalpath")) {
      const target = tokens[index + 1]
      if (!target) return { parseable: false, targets }
      targets.push(target)
      index += 1
      continue
    }
    if (!optionsEnded && optionsWithValues.has(lower)) {
      if (!tokens[index + 1]) return { parseable: false, targets }
      index += 1
      continue
    }
    if (/^\d*>&\d+$/.test(token)) continue
    if (/^(?:\d*|&)>{1,2}\S+$/.test(token)) continue
    if (/^(?:\d*|&)>{1,2}$/.test(token)) {
      if (index + 1 < tokens.length) index += 1
      continue
    }
    if (!optionsEnded && (optionsWithoutValues.has(token) || optionsWithoutValues.has(lower))) continue
    if (!optionsEnded && /^-[firdvR]+$/.test(token)) continue
    if (!optionsEnded && CMD_STYLE_DELETE_COMMANDS.includes(command ?? "") && CMD_DELETE_FLAGS.test(token)) continue
    if (!optionsEnded && token.startsWith("-")) return { parseable: false, targets }
    targets.push(token)
  }

  return { parseable: targets.length > 0, targets }
}

type ParsedTransferInvocation = {
  source: string
  target: string
}

function parsePositionalTransfer(tokens: string[], allowedFlags: RegExp) {
  const operands: string[] = []
  let optionsEnded = false
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (!optionsEnded && token === "--") {
      optionsEnded = true
      continue
    }
    if (!optionsEnded && token.startsWith("-")) {
      if (!allowedFlags.test(token)) return undefined
      continue
    }
    operands.push(token)
  }
  if (operands.length !== 2) return undefined
  return { source: operands[0], target: operands[1] }
}

function parsePowerShellTransfer(tokens: string[], destinationNames: Set<string>) {
  let source: string | undefined
  let target: string | undefined
  const positional: string[] = []
  const switches = new Set(["-recurse", "-force", "-container", "-confirm:$false"])
  const optionsWithValues = new Set([
    "-erroraction",
    "-warningaction",
    "-informationaction",
    "-errorvariable",
    "-warningvariable",
    "-outvariable",
    "-outbuffer",
    "-pipelinevariable",
  ])

  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    const lower = token.toLowerCase()
    if (lower === "-path" || lower === "-literalpath") {
      if (source || !tokens[index + 1]) return undefined
      source = tokens[index + 1]
      index += 1
      continue
    }
    if (destinationNames.has(lower)) {
      if (target || !tokens[index + 1]) return undefined
      target = tokens[index + 1]
      index += 1
      continue
    }
    if (switches.has(lower)) continue
    if (optionsWithValues.has(lower)) {
      if (!tokens[index + 1]) return undefined
      index += 1
      continue
    }
    if (token.startsWith("-")) return undefined
    positional.push(token)
  }

  if (!source) source = positional.shift()
  if (!target) target = positional.shift()
  if (!source || !target || positional.length > 0) return undefined
  return { source, target }
}

function parseCopyInvocation(segment: string): ParsedTransferInvocation | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  const command = commandLeaf(tokens[0] ?? "")
  if (command === "cp") {
    if (tokens.some((token) => ["-path", "-literalpath", "-destination"].includes(token.toLowerCase()))) {
      return parsePowerShellTransfer(tokens, new Set(["-destination"]))
    }
    return parsePositionalTransfer(
      tokens,
      /^(?:-[aAbdfHilLnPpRrSsuvx]+|--(?:archive|force|interactive|link|no-clobber|no-dereference|recursive|update|verbose|preserve(?:=.+)?|no-preserve=.+|reflink(?:=.+)?|sparse=.+))$/,
    )
  }
  if (command === "copy") return parsePositionalTransfer(tokens, /^\/[abdvyn]+$/i)
  if (command === "copy-item") {
    return parsePowerShellTransfer(tokens, new Set(["-destination"]))
  }
  return undefined
}

function parseMoveInvocation(segment: string): ParsedTransferInvocation | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  const command = commandLeaf(tokens[0] ?? "")
  if (command === "mv" || command === "move") {
    if (tokens.some((token) => ["-path", "-literalpath", "-destination"].includes(token.toLowerCase()))) {
      return parsePowerShellTransfer(tokens, new Set(["-destination"]))
    }
    return parsePositionalTransfer(tokens, /^(?:-[finTuv]+|--(?:force|interactive|no-clobber|update|verbose|no-target-directory))$/)
  }
  if (command === "move-item") {
    return parsePowerShellTransfer(tokens, new Set(["-destination"]))
  }
  if (command === "rename-item" || command === "ren") {
    return parsePowerShellTransfer(tokens, new Set(["-newname"]))
  }
  return undefined
}

function expandTrustedTempVariables(value: string) {
  const replacements: Array<[RegExp, string | undefined]> = [
    [/^%LOCALAPPDATA%(?=$|[\\/])/i, process.env.LOCALAPPDATA],
    [/^%TEMP%(?=$|[\\/])/i, process.env.TEMP],
    [/^\$env:LOCALAPPDATA(?=$|[\\/])/i, process.env.LOCALAPPDATA],
    [/^\$env:TEMP(?=$|[\\/])/i, process.env.TEMP],
    [/^\$\{env:LOCALAPPDATA\}(?=$|[\\/])/i, process.env.LOCALAPPDATA],
    [/^\$\{env:TEMP\}(?=$|[\\/])/i, process.env.TEMP],
  ]
  let expanded = stripMatchingQuotes(value.trim())
  for (const [pattern, replacement] of replacements) {
    if (replacement && pattern.test(expanded)) {
      expanded = expanded.replace(pattern, replacement)
      break
    }
  }
  return expandHome(expanded)
}

function normalizeMsysPath(value: string) {
  if (process.platform !== "win32") return value
  return value.replace(/^\/([a-zA-Z])(?=\/|$)/, "$1:/")
}

function resolveTempPathCandidate(candidate: string, base: string) {
  const expanded = normalizeMsysPath(expandTrustedTempVariables(candidate))
  if (!expanded || /[`$%{}<>|]/.test(expanded)) return undefined

  const wildcardIndex = expanded.search(/[*?[]/)
  if (wildcardIndex >= 0) {
    const wildcardSuffix = expanded.slice(wildcardIndex)
    if (/[\\/]/.test(wildcardSuffix)) return undefined
    const prefix = expanded.slice(0, wildcardIndex)
    const anchorText = prefix.endsWith("/") || prefix.endsWith("\\") ? prefix : path.dirname(prefix)
    if (!anchorText) return undefined
    const anchor = path.isAbsolute(anchorText) ? path.normalize(anchorText) : path.resolve(base, anchorText)
    return { absolute: anchor, contentsOnly: true }
  }

  const absolute = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(base, expanded)
  return { absolute, contentsOnly: false }
}

function isStrictlyWithin(base: string, target: string) {
  const relative = path.relative(path.resolve(base), path.resolve(target))
  return Boolean(relative && !relative.startsWith("..") && !path.isAbsolute(relative))
}

async function canonicalExistingAnchor(candidate: string) {
  let current = path.resolve(candidate)
  for (let index = 0; index < 64; index += 1) {
    try {
      return await realpath(current)
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return undefined
      current = parent
    }
  }
  return undefined
}

async function trustedUserLocalTempRoots(input: ClassifyShellCommandInput) {
  const candidates = input.trustedTempRoot
    ? [input.trustedTempRoot]
    : [
        process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "Temp") : undefined,
        process.env.USERPROFILE ? path.join(process.env.USERPROFILE, "AppData", "Local", "Temp") : undefined,
      ]
  const roots: string[] = []
  for (const candidate of candidates) {
    if (!candidate) continue
    try {
      const canonical = await realpath(path.resolve(candidate))
      if (!roots.some((root) => path.resolve(root).toLowerCase() === path.resolve(canonical).toLowerCase())) {
        roots.push(canonical)
      }
    } catch {
      // A missing or inaccessible temp root cannot qualify for the whitelist.
    }
  }
  return roots
}

async function isTrustedTempPath(
  candidate: string,
  base: string,
  roots: string[],
) {
  const resolved = resolveTempPathCandidate(candidate, base)
  if (!resolved) return false

  for (const root of roots) {
    const lexicalMatch =
      isStrictlyWithin(root, resolved.absolute) ||
      (resolved.contentsOnly && path.resolve(root).toLowerCase() === path.resolve(resolved.absolute).toLowerCase())
    if (!lexicalMatch) continue

    const canonicalAnchor = await canonicalExistingAnchor(resolved.absolute)
    if (!canonicalAnchor) continue
    const canonicalMatch =
      isStrictlyWithin(root, canonicalAnchor) ||
      path.resolve(root).toLowerCase() === path.resolve(canonicalAnchor).toLowerCase()
    if (canonicalMatch) return true
  }
  return false
}

/**
 * The trusted temp area for the segment-level confinement checks: `/tmp` and
 * `/var/tmp` canonically, plus the session's trusted user-local temp roots
 * (LOCALAPPDATA Temp). Canonicalizing both sides closes the symlink escape a
 * purely lexical `/tmp/../…` or `/tmp/link-out` target would open.
 */
async function trustedTempRoots(input: ClassifyShellCommandInput) {
  const roots: string[] = []
  for (const candidate of ["/tmp", "/var/tmp", ...(await trustedUserLocalTempRoots(input))]) {
    try {
      roots.push(await realpath(candidate))
    } catch {
      // A missing temp root cannot confine anything.
    }
  }
  return roots
}

/**
 * Whether `candidate` (resolved against `base`) lands strictly inside one of
 * the trusted temp roots — lexically first, then against the canonical
 * projection so a symlinked or `..`-laden path cannot claim a temp address
 * while writing elsewhere. A bare `.` resolves to `base` itself.
 */
async function pathInsideTempRoot(candidate: string, base: string, roots: string[]): Promise<boolean> {
  const expanded = expandTrustedTempVariables(candidate)
  if (!expanded || /[`$%{}<>|]/.test(expanded)) return false
  const absolute = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(base, expanded)
  for (const root of roots) {
    if (!isStrictlyWithin(root, absolute)) continue
    const canonical = await canonicalProjectedPath(absolute)
    if (canonical && isWithin(root, canonical)) return true
  }
  return false
}

/**
 * All-targets-confined check for one segment: every write destination
 * (redirects, `tee`/`dd`/`cp`/`mv`/`mkdir`/`tar`/`curl -o`/heredoc writes via
 * `extractWriteTargets`), archive extraction root (`tar -C`, `unzip -d`),
 * delete target, and `mv` source must verify inside a trusted temp root. One
 * unparseable or escaping target fails the whole segment — the normal flow
 * then applies.
 */
async function writeTargetsConfinedToTemp(
  segment: string,
  base: string,
  roots: string[],
  shell: string,
): Promise<{ confined: boolean; targets: number }> {
  const fail = { confined: false, targets: 0 }
  // Substitution/expansion bodies carry executable code the target scan
  // cannot see — confinement only applies to fully literal segments.
  if (hasDynamicShellExpansion(segment, shell)) return fail
  const writes = extractWriteTargets(segment)
  if (writes.unparseable) return fail

  const tokens = simpleInvocationTokens(segment)
  const command = commandLeaf(tokens[0] ?? "")
  // `2>&1`-style fd merges can surface as empty redirect targets; they are not paths.
  const targets = writes.targets.filter((target) => target !== "")

  if (command === "tar") {
    // Extraction root: `-C <dir>` (or `--directory=<dir>`), else the base.
    const dirs = [...segment.matchAll(/\s-C\s+("([^"]*)"|'([^']*)'|(\S+))|--directory(?:=|\s+)("([^"]*)"|'([^']*)'|(\S+))/gi)]
      .map((m) => m[2] ?? m[3] ?? m[4] ?? m[6] ?? m[7] ?? m[8])
      .filter((dir): dir is string => Boolean(dir))
    targets.push(...(dirs.length > 0 ? dirs : ["."]))
  }
  if (command === "unzip" || command === "7z" || command === "7za" || command === "7zr") {
    const dirs = [...segment.matchAll(/(?:^|\s)-d\s*("([^"]*)"|'([^']*)'|(\S+))/gi)]
      .map((m) => m[2] ?? m[3] ?? m[4])
      .filter((dir): dir is string => Boolean(dir))
    targets.push(...(dirs.length > 0 ? dirs : ["."]))
  }

  // `find <root> … -delete` deletes under its search root.
  if (command === "find" && /(?:^|\s)-delete(?:\s|$)/.test(segment)) {
    const root = tokens.find((token, index) => index > 0 && !token.startsWith("-"))
    if (root) targets.push(root)
  }

  const deletion = parseDeleteInvocation(segment)
  if (deletion) {
    if (!deletion.parseable || deletion.targets.length === 0) return fail
    targets.push(...deletion.targets)
  }

  const move = parseMoveInvocation(segment)
  if (move) {
    // `mv` removes the source — a worktree source is a worktree delete.
    targets.push(move.source, move.target)
  }
  const copy = parseCopyInvocation(segment)
  if (copy) targets.push(copy.target)

  for (const target of targets) {
    if (!(await pathInsideTempRoot(target, base, roots))) return fail
  }
  return { confined: true, targets: targets.length }
}

/** Commands that are never eligible for the temp-confined exemption: they
 * execute programs, reach the network, or escalate privileges, so a confined
 * write target does not make the segment safe. */
const TEMP_CONFINED_EXCLUDED_COMMAND = new Set([
  "bash", "sh", "zsh", "dash", "cmd", "powershell", "pwsh",
  "python", "python3", "py", "node", "deno", "bun", "ruby", "perl", "php",
  "curl", "curl.exe", "wget", "wget2", "aria2c", "scp", "rsync", "ssh",
  "invoke-webrequest", "iwr", "irm",
  "sudo", "runas", "eval", "source", ".", "exec", "xargs",
])

/**
 * Fix B — "all targets confined" replaces "all segments pure": a segment whose
 * every write/delete/extract target canonically lands inside a trusted temp
 * root is ALLOW `cleanup.temp-confined` in both modes. Other findings still
 * rule: a deny or sensitive-path finding falls through to the normal flow,
 * and executors/network/privilege commands are never eligible.
 *
 * An unverified base (a `cd` claim a `;`/`||` connector does not guarantee, or
 * an unverified runtime workdir) must itself canonically sit inside a temp
 * root before it can carry the exemption; otherwise the claimed confinement
 * may be imaginary.
 */
async function classifyTempConfinedSegment(
  segment: string,
  base: string,
  input: InternalClassifyInput,
): Promise<SegmentDecision | undefined> {
  const tokens = simpleInvocationTokens(segment)
  const command = commandLeaf(tokens[0] ?? "")
  if (!command || TEMP_CONFINED_EXCLUDED_COMMAND.has(command)) return undefined

  const roots = await trustedTempRoots(input)
  if (roots.length === 0) return undefined
  // Zero-target segments carry nothing to confine — they belong to the
  // normal safe/unsafe flow, not this exemption.
  const confinement = await writeTargetsConfinedToTemp(segment, base, roots, input.shell)
  if (!confinement.confined || confinement.targets === 0) return undefined

  if (input.baseUnverified === true && !(await baseInsideTempRoot(base, input))) {
    return {
      verdict: "ASK",
      rules: ["filesystem.temp-context-delete"],
      reason:
        "The operation runs after a `cd` that is not guaranteed to have taken effect, and the claimed base is not a verified temp directory",
    }
  }

  const finding = analyzeSegmentPaths(segment, {
    cwd: base,
    worktree: input.worktree,
    strictness: input.strictness ?? "LOOSE",
  })
  if (finding.kind !== "pass") {
    // Confined targets make the outside-write/extract asks moot; a deny or a
    // sensitive finding still belongs to the normal flow.
    if (
      finding.kind === "deny" ||
      (finding.rule !== "filesystem.outside-write" &&
        finding.rule !== "filesystem.tar-extract-system" &&
        finding.rule !== "filesystem.unverified-base")
    ) {
      return undefined
    }
  }

  // Credential-material deletion keeps its `data.critical-delete` verdict no
  // matter where the target sits: the exemption must not let `rm .env` ride
  // through just because the cwd is a temp root.
  if (hasCriticalDataDestruction(segment, input.shell)) return undefined

  return {
    verdict: "ALLOW",
    rules: ["cleanup.temp-confined"],
    reason: "Every write and deletion target is canonically confined to a trusted temp directory",
  }
}

/**
 * Fix C — every forced-recursive delete invocation across the segment's
 * executable surfaces has all of its targets confined to a trusted temp root.
 * Used to exempt `hard.forced-recursive-delete` (and the definite
 * `filesystem.forced-recursive-delete` signal) only when confinement is
 * proven; the absolute floors (`rm -rf /`, system roots, root globs) never
 * reach this check.
 */
async function forcedDeletesConfinedToTemp(
  surfaces: string[],
  input: InternalClassifyInput,
): Promise<boolean> {
  const roots = await trustedTempRoots(input)
  if (roots.length === 0) return false

  let found = false
  for (const surface of surfaces) {
    const wrappedPowerShell = unwrapPowerShellCommand(surface)
    const payload = wrappedPowerShell ?? surface
    const payloadShell = wrappedPowerShell ? "powershell" : input.shell
    const segments = splitCommandSegments(payload, payloadShell) ?? [{ text: payload }]

    let stable: SegmentBase = { dir: path.resolve(input.cwd), unverified: input.baseUnverified === true }
    let cond: SegmentBase = stable
    for (const item of segments) {
      ;({ stable, cond } = advanceSegmentBase(item, stable, cond, input.cwd))
      const seg = stripHarmlessPrefixes(item.text)
      const cd = parseCdSegment(seg)
      if (cd) {
        if (item.incoming !== "|" && item.incoming !== "&") {
          const resolvedDir = resolveCdBase(cd.dir, cond.dir)
          cond = { dir: resolvedDir, unverified: cond.unverified }
          if (item.incoming === undefined || item.incoming === ";" || item.incoming === "newline") stable = cond
        }
        continue
      }
      const segBase = cond.dir
      if (segBase === undefined) continue

      const shape = forcedRecursiveShape(simpleInvocationTokens(seg))
      if (!shape.forced) continue
      found = true
      if (cond.unverified && !(await baseInsideTempRoot(segBase, input))) return false
      for (const target of shape.targets) {
        if (!(await pathInsideTempRoot(stripMatchingQuotes(target), segBase, roots))) return false
      }
    }
  }
  return found
}

function isHarmlessTailSegment(segment: string) {
  const value = segment.trim()
  if (/[<>]/.test(value)) return false
  if (/^(?:echo|printf|Write-Output|true|false|:|cd|popd)\b/i.test(value)) return true
  if (/^set\b/i.test(value)) {
    const tokens = value.split(/\s+/).slice(1)
    const safeOptions = new Set([
      "pipefail", "errexit", "nounset", "xtrace", "verbose",
      "noclobber", "ignoreeof", "allexport", "nolog", "privileged",
    ])
    if (tokens.every((t) => /^[-+][a-zA-Z]+$/.test(t) || safeOptions.has(t.toLowerCase()) || t === "--" || t === "-")) {
      return true
    }
  }
  return false
}

async function classifyUserLocalTempSegment(
  source: string,
  input: InternalClassifyInput,
): Promise<StaticSecurityDecision | undefined> {
  const roots = await trustedUserLocalTempRoots(input)
  if (roots.length === 0) return undefined

  const wrappedPowerShell = unwrapPowerShellCommand(source)
  const wrappedNamedShell = wrappedPowerShell
    ? undefined
    : unwrapNamedTempDeletionShell(source, input.shell)
  const payload = wrappedPowerShell ?? wrappedNamedShell?.payload ?? source
  const payloadShell = wrappedPowerShell
    ? "powershell"
    : wrappedNamedShell?.shell ?? input.shell
  const segments = splitCommandSegments(payload, payloadShell)
  if (!segments?.length) return undefined

  let stable: SegmentBase = { dir: path.resolve(input.cwd), unverified: input.baseUnverified === true }
  let cond: SegmentBase = stable
  const unverifiedBases: string[] = []
  let operations = 0
  for (const item of segments) {
    ;({ stable, cond } = advanceSegmentBase(item, stable, cond, input.cwd))
    const segment = item.text
    const cd = parseCdSegment(segment)
    if (cd) {
      if (item.incoming !== "|" && item.incoming !== "&") {
        const resolvedDir = resolveCdBase(cd.dir, cond.dir)
        cond = { dir: resolvedDir, unverified: cond.unverified }
        if (item.incoming === undefined || item.incoming === ";" || item.incoming === "newline") stable = cond
      }
      continue
    }
    const base = cond.dir
    if (cond.unverified && base !== undefined && !unverifiedBases.includes(base)) unverifiedBases.push(base)
    if (base === undefined) return undefined

    const deletion = parseDeleteInvocation(segment)
    if (deletion) {
      if (!deletion.parseable || deletion.targets.length === 0) return undefined
      for (const target of deletion.targets) {
        if (!(await isTrustedTempPath(target, base, roots))) return undefined
      }
      operations += 1
      if (input.strictness === "HARD") {
        return {
          verdict: "DENY",
          rules: ["hard.local-temp-delete"],
          reason: `Permanent deletion inside the trusted Local Temp directory is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
          fingerprints: [],
        }
      }
      continue
    }

    const move = parseMoveInvocation(segment)
    if (move) {
      const sourcePath = resolveTempPathCandidate(move.source, base)
      if (!sourcePath || !(await isTrustedTempPath(move.source, base, roots))) return undefined
      const command = commandLeaf(simpleInvocationTokens(segment)[0] ?? "")
      const targetBase =
        (command === "rename-item" || command === "ren") && !path.isAbsolute(expandTrustedTempVariables(move.target))
          ? path.dirname(sourcePath.absolute)
          : base
      if (!(await isTrustedTempPath(move.target, targetBase, roots))) return undefined
      operations += 1
      continue
    }

    const copy = parseCopyInvocation(segment)
    if (copy) {
      if (!literalPathToken(copy.source)) return undefined
      if (!(await isTrustedTempPath(copy.target, base, roots))) return undefined
      operations += 1
      continue
    }

    if (isHarmlessTailSegment(segment)) continue
    return undefined
  }

  if (operations === 0) return undefined
  if (input.strictness === "HARD") return undefined
  if (unverifiedBases.length > 0 && !(await unverifiedBasesAllInTemp(unverifiedBases, input))) {
    const ask = tempContextDeleteAsk()
    return {
      verdict: ask.verdict,
      rules: ask.rules,
      reason: ask.reason,
      fingerprints: [],
    }
  }
  return {
    verdict: "ALLOW",
    rules: ["cleanup.user-local-temp"],
    reason: "Filesystem operation is strictly confined to the trusted user Local Temp directory",
    fingerprints: [],
  }
}

function unwrapNamedTempDeletionShell(
  source: string,
  shell: string,
): { payload: string; shell: string } | undefined {
  const value = stripLeadingDirectoryChanges(source)
  if (splitSimpleSegments(value, shell)?.length !== 1) return undefined

  const tokens = simpleInvocationTokens(value)
  let commandIndex = 0
  if (commandLeaf(tokens[0] ?? "") === "wsl") {
    commandIndex = 1
    while (commandIndex < tokens.length) {
      const lower = tokens[commandIndex].toLowerCase()
      if (lower === "-d" || lower === "--distribution" || lower === "-u" || lower === "--user") {
        commandIndex += 2
        continue
      }
      if (lower === "--") {
        commandIndex += 1
        break
      }
      break
    }
  }

  const wrapper = commandLeaf(tokens[commandIndex] ?? "")
  let commandFlagIndex = -1
  let wrappedShell = shell
  if (["bash", "sh", "zsh"].includes(wrapper ?? "")) {
    commandFlagIndex = tokens.findIndex(
      (token, index) => index > commandIndex && /^-[a-z]*c[a-z]*$/i.test(token),
    )
    wrappedShell = wrapper ?? shell
  } else if (wrapper === "cmd") {
    commandFlagIndex = tokens.findIndex((token, index) => index > commandIndex && /^\/c$/i.test(token))
    wrappedShell = "cmd"
  } else {
    return undefined
  }

  const quotedPayload = tokens[commandFlagIndex + 1]
  if (commandFlagIndex < 0 || !quotedPayload) return undefined
  if (tokens.slice(commandFlagIndex + 2).some((token) => !/^\d*>&\d+$/.test(token))) return undefined
  const payload = stripMatchingQuotes(quotedPayload).trim()
  return payload ? { payload, shell: wrappedShell } : undefined
}

function namedTempDeletionPayload(source: string, input: ClassifyShellCommandInput) {
  let payload = source
  let payloadShell = input.shell
  for (let depth = 0; depth < 4; depth += 1) {
    const wrappedPowerShell = unwrapPowerShellCommand(payload)
    if (wrappedPowerShell) {
      payload = wrappedPowerShell
      payloadShell = "powershell"
      continue
    }
    const wrappedShell = unwrapNamedTempDeletionShell(payload, payloadShell)
    if (!wrappedShell) break
    payload = wrappedShell.payload
    payloadShell = wrappedShell.shell
  }
  return { payload, payloadShell }
}

function decodedPowerShellDeletionPayloads(source: string, shell: string) {
  const value = stripLeadingDirectoryChanges(source)
  if (splitSimpleSegments(value, shell)?.length !== 1) return []

  const tokens = simpleInvocationTokens(value)
  if (!["powershell", "pwsh"].includes(commandLeaf(tokens[0] ?? "") ?? "")) return []
  const encodedIndex = tokens.findIndex((token) => /^-(?:encodedcommand|enc)$/i.test(token))
  const encoded = tokens[encodedIndex + 1]
  if (encodedIndex < 1 || !encoded) return []

  const switchesWithoutValues = new Set(["-noprofile", "-noninteractive", "-nologo", "-sta", "-mta"])
  const switchesWithValues = new Set(["-executionpolicy", "-ep", "-windowstyle"])
  for (let index = 1; index < encodedIndex; index += 1) {
    const token = tokens[index].toLowerCase()
    if (switchesWithoutValues.has(token)) continue
    if (switchesWithValues.has(token) && index + 1 < encodedIndex) {
      index += 1
      continue
    }
    return []
  }
  if (tokens.slice(encodedIndex + 2).some((token) => !/^\d*>&\d+$/.test(token))) return []
  return decodePowerShellBase64(stripMatchingQuotes(encoded))
}

async function classifyNamedTempDeletionPolicy(
  source: string,
  input: InternalClassifyInput,
): Promise<StaticSecurityDecision | undefined> {
  const candidates = [
    namedTempDeletionPayload(source, input),
    ...decodedPowerShellDeletionPayloads(source, input.shell).map((payload) => ({
      payload,
      payloadShell: "powershell",
    })),
  ]
  const rootDeleteRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "filesystem.root-delete")

  for (const { payload, payloadShell } of candidates) {
    const segments = splitCommandSegments(payload, payloadShell)
    if (!segments?.length || rootDeleteRule?.test(payload)) continue

    let hasNamedTempTarget = false
    let pureDeletion = true
    let stable: SegmentBase = { dir: path.resolve(input.cwd), unverified: input.baseUnverified === true }
    let cond: SegmentBase = stable
    const unverifiedBases: string[] = []
    for (const item of segments) {
      ;({ stable, cond } = advanceSegmentBase(item, stable, cond, input.cwd))
      const segment = item.text
      const cd = parseCdSegment(segment)
      if (cd) {
        if (item.incoming !== "|" && item.incoming !== "&") {
          const resolvedDir = resolveCdBase(cd.dir, cond.dir)
          cond = { dir: resolvedDir, unverified: cond.unverified }
          if (item.incoming === undefined || item.incoming === ";" || item.incoming === "newline") stable = cond
        }
        continue
      }
      const base = cond.dir
      if (cond.unverified && base !== undefined && !unverifiedBases.includes(base)) unverifiedBases.push(base)
      const stripped = stripHarmlessPrefixes(segment)
      const tokens = simpleInvocationTokens(stripped.trim())
      const command = commandLeaf(tokens[0] ?? "")
      if (!DELETE_COMMANDS.has(command ?? "")) {
        if (isHarmlessTailSegment(stripped)) continue
        pureDeletion = false
        break
      }

      const deletion = parseDeleteInvocation(stripped)
      if (!deletion?.parseable || deletion.targets.length === 0) {
        pureDeletion = false
        break
      }
      if (base === undefined || !(await deletionTargetsAreNamedTemp(deletion.targets, base, input.worktree))) {
        pureDeletion = false
        break
      }
      hasNamedTempTarget = true
    }

    if (pureDeletion && hasNamedTempTarget) {
      if (input.strictness === "HARD") {
        return {
          verdict: "DENY",
          rules: ["hard.named-temp-delete"],
          reason: `Permanent deletion of named temp/tmp targets is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
          fingerprints: [],
        }
      }
      if (unverifiedBases.length > 0 && !(await unverifiedBasesAllInTemp(unverifiedBases, input))) {
        const ask = tempContextDeleteAsk()
        return { verdict: ask.verdict, rules: ask.rules, reason: ask.reason, fingerprints: [] }
      }
      return {
        verdict: "ALLOW",
        rules: ["cleanup.named-temp"],
        reason: "Every deletion target is confined to a named temp or tmp directory",
        fingerprints: [],
      }
    }
  }

  return undefined
}

async function deletionTargetsAreNamedTemp(targets: string[], base: string, worktree?: string) {
  for (const target of targets) {
    if (!(await isNamedTempTargetResolved(target, base, worktree))) return false
  }
  return true
}

function hasExplicitNonCopyBackupCreation(segment: string) {
  const value = segment.trim()
  if (!BACKUP_SUFFIX_REFERENCE.test(value)) return false
  if (/^(?:mkdir|New-Item\s+[^\n]*-ItemType\s+Directory)\b/i.test(value)) return false
  if (/^(?:touch|new-item|set-content|out-file|tee|install)\b/i.test(value)) return true
  if (
    /^tar\b[^\r\n;&|]*(?:-[A-Za-z]*f\s+|--file(?:=|\s+))(?:"[^"]*(?:\.backup|-backup|\.bak|-bak)\d*"|'[^']*(?:\.backup|-backup|\.bak|-bak)\d*'|[^\s;&|]*(?:\.backup|-backup|\.bak|-bak)\d*)(?:\s|$)/i.test(
      value,
    )
  ) {
    return true
  }
  if (
    /^zip\b(?:\s+-\S+)*\s+(?:"[^"]*(?:\.backup|-backup|\.bak|-bak)\d*"|'[^']*(?:\.backup|-backup|\.bak|-bak)\d*'|[^\s;&|]*(?:\.backup|-backup|\.bak|-bak)\d*)(?:\s|$)/i.test(
      value,
    )
  ) {
    return true
  }
  return /(?:^|[^>])>\s*(?:"[^"]*(?:\.backup|-backup|\.bak|-bak)\d*"|'[^']*(?:\.backup|-backup|\.bak|-bak)\d*'|[^\s;&|]*(?:\.backup|-backup|\.bak|-bak)\d*)(?:\s|$)/i.test(
    value,
  )
}

function filesystemEntryKind(info: Awaited<ReturnType<typeof lstat>>) {
  if (info.isFile()) return "file"
  if (info.isDirectory()) return "directory"
  if (info.isSymbolicLink()) return "symlink"
  return "other"
}

async function inspectBackupDeletionTarget(
  candidate: string,
  input: ClassifyShellCommandInput,
): Promise<{ allowed: boolean; reason: string; sibling?: boolean }> {
  const literal = literalPathToken(candidate)
  if (!literal) return { allowed: false, reason: "Backup deletion target is not a literal path" }
  const identity = backupPathIdentity(literal)
  const obvious = identity ? { backupName: identity.backupName, stem: identity.originalName } : obviousBackupIdentity(literal)
  if (!identity && !obvious) return { allowed: false, reason: "Deletion target is not an obvious backup name" }
  if (isCriticalBackupTarget(literal) || (obvious && isCriticalOriginalPath(obvious.stem))) {
    return { allowed: false, reason: "Critical credential backups cannot be deleted" }
  }
  const loose = (input.strictness ?? "LOOSE") !== "HARD"

  const expanded = expandHome(literal)
  const absolute = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(input.cwd, expanded)
  if (!isWithin(input.worktree, absolute)) {
    return { allowed: false, reason: "Backup deletion target is outside the worktree" }
  }

  const parent = path.dirname(absolute)
  let canonicalWorktree: string
  let canonicalParent: string
  let entries: Dirent[]
  try {
    canonicalWorktree = await realpath(input.worktree)
    canonicalParent = await realpath(parent)
    entries = await readdir(canonicalParent, { withFileTypes: true })
  } catch {
    return { allowed: false, reason: "Backup directory metadata is unavailable" }
  }
  if (!isWithin(canonicalWorktree, canonicalParent)) {
    return { allowed: false, reason: "Backup deletion target resolves outside the worktree" }
  }

  const targetName = identity ? identity.backupName : obvious!.backupName
  const exactBackup = entries.find((entry) => entry.name === targetName)
  if (!exactBackup) return { allowed: false, reason: "Backup target does not exist with an exact name" }

  // LOOSE relaxation: an obvious backup name plus a similarly named sibling in
  // the same directory (the original or another dated copy) is deletable
  // without the exact-original, kind, and age verification below.
  if (loose && obvious && hasSimilarBackupSibling(entries, targetName)) {
    return { allowed: true, reason: "Obvious backup with a similarly named sibling", sibling: true }
  }

  if (!identity) {
    return { allowed: false, reason: "Backup has no similar sibling in the same directory" }
  }
  const exactOriginal = entries.find((entry) => entry.name === identity.originalName)
  if (!exactOriginal) return { allowed: false, reason: "Backup has no exact same-directory original" }

  let backupInfo: Awaited<ReturnType<typeof lstat>>
  let originalInfo: Awaited<ReturnType<typeof lstat>>
  try {
    backupInfo = await lstat(path.join(canonicalParent, identity.backupName))
    originalInfo = await lstat(path.join(canonicalParent, identity.originalName))
  } catch {
    return { allowed: false, reason: "Backup or original metadata is unavailable" }
  }
  if (filesystemEntryKind(backupInfo) !== filesystemEntryKind(originalInfo)) {
    return { allowed: false, reason: "Backup and original filesystem types do not match" }
  }

  const createdAt = backupInfo.birthtimeMs
  if (!Number.isFinite(createdAt) || createdAt <= 0) {
    return { allowed: false, reason: "Backup creation time is unavailable" }
  }
  const ageMs = (input.nowMs ?? Date.now()) - createdAt
  if (ageMs <= MIN_BACKUP_AGE_MS) {
    return { allowed: false, reason: "Backup is not older than two minutes" }
  }
  return { allowed: true, reason: "Backup has an exact original and is older than two minutes" }
}

async function classifyBackupPolicy(
  source: string,
  input: ClassifyShellCommandInput,
): Promise<StaticSecurityDecision | undefined> {
  const wrappedPowerShell = unwrapPowerShellCommand(source)
  const payload = wrappedPowerShell ?? source
  const payloadShell = wrappedPowerShell ? "powershell" : input.shell
  const segments = splitSimpleSegments(payload, payloadShell)
  if (!segments?.length) return undefined

  for (const segment of segments) {
    const move = parseMoveInvocation(segment)
    const moveTarget = move && literalPathToken(move.target)
    const command = commandLeaf(simpleInvocationTokens(segment)[0] ?? "")
    const unixRenameToBackup = command === "rename" && BACKUP_SUFFIX_REFERENCE.test(segment)
    if ((moveTarget && backupPathIdentity(moveTarget)) || unixRenameToBackup) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-move"],
        reason: "Moving or renaming data into a backup name is blocked by filesystem policy because it hides the data's origin",
        fingerprints: [],
      }
    }
    const copy = parseCopyInvocation(segment)
    const copySource = copy && literalPathToken(copy.source)
    const copyTarget = copy && literalPathToken(copy.target)
    if (
      copyTarget &&
      backupPathIdentity(copyTarget) &&
      (isCriticalBackupTarget(copyTarget) || Boolean(copySource && isCriticalOriginalPath(copySource)))
    ) {
      return {
        verdict: "DENY",
        rules: ["filesystem.critical-backup"],
        reason: "Critical credential files cannot use the backup exception",
        fingerprints: [],
      }
    }
    if (hasExplicitNonCopyBackupCreation(segment)) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-noncopy"],
        reason: "Backup names may only be created by copying",
        fingerprints: [],
      }
    }
  }

  if (segments.length !== 1) {
    if (segments.some((segment) => parseDeleteInvocation(segment) && BACKUP_SUFFIX_REFERENCE.test(segment))) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-delete-unverified"],
        reason: "Backup deletion must be a standalone verified operation",
        fingerprints: [],
      }
    }
    return undefined
  }

  const segment = segments[0]
  const copy = parseCopyInvocation(segment)
  const copyTarget = copy && literalPathToken(copy.target)
  if (copyTarget && backupPathIdentity(copyTarget)) {
    const copySource = copy && literalPathToken(copy.source)
    const ctx: PathContext = { cwd: input.cwd, worktree: input.worktree, strictness: input.strictness ?? "LOOSE" }
    const targetResolved = resolveLexical(copyTarget, input.cwd, expandHome("~"))
    const absolute = targetResolved.absolute
    const inWorktree = absolute !== undefined && isWithinLexical(input.worktree, absolute)
    const lower = absolute?.toLowerCase() ?? ""
    const inTemp = lower === "/tmp" || lower.startsWith("/tmp/") || lower === "/var/tmp" || lower.startsWith("/var/tmp/")
    if (!inWorktree && !inTemp) return undefined
    if (!checkPathSensitivity(copyTarget, ctx).parseable || checkPathSensitivity(copyTarget, ctx).sensitive) {
      return undefined
    }
    if (copySource && checkPathSensitivity(copySource, ctx).sensitive) return undefined
    return {
      verdict: "ALLOW",
      rules: ["filesystem.backup-copy"],
      reason: "Creates a non-critical backup by copying",
      fingerprints: [],
    }
  }

  const deletion = parseDeleteInvocation(segment)
  if (!deletion) return undefined
  const loose = (input.strictness ?? "LOOSE") !== "HARD"
  const identityBackupTargets = deletion.targets.filter((target) => {
    const literal = literalPathToken(target)
    return Boolean(literal && backupPathIdentity(literal))
  })
  const obviousBackupTargets = loose
    ? deletion.targets.filter((target) => {
        const literal = literalPathToken(target)
        return Boolean(literal && !backupPathIdentity(literal) && obviousBackupIdentity(literal))
      })
    : []
  if (identityBackupTargets.length === 0 && obviousBackupTargets.length === 0) {
    if (!deletion.parseable && BACKUP_SUFFIX_REFERENCE.test(segment)) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-delete-unverified"],
        reason: "Backup deletion could not be verified exactly",
        fingerprints: [],
      }
    }
    return undefined
  }
  if (
    !deletion.parseable ||
    identityBackupTargets.length + obviousBackupTargets.length !== deletion.targets.length
  ) {
    // Mixed verified/unverified targets keep the historical all-or-nothing DENY
    // only when an exact-suffix backup is involved; obvious-only mixes fall
    // through to the general pipeline (ASK → dynamic review) as before.
    if (identityBackupTargets.length === 0) return undefined
    return {
      verdict: "DENY",
      rules: ["filesystem.backup-delete-unverified"],
      reason: "Backup deletion contains unverified or non-backup targets",
      fingerprints: [],
    }
  }

  let siblingVerified = false
  let verifiedAny = false
  for (const target of [...identityBackupTargets, ...obviousBackupTargets]) {
    const inspected = await inspectBackupDeletionTarget(target, input)
    if (!inspected.allowed) {
      // A failed obvious-only target must not become a new static DENY: without
      // the exact-suffix anchor its verification is heuristic, so fall through
      // to the general pipeline (ASK → dynamic review) as before.
      if (identityBackupTargets.length === 0) return undefined
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-delete"],
        reason: inspected.reason,
        fingerprints: [],
      }
    }
    verifiedAny = true
    if (inspected.sibling) siblingVerified = true
  }
  if (!verifiedAny) return undefined
  if (input.strictness === "HARD") {
    return {
      verdict: "DENY",
      rules: ["hard.backup-delete"],
      reason: `Permanent deletion of backup targets is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
      fingerprints: [],
    }
  }
  return {
    verdict: "ALLOW",
    rules: ["filesystem.backup-delete"],
    reason: siblingVerified
      ? "Every backup is an obvious backup file with a similarly named sibling"
      : "Every backup has an exact original and is older than two minutes",
    fingerprints: [],
  }
}

function decodePowerShellBase64(value: string) {
  try {
    const bytes = Buffer.from(value, "base64")
    if (!bytes.length) return []
    const candidates = [bytes.toString("utf8"), bytes.toString("utf16le")]
    return candidates
      .map((item) => item.replace(/\0/g, "").trim())
      .filter((item) => item.length > 0 && /[\p{L}\p{N}\s"'`$;|&()./\\-]/u.test(item))
  } catch {
    return []
  }
}

function extractDecodedPayloads(script: string, opts?: { executedOnly?: boolean }) {
  const decoded: string[] = []
  const patterns: RegExp[] = [
    /(?:-encodedcommand|-enc)\s+["']?([A-Za-z0-9+/]{12,}={0,2})["']?/gi,
    // `echo <b64> | base64 -d` decodes a payload. Whether that payload is
    // EXECUTED depends on the downstream consumer: `… | base64 -d | sh`
    // runs it, `… | base64 -d > fixture.bin` only stores it. With
    // executedOnly the payload surface is collected only when the pipeline
    // continues into a code interpreter — storing a decoded blob without a
    // proven executor goes to the dynamic reviewer (execution.wrapper ASK),
    // never to the floor scans.
    opts?.executedOnly
      ? /\b(?:echo|printf)\s+["']?([A-Za-z0-9+/]{16,}={0,2})["']?\s*\|\s*base64\s+(?:-d|--decode)\b[^\n]{0,300}?\|\s*(?:sh|bash|zsh|dash|ksh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node|ruby|perl|php|powershell|pwsh|eval|source|\.\s|xargs\b|busybox\s+sh)\b/gi
      : /\b(?:echo|printf)\s+["']?([A-Za-z0-9+/]{16,}={0,2})["']?\s*\|\s*base64\s+(?:-d|--decode)/gi,
  ]

  for (const pattern of patterns) {
    for (const match of script.matchAll(pattern)) {
      for (const candidate of decodePowerShellBase64(match[1] ?? "")) {
        if (!decoded.includes(candidate)) decoded.push(candidate)
        if (decoded.length >= MAX_DECODED_PAYLOADS) return decoded
      }
    }
  }
  return decoded
}

function extractQuotedWrappers(script: string) {
  return extractQuotedWrapperPayloads(script).map((payload) => payload.payload)
}

/** Like `extractQuotedWrappers` but keeps the interpreter leaf so rule scans
 *  can judge a language payload by its execution sinks instead of raw text. */
function extractQuotedWrapperPayloads(script: string): { payload: string; leaf: string }[] {
  const payloads: { payload: string; leaf: string }[] = []
  const patterns: Array<{ re: RegExp; leaf: RegExpExecArray | null } | RegExp> = [
    /\b(bash|sh|zsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node|ruby|perl|php|lua|deno|bun)\b[^\n]{0,80}\s-(?:c|e|r)\s+(["'])([\s\S]{1,32000}?)\2/gi,
    /\b(cmd(?:\.exe)?)\b[^\n]{0,80}\s\/c\s+(["'])([\s\S]{1,32000}?)\2/gi,
    /\b(powershell|pwsh)\b[^\n]{0,120}\s-(?:command|c)\s+(["'])([\s\S]{1,32000}?)\2/gi,
  ]
  for (const pattern of patterns) {
    const re = pattern as RegExp
    for (const match of script.matchAll(re)) {
      const leaf = (match[1] ?? "").toLowerCase().replace(/\.exe$/, "")
      const payload = match[3]?.trim()
      if (payload && !payloads.some((p) => p.payload === payload)) {
        payloads.push({ payload, leaf })
      }
      if (payloads.length >= MAX_DECODED_PAYLOADS) return payloads
    }
  }
  return payloads
}

/** Rule-scan surfaces for executed wrapper payloads: shell-dialect payloads
 *  (bash -c, cmd /c, pwsh -Command) scan raw since the floor rules ARE shell
 *  rules; language payloads reduce to their sink-argument blocks so a literal
 *  `rm -rf /` inside `python3 -c 'print("rm -rf /")'` stays data. */
function ruleScanWrappers(script: string): string[] {
  const out: string[] = []
  for (const { payload, leaf } of extractQuotedWrapperPayloads(script)) {
    if (LANG_INLINE_LEAVES.has(leaf)) {
      const sinks = langDestructiveRuleView(payload, leaf).trim()
      if (sinks) out.push(sinks)
    } else {
      out.push(payload)
    }
  }
  return out
}

function stripLeadingDirectoryChanges(script: string) {
  let value = script.trim()
  for (let index = 0; index < 4; index += 1) {
    const match = value.match(/^(?:cd|pushd|set-location)\s+(?:"[^"]+"|'[^']+'|[^;&|]+)\s*&&\s*([\s\S]+)$/i)
    if (!match) break
    value = match[1].trim()
  }
  return value
}

const DELETE_COMMANDS = new Set([
  "rm",
  "remove-item",
  "del",
  "erase",
  "unlink",
  "rmdir",
  "rd",
  "ri",
])

function isFullyQuoted(value: string) {
  const trimmed = value.trim()
  if (trimmed.length < 2) return false
  const first = trimmed[0]
  const last = trimmed[trimmed.length - 1]
  return (first === '"' || first === "'") && first === last
}

function isDynamicCdTarget(rawTarget: string, target: string) {
  if (target === "-" || /^~[-+]/.test(target)) return true
  if (/[\n;&|]/.test(rawTarget)) return true
  if (/\$\{|`|\$\(|\$[A-Za-z_]|%/.test(target)) return true
  if (!isFullyQuoted(rawTarget) && /\s/.test(target)) return true
  return false
}

const CD_FLAGS = /^-(?:P|L|e)$/

function parseCdSegment(text: string): { dir: string | undefined } | undefined {
  const trimmed = text.trim()
  if (/^\(?\s*(?:cd|pushd|popd|set-location)\s*\)?$/i.test(trimmed)) {
    // Bare `cd` returns to the home directory; bare pushd/popd/set-location
    // land somewhere unknown (stack-dependent or profile-dependent).
    return { dir: /^\(?\s*cd\b/i.test(trimmed) ? "~" : undefined }
  }
  if (/^\(?\s*(?:popd\b|cd\.\.\s*\)?$)/i.test(trimmed)) {
    return { dir: undefined }
  }
  const match = trimmed.match(/^\(?\s*(?:cd|pushd|set-location)\s+(.+)$/i)
  if (!match) return undefined
  // `cd` accepts -P/-L/-e option letters and a `--` end-of-options marker
  // before the directory operand; they affect resolution semantics, not the
  // destination itself.
  const isCd = /^\(?\s*cd\b/i.test(trimmed)
  let rest = match[1].trim()
  if (isCd) {
    const tokens = rest.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    let endOfOptions = false
    while (tokens.length > 0) {
      const token = tokens[0] ?? ""
      if (!endOfOptions && token === "--") {
        endOfOptions = true
        tokens.shift()
        continue
      }
      if (!endOfOptions && CD_FLAGS.test(token)) {
        tokens.shift()
        continue
      }
      break
    }
    rest = tokens.join(" ")
    if (!rest) return { dir: "~" }
  }
  const rawTarget = rest
  const target = stripMatchingQuotes(rawTarget)
  return { dir: isDynamicCdTarget(rawTarget, target) ? undefined : target }
}

function resolveCdBase(dir: string | undefined, base: string | undefined) {
  if (dir === undefined) return undefined
  const expanded = expandHome(dir)
  if (!expanded || /[*?[\]`$%{}]/.test(expanded) || /[<>|]/.test(expanded)) return undefined
  return path.isAbsolute(expanded) ? path.normalize(expanded) : base ? path.resolve(base, expanded) : undefined
}

function isWorktreeDisposableTarget(target: string, cwd: string, worktree: string): boolean {
  const literal = literalPathToken(target)
  if (!literal) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  return resolved.absolute !== undefined && isWithinLexical(worktree, resolved.absolute)
}

function isTempDisposableTarget(target: string, cwd: string): boolean {
  const literal = literalPathToken(target)
  if (!literal) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  if (!resolved.absolute) return false
  const absolute = resolved.absolute.toLowerCase()
  if (absolute === "/tmp" || absolute.startsWith("/tmp/")) return true
  if (absolute === "/var/tmp" || absolute.startsWith("/var/tmp/")) return true
  const downloads = expandHome("~/Downloads").toLowerCase()
  return absolute.startsWith(`${downloads}/`)
}

function isTempFindRoot(root: string, cwd: string): boolean {
  const literal = literalPathToken(root)
  if (!literal) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  if (!resolved.absolute) return false
  const absolute = resolved.absolute.toLowerCase()
  return absolute === "/tmp" || absolute.startsWith("/tmp/")
}

async function isExplicitDisposableCleanup(script: string, cwd: string, worktree: string): Promise<boolean> {
  const value = stripLeadingDirectoryChanges(script).replace(/\s+/g, " ").trim()

  const findTmp = value.match(/^find\s+(\S+)\b[^;&|]*\s-mtime\s+\+\d+\b[^;&|]*\s-delete$/i)
  if (findTmp) return isTempFindRoot(findTmp[1], cwd)

  // A trailing reinstall keeps the cleanup shape (`rm -rf node_modules && npm i`).
  const withoutInstall = value.replace(/\s*&&\s*(?:npm|pnpm|yarn|bun)\s+(?:install|i)$/i, "")

  const rmForceFile = withoutInstall.match(/^rm\s+-f\s+([^;&|]+)$/i)
  if (rmForceFile) {
    const target = rmForceFile[1].trim()
    if (/^\/tmp\//.test(target) || /^~[\\/]Downloads[\\/][^\s]*\.tmp$/.test(target)) {
      return isTempDisposableTarget(target, cwd)
    }
    return false
  }

  const deletion = parseRecursiveForceDeletion(withoutInstall)
  if (!deletion) return false
  for (const t of deletion.targets) {
    if (!(await isDisposableCleanupTarget(t, cwd, worktree))) return false
  }
  return true
}

function shellEscapeCharacter(shell: string) {
  const name = path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase()
  if (name === "pwsh" || name === "powershell") return "`"
  if (name === "cmd") return "^"
  return "\\"
}

function shellSupportsSingleQuotes(shell: string) {
  return path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase() !== "cmd"
}

function strictTimeoutRemainder(tokens: string[]): string | undefined {
  let i = 1
  for (;;) {
    if (i >= tokens.length) return undefined
    const lower = tokens[i].toLowerCase()
    if (lower === "--") {
      i += 1
      break
    }
    if (!lower.startsWith("-")) break
    if (lower === "-k" || lower === "--kill-after" || lower === "-s" || lower === "--signal") {
      i += 2
      continue
    }
    if (lower === "--verbose" || lower === "--foreground" || lower === "--preserve-status") {
      i += 1
      continue
    }
    return undefined
  }
  if (i >= tokens.length || !/^\d+(\.\d+)?[smhd]?$/.test(tokens[i] ?? "")) return undefined
  i += 1
  if (i >= tokens.length) return undefined
  return tokens.slice(i).join(" ")
}

/**
 * Strict wrapper stripping (mirrors Claude Code `stripWrappersFromArgv`).
 * Unknown or malformed flags ⇒ do NOT strip ⇒ the segment falls through to ASK.
 * `env -S`, `watch`, and flag-injection forms are deliberately not stripped.
 */
function stripWrapperPrefix(segment: string): string | undefined {
  const original = segment
  const tokens = simpleInvocationTokens(segment.trim())
  if (tokens.length === 0) return segment
  const leaf = commandLeaf(tokens[0] ?? "")
  if (leaf === "timeout") return strictTimeoutRemainder(tokens)
  if (leaf === "time" || leaf === "nohup" || leaf === "setsid") {
    if (tokens.length >= 2 && !(tokens[1] ?? "").startsWith("-")) return tokens.slice(1).join(" ")
    return original
  }
  if (leaf === "nice") {
    let i = 1
    if (i < tokens.length && tokens[i] === "--") return tokens.slice(i + 1).join(" ")
    if (i < tokens.length && /^-\d+$/.test(tokens[i] ?? "")) return tokens.slice(i + 1).join(" ")
    if (i < tokens.length && (tokens[i] === "-n" || tokens[i] === "--adjustment")) {
      if (i + 1 < tokens.length && /^-?\d+$/.test(tokens[i + 1] ?? "")) return tokens.slice(i + 2).join(" ")
      return original
    }
    if (i < tokens.length && !(tokens[i] ?? "").startsWith("-")) return tokens.slice(1).join(" ")
    return original
  }
  if (leaf === "ionice") {
    let i = 1
    while (i < tokens.length && (tokens[i] ?? "").startsWith("-") && tokens[i] !== "--") {
      const t = tokens[i] ?? ""
      if (t === "-t") {
        i += 1
      } else if (t === "-c" || t === "-n" || t === "-p") {
        if (i + 1 >= tokens.length) return original
        i += 2
      } else {
        return original
      }
    }
    if (i >= tokens.length || (tokens[i] ?? "").startsWith("-") || (tokens[i] ?? "") === "--") return original
    return tokens.slice(i).join(" ")
  }
  if (leaf === "stdbuf") {
    let i = 1
    while (i < tokens.length && ((tokens[i] ?? "").startsWith("-") || tokens[i] === "--")) {
      const t = tokens[i] ?? ""
      if (t === "--") {
        i += 1
        break
      }
      if (/^-[ioe]$/.test(t)) {
        if (i + 1 >= tokens.length) return original
        i += 2
        continue
      }
      if (/^-[ioe]\S+$/.test(t) || t === "-L" || t === "--line-buffered") {
        i += 1
        continue
      }
      return original
    }
    if (i >= tokens.length) return original
    return tokens.slice(i).join(" ")
  }
  if (leaf === "env") {
    let i = 1
    let sawCommand = false
    while (i < tokens.length) {
      const t = tokens[i] ?? ""
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
        i += 1
        continue
      }
      if (t === "-i" || t === "--ignore-environment" || t === "-0" || t === "--null") {
        i += 1
        continue
      }
      if (t === "-u" || t === "--unset" || t === "--unset-environment") {
        if (i + 1 >= tokens.length) return original
        i += 2
        continue
      }
      if (t === "-v" || t === "--debug") {
        i += 1
        continue
      }
      if (t === "-S" || t === "--split-string" || t === "-C" || t === "-P" || t === "--argv0") {
        return original
      }
      sawCommand = true
      break
    }
    if (!sawCommand || i >= tokens.length) return original
    return tokens.slice(i).join(" ")
  }
  return segment
}

function stripHarmlessPrefixes(segment: string): string {
  let result = segment.trim()
  for (let depth = 0; depth < 3; depth += 1) {
    const subshell = result.match(/^\(([\s\S]+)\)$/)
    if (subshell) {
      result = subshell[1].trim()
      continue
    }
    const wrapperStripped = stripWrapperPrefix(result)
    if (wrapperStripped && wrapperStripped !== result) {
      result = wrapperStripped
      continue
    }
    break
  }
  return result
}

function maskHeredocBody(text: string): string {
  const match = text.match(/<<-?\s*(?:'([^']+)'|"([^"]+)"|(\w+))/)
  if (!match) return text
  const delimiter = match[1] ?? match[2] ?? match[3]
  if (!delimiter) return text
  const bodyStart = (match.index ?? 0) + match[0].length
  const lineEnd = text.indexOf("\n", bodyStart)
  if (lineEnd < 0) return text
  const escapedDelim = delimiter.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const closingRegex = new RegExp(`^\\s*${escapedDelim}\\s*$`, "m")
  const bodyContent = text.slice(lineEnd + 1)
  const closingMatch = bodyContent.match(closingRegex)
  if (!closingMatch) return text
  const bodyEnd = lineEnd + 1 + (closingMatch.index ?? 0) + closingMatch[0].length
  return text.slice(0, lineEnd + 1) + "[heredoc-body]" + text.slice(bodyEnd)
}

// --- heredoc consumer model --------------------------------------------------
//
// A heredoc body's danger is defined by its CONSUMER, not its content:
// `cat <<'EOF'` writes inert text, `bash <<'EOF'` runs the body as shell code,
// `python3 - <<'PY'` runs it as a language program, `ssh host <<'EOF'` runs it
// as a remote shell script, and `psql <<'SQL'` feeds a database shell that can
// still escape to the host. An unquoted delimiter additionally expands the
// body in the invoking shell before the consumer reads it, so unquoted bodies
// are never masked regardless of consumer.

type HeredocInfo = {
  /** Delimiter word (quotes/escapes stripped). */
  delim: string
  /** Quoted delimiter (`<<'EOF'`/`<<"EOF"`/`<<\EOF`): the body is not expanded. */
  quoted: boolean
  /** Body content range inside the segment. */
  bodyRange: { start: number; end: number }
  /** Offset where the closing delimiter line ends; undefined when the heredoc
   * never closed (per bash the body then runs to end of input). */
  closeEnd?: number
  /** Offset where the header (the `<<` operator's line) started. */
  headerStart: number
  /** The full header line carrying the `<<` operator. */
  headerText: string
  /** Offset of the `<<` operator inside the segment. */
  opStart: number
}

/**
 * Parses every heredoc in a single segment. Bodies are consumed line-wise in
 * declaration order, `<<-` delimiters tolerate leading tabs, and a missing
 * closing line reports the remaining text as the (unclosed) body.
 */
function parseHeredocs(text: string): HeredocInfo[] {
  const heredocs: HeredocInfo[] = []
  const pending: HeredocInfo[] = []
  let headerStart = -1
  let headerEnd = -1
  let lineStart = 0
  let quote: "'" | '"' | undefined
  let escaped = false

  const finishLine = (end: number) => {
    // Closing-delimiter check against the line [lineStart, end).
    if (pending.length > 0 && pending[0].bodyRange.start >= 0) {
      const h = pending[0]
      const line = text.slice(lineStart, end)
      const stripped = h.quoted || line === line.trimStart() ? line : line.replace(/^\t+/, "")
      if (stripped.trim() === h.delim) {
        h.bodyRange.end = lineStart
        h.closeEnd = end
        pending.shift()
        heredocs.push(h)
      }
      lineStart = end
      return
    }
    if (pending.length > 0) {
      // This line is the header: it ends at `end`, bodies begin there.
      headerEnd = end
      const headerText = text.slice(headerStart, end)
      for (const h of pending) h.headerText = headerText
      pending[0].bodyRange.start = end
    }
    lineStart = end
  }

  for (let i = 0; i < text.length; i += 1) {
    if (pending.length > 0 && pending[0].bodyRange.start >= 0) {
      if (text[i] === "\n") finishLine(i + 1)
      continue
    }
    if (escaped) {
      escaped = false
      continue
    }
    if (text[i] === "\\") {
      escaped = true
      continue
    }
    if (quote) {
      if (text[i] === quote) quote = undefined
      continue
    }
    if (text[i] === "'" || text[i] === '"') {
      quote = text[i] as "'" | '"'
      continue
    }
    if (text[i] === "\n") {
      finishLine(i + 1)
      continue
    }
    if (text[i] === "<" && text[i + 1] === "<") {
      if (headerStart < 0) headerStart = lineStart
      let j = i + 2
      if (text[j] === "-") j += 1
      while (j < text.length && (text[j] === " " || text[j] === "\t")) j += 1
      let delim = ""
      let quoted = false
      const first = text[j]
      if (first === "'" || first === '"') {
        quoted = true
        j += 1
        while (j < text.length && text[j] !== first) {
          delim += text[j]
          j += 1
        }
        j += 1
      } else if (first === "\\") {
        quoted = true
        j += 1
        while (j < text.length && /\w/.test(text[j])) {
          delim += text[j]
          j += 1
        }
      } else {
        while (j < text.length && /\w/.test(text[j])) {
          delim += text[j]
          j += 1
        }
      }
      if (delim) {
        pending.push({
          delim,
          quoted,
          bodyRange: { start: -1, end: -1 },
          headerStart,
          headerText: "",
          opStart: i,
        })
        i = j - 1
      }
      continue
    }
  }
  finishLine(text.length)

  // Unclosed heredocs: bash consumes to end of input as the body.
  for (const h of pending) {
    if (h.bodyRange.start < 0) h.bodyRange.start = text.length
    h.bodyRange.end = text.length
    heredocs.push(h)
  }
  return heredocs
}

type HeredocConsumer = "data" | "shell" | "lang" | "remote" | "db" | "unknown"

const HEREDOC_DATA_COMMANDS = new Set([
  "cat", "tee", "sponge", "dd", "grep", "rg", "jq", "yq", "awk", "gawk", "mawk",
  "sed", "sort", "wc", "head", "tail", "uniq", "column", "tr", "cut", "paste",
  "comm", "diff", "less", "more", "base64", "md5sum", "sha1sum", "sha256sum",
  "sha224sum", "sha384sum", "sha512sum", "gzip", "gunzip", "iconv", "fold",
  "fmt", "nl", "expand", "unexpand", "tac", "strings", "xxd", "od", "hexdump",
])
const HEREDOC_SHELL_COMMANDS = new Set(["bash", "sh", "zsh", "dash", "ksh"])
const HEREDOC_LANG_COMMANDS = new Set([
  "python", "python3", "py", "node", "deno", "bun", "ruby", "perl", "php",
  "lua", "rscript", "pwsh", "powershell",
])
const HEREDOC_DB_COMMANDS = new Set([
  "psql", "mysql", "mariadb", "sqlite3", "mongosh", "mongo", "redis-cli",
])
/** ssh options that consume a separate argument token. */
const SSH_VALUE_FLAGS = new Set([
  "-b", "-c", "-d", "-e", "-f", "-i", "-j", "-l", "-m", "-o", "-p", "-q", "-s", "-w",
])
const SSH_LONG_VALUE_FLAGS = new Set(["--config", "--ssh-option"])

/** The pipeline part carrying the `<<` operator: bounded by unquoted
 * `|`, `&`, `;`, or newline inside the header line. */
function heredocPipelinePart(headerText: string, opOffset: number) {
  let start = 0
  let quote: "'" | '"' | undefined
  let escaped = false
  for (let i = 0; i < opOffset; i += 1) {
    const ch = headerText[i]
    if (escaped) { escaped = false; continue }
    if (ch === "\\") { escaped = true; continue }
    if (quote) { if (ch === quote) quote = undefined; continue }
    if (ch === "'" || ch === '"') { quote = ch; continue }
    if (ch === "|" || ch === ";" || ch === "\n" || (ch === "&" && headerText[i + 1] !== "&")) start = i + 1
  }
  let end = headerText.length
  quote = undefined
  escaped = false
  for (let i = opOffset + 2; i < headerText.length; i += 1) {
    const ch = headerText[i]
    if (escaped) { escaped = false; continue }
    if (ch === "\\") { escaped = true; continue }
    if (quote) { if (ch === quote) quote = undefined; continue }
    if (ch === "'" || ch === '"') { quote = ch; continue }
    if (ch === "|" || ch === ";" || (ch === "&" && headerText[i + 1] !== "&")) {
      end = i
      break
    }
  }
  return { start, end }
}

/**
 * Command tokens of the heredoc's own pipeline part: env assignments, leading
 * wrappers, `<<` operators/delimiters, and output redirects are stripped so
 * `[0]` is the consuming command word.
 */
function heredocConsumerTokens(h: HeredocInfo): string[] {
  const part = heredocPipelinePart(h.headerText, h.opStart - h.headerStart)
  const body = h.headerText.slice(part.start, part.end)
  // Remove every `<<[-] delim` occurrence, then output redirects.
  const withoutHeredocs = body.replace(/<<-?\s*(?:'[^']*'|"[^"]*"|\\?\w+)/g, " ")
  const withoutRedirects = stripOutputRedirects(withoutHeredocs)
  if (withoutRedirects === undefined) return []
  let tokens = simpleInvocationTokens(withoutRedirects).filter(
    (token) => !/^\d*>&\d+$/.test(token) && !/^\d*&?>$/.test(token),
  )
  while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
  if ((tokens[0] ?? "").toLowerCase() === "sudo") tokens = tokens.slice(1)
  if ((tokens[0] ?? "").toLowerCase() === "env") {
    tokens = tokens.slice(1)
    while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
  }
  if ((tokens[0] ?? "").toLowerCase() === "command") tokens = tokens.slice(1)
  if ((tokens[0] ?? "").toLowerCase() === "wsl") {
    const separator = tokens.indexOf("--")
    tokens = separator >= 0 ? tokens.slice(separator + 1) : tokens.slice(1)
  }
  return tokens
}

/** Shell interpreters: the body is shell code unless the program clearly comes
 * from a file argument or `-c`. Ambiguity defaults to stdin = code (fail-closed
 * toward review). */
function shellProgramFromStdin(tokens: string[]): boolean {
  let sawDash = false
  for (let i = 1; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (token === "--") {
      const rest = tokens.slice(i + 1)
      return rest.length === 0 || (rest.length === 1 && rest[0] === "-") || sawDash
    }
    if (/^-[a-z]*c[a-z]*$/i.test(token)) return false
    if (token === "-") {
      sawDash = true
      continue
    }
    if (token.startsWith("-")) continue
    return false
  }
  return true
}

/** Language interpreters: the body is language code only when the program is
 * read from stdin (no positional script, no `-c`/`-e`/`--eval`/`-m`/`-file`
 * code-or-module source). Flag values are skipped so `python3 -W ignore -`
 * still resolves to stdin; anything ambiguous resolves to code. */
function interpreterProgramFromStdin(tokens: string[]): boolean {
  const longFlagsWithValues = new Set([
    "--check-hash-based-pycs", "--explain", "--help-env", "--help-xoptions",
    "--help-all", "--init", "--install", "--require", "--eval", "-eval",
    "--module", "--command", "--config", "--port", "--host", "--user",
  ])
  for (let i = 1; i < tokens.length; i += 1) {
    const token = tokens[i]
    const lower = token.toLowerCase()
    if (token === "--") {
      const rest = tokens.slice(i + 1)
      return rest.length === 0 || (rest.length === 1 && rest[0] === "-")
    }
    if (["-c", "-e", "-m", "--eval", "--command", "-command", "-file", "--print"].includes(lower)) {
      return false
    }
    if (token === "-") continue
    if (token.startsWith("--") && longFlagsWithValues.has(lower)) {
      i += 1
      continue
    }
    if (token.startsWith("-") && token.length > 1) {
      // Unknown single-dash flag: assume it consumes the next token so a flag
      // value is never mistaken for the script path (fail toward code).
      const next = tokens[i + 1]
      if (next !== undefined && !next.startsWith("-")) i += 1
      continue
    }
    return false
  }
  return true
}

/** `ssh`/`mosh` consume stdin as a remote command stream only when the argv
 * carries no remote command of its own (`ssh host cmd…` leaves stdin as data). */
function remoteProgramFromStdin(tokens: string[]): boolean {
  let positionals = 0
  for (let i = 1; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (token === "--") {
      // Everything after `--` is positional (host first).
      positionals += tokens.length - i - 1
      break
    }
    if (SSH_LONG_VALUE_FLAGS.has(token.toLowerCase()) || SSH_VALUE_FLAGS.has(token.toLowerCase())) {
      i += 1
      continue
    }
    if (token.startsWith("-") && token.length > 1) continue
    positionals += 1
    if (positionals >= 2) return false
  }
  return positionals < 2
}

/** `docker|podman|kubectl exec -i` and `lxc|incus exec` forward stdin to the
 * remote process; without `-i` the body is unread data for docker/podman/
 * kubectl. */
function containerExecReadsStdin(tokens: string[]): boolean {
  const leaf = commandLeaf(tokens[0] ?? "")
  const subcommand = (tokens[1] ?? "").toLowerCase()
  if (leaf === "lxc" || leaf === "incus") return subcommand === "exec"
  if (subcommand !== "exec") return false
  return tokens
    .slice(2)
    .some((token) => /^-[a-z]*i/i.test(token) || token === "--interactive" || token === "--stdin")
}

function heredocConsumer(h: HeredocInfo): HeredocConsumer {
  const tokens = heredocConsumerTokens(h)
  if (tokens.length === 0) {
    // Pure redirection (`> file <<EOF`) writes the body to a file: inert data.
    return />/.test(h.headerText) ? "data" : "unknown"
  }
  const leaf = commandLeaf(tokens[0] ?? "") ?? ""
  if (HEREDOC_DATA_COMMANDS.has(leaf)) {
    return "data"
  }
  if (leaf === "cp") {
    const sources = tokens.slice(1).filter((token) => !token.startsWith("-"))
    return sources[0] === "/dev/stdin" || sources[0] === "/dev/fd/0" ? "data" : "unknown"
  }
  if (HEREDOC_SHELL_COMMANDS.has(leaf)) {
    return shellProgramFromStdin(tokens) ? "shell" : "data"
  }
  if (HEREDOC_LANG_COMMANDS.has(leaf)) {
    return interpreterProgramFromStdin(tokens) ? "lang" : "data"
  }
  if (leaf === "ssh" || leaf === "mosh") {
    return remoteProgramFromStdin(tokens) ? "remote" : "data"
  }
  if (["docker", "podman", "kubectl", "lxc", "incus"].includes(leaf)) {
    return containerExecReadsStdin(tokens) ? "remote" : "data"
  }
  if (HEREDOC_DB_COMMANDS.has(leaf)) return "db"
  return "unknown"
}

const DB_SHELL_ESCAPE = /\\!|\bxp_cmdshell\b|\bCOPY\b[\s\S]{0,200}\bPROGRAM\b|\bsystem\s*\(/i

/**
 * True when the heredoc's pipeline part is piped onward and a downstream
 * stage executes what it receives (shell/language/DB/remote interpreter or
 * an unknown leaf — ambiguous stages count as code). `cat <<EOF | sh`,
 * `tee <<EOF | bash`, and `cat <<EOF | unknown-tool` keep their bodies
 * visible to the floor scans; `cat <<EOF | wc -l` stays data.
 */
function heredocFlowsToCode(h: HeredocInfo): boolean {
  const { end } = heredocPipelinePart(h.headerText, h.opStart - h.headerStart)
  const downstream = h.headerText.slice(end)
  if (!/^\s*\|/.test(downstream)) return false
  const rest = downstream.replace(/^\s*\|&?\s*/, "")
  // Naive stage split: quoted pipes inside downstream arguments merely
  // produce extra fragments whose unknown leaf resolves to code —
  // conservative in the masking direction.
  for (const part of rest.split(/[|&;]/)) {
    const leaf = commandLeaf(simpleInvocationTokens(part)[0] ?? "")
    // Only known data consumers keep the body masked; shells, interpreters,
    // DB/remote consumers, and unknown leaves all count as code.
    if (!HEREDOC_DATA_COMMANDS.has(leaf ?? "")) return true
  }
  return false
}

/** Stricter than `heredocFlowsToCode`: true only when the downstream pipeline
 *  contains a KNOWN executor that provably consumes stdin as code — a shell
 *  or language interpreter reading its program from stdin, a DB shell, or a
 *  remote exec forwarding stdin. Unknown downstream leaves do NOT qualify:
 *  they are the ambiguous case routed to the dynamic reviewer (payload-text
 *  fix a), whereas a proven executor keeps the body on the DENY path. */
function heredocFlowsToKnownExecutor(h: HeredocInfo): boolean {
  const { end } = heredocPipelinePart(h.headerText, h.opStart - h.headerStart)
  const downstream = h.headerText.slice(end)
  if (!/^\s*\|/.test(downstream)) return false
  const rest = downstream.replace(/^\s*\|&?\s*/, "")
  for (const part of rest.split(/[|&;]/)) {
    const tokens = simpleInvocationTokens(part)
    if (tokens.length === 0) continue
    const leaf = commandLeaf(tokens[0] ?? "") ?? ""
    if (HEREDOC_SHELL_COMMANDS.has(leaf)) {
      if (shellProgramFromStdin(tokens)) return true
      continue
    }
    if (HEREDOC_LANG_COMMANDS.has(leaf)) {
      if (interpreterProgramFromStdin(tokens)) return true
      continue
    }
    if (HEREDOC_DB_COMMANDS.has(leaf)) return true
    if (leaf === "ssh" || leaf === "mosh") {
      if (remoteProgramFromStdin(tokens)) return true
      continue
    }
    if (["docker", "podman", "kubectl", "lxc", "incus"].includes(leaf) && containerExecReadsStdin(tokens)) {
      return true
    }
  }
  return false
}

/**
 * Masks heredoc bodies that cannot influence execution (E2): the body must
 * feed a KNOWN data consumer whose output is not piped into code, AND the
 * body must be inert — a quoted delimiter (no expansion) or a proven
 * expansion-free unquoted body. Quoted bodies feeding `sh`/`python`/DB
 * stdin stay visible: quoting suppresses shell expansion, not interpretation
 * of stdin. Write-to-file heredocs keep their correlation check on the
 * original segment text.
 */
function maskHeredocBodies(
  text: string,
  shell: string,
  maskableConsumer: (h: HeredocInfo) => boolean,
): string {
  const heredocs = parseHeredocs(text)
  if (heredocs.length === 0) return text
  let out = ""
  let cursor = 0
  for (const h of heredocs) {
    const maskable =
      maskableConsumer(h) &&
      (h.quoted || !hasUnquotedExpansion(text.slice(h.bodyRange.start, h.bodyRange.end), shell))
    if (maskable) {
      // The masked text must still LEX as a heredoc (a lexer that sees `<<EOF`
      // consumes to the closing line), so the closing line is kept in place
      // with its delimiter word blanked — a bare `rm`/`bash` delimiter name
      // can never resurface as an executable token.
      const closing =
        h.closeEnd === undefined
          ? ""
          : (() => {
              const line = text.slice(h.bodyRange.end, h.closeEnd)
              const nl = line.endsWith("\n") ? "\n" : ""
              const inner = nl ? line.slice(0, -1) : line
              return inner.replace(/\S/g, " ") + nl
            })()
      out += text.slice(cursor, h.bodyRange.start) + "[heredoc-body]\n" + closing
    } else {
      out += text.slice(cursor, h.closeEnd ?? h.bodyRange.end)
    }
    cursor = h.closeEnd ?? h.bodyRange.end
  }
  return out + text.slice(cursor)
}

function maskHeredocDataBodies(text: string, shell: string): string {
  return maskHeredocBodies(
    text,
    shell,
    (h) => heredocConsumer(h) === "data" && !heredocFlowsToCode(h),
  )
}

/**
 * Floor-scan variant that additionally masks heredoc bodies whose consumer is
 * UNKNOWN — when the static layer cannot prove the body is only stored/read as
 * data, but also cannot prove it reaches an executor. Those ambiguous bodies
 * are routed to the dynamic reviewer (execution.ambiguous-heredoc ASK in
 * classifyHeredocSegment) instead of hitting the floor DENY rules as raw text.
 * Bodies provably piped into an executor (`cat <<EOF | sh`) stay visible.
 */
function maskHeredocNonExecBodies(text: string, shell: string): string {
  return maskHeredocBodies(
    text,
    shell,
    (h) =>
      (heredocConsumer(h) === "data" || heredocConsumer(h) === "unknown") &&
      !heredocFlowsToCode(h),
  )
}

/** The segment minus all heredoc bodies AND their `<<` operator tokens, so a
 * residual command line classifies exactly like a plain command. */
function heredocResidualText(segment: string, heredocs: HeredocInfo[]): string {
  const headerEnd = heredocs[0] ? segment.indexOf("\n", heredocs[0].headerStart) : -1
  const lastClose = heredocs.length ? (heredocs[heredocs.length - 1].closeEnd ?? segment.length) : segment.length
  const headerLine = headerEnd === -1 ? segment : segment.slice(0, headerEnd)
  const residualHeader = headerLine.replace(/<<-?\s*(?:'[^']*'|"[^"]*"|\\?\w+)/g, " ")
  const trailing = lastClose < segment.length ? segment.slice(lastClose) : ""
  const joined = trailing ? `${residualHeader}\n${trailing}` : residualHeader
  return joined.trim()
}

/**
 * Paths written by this segment's heredocs/redirects that later invocation can
 * turn into code. Returns absolute targets paired with the written body. Only
 * literal, already-closed bodies are correlated.
 */
function heredocWrittenBodies(segment: string, base: string): { target: string; body: string }[] {
  const out: { target: string; body: string }[] = []
  const add = (target: string | undefined, body: string | undefined) => {
    if (!target || body === undefined) return
    const literal = literalPathToken(target)
    if (!literal) return
    const resolved = resolveLexical(literal, base, expandHome("~"))
    if (resolved.absolute) out.push({ target: resolved.absolute, body })
  }

  const heredocs = parseHeredocs(segment)
  if (heredocs.length > 0) {
    const residual = heredocResidualText(segment, heredocs)
    const writes = extractWriteTargets(residual)
    for (const h of heredocs) {
      const body = segment.slice(h.bodyRange.start, h.bodyRange.end)
      for (const target of writes.targets) add(target, body)
    }
  }
  // `echo 'literal' > f` / `printf 'fmt' > f`: a literal write whose content can
  // become code when the target is later invoked.
  const literalWrite = segment.match(/^(?:echo|printf)\s+(['"])([\s\S]*?)\1\s*(?:\d*>>?|&>)\s*(\S+)\s*$/i)
  if (literalWrite) add(literalWrite[3], literalWrite[2])
  return out
}

/** Whether `segment` invokes a previously written path as code: interpreter
 * file argument, `source`/`.` command, or direct `./path` execution. */
function invokedScriptPath(segment: string): string | undefined {
  const stripped = stripHarmlessPrefixes(segment).trim()
  const tokens = simpleInvocationTokens(stripped).map(stripMatchingQuotes)
  if (tokens.length === 0) return undefined
  const leaf = commandLeaf(tokens[0] ?? "") ?? ""
  if (leaf === "source" || leaf === ".") return tokens[1]
  if (HEREDOC_SHELL_COMMANDS.has(leaf) || HEREDOC_LANG_COMMANDS.has(leaf)) {
    for (let i = 1; i < tokens.length; i += 1) {
      const token = tokens[i]
      if (token === "--") return tokens[i + 1]
      if (["-c", "-e", "-m", "--eval", "--command", "-command", "-file"].includes(token.toLowerCase())) {
        return undefined
      }
      if (token.startsWith("-")) continue
      return token
    }
    return undefined
  }
  if (/^\.{0,2}[\\/]|^\//.test(tokens[0])) return tokens[0]
  return undefined
}

type SegmentConnector = "&&" | "||" | ";" | "newline" | "|" | "&"
type CommandSegment = { text: string; incoming?: SegmentConnector }

/** Non-backtracking test for `(?:^|\s)\d*>\s*$` (an fd-redirect prefix such as
 * `2>` immediately before a `>&N` merge). */
function endsWithFdRedirectPrefix(text: string): boolean {
  let i = text.length
  while (i > 0 && /\s/.test(text[i - 1])) i -= 1
  if (i === 0 || text[i - 1] !== ">") return false
  i -= 1
  while (i > 0 && /\d/.test(text[i - 1])) i -= 1
  return i === 0 || /\s/.test(text[i - 1])
}

/**
 * POSIX-shell comment recognition for the lexical split: an unquoted,
 * unescaped `#` at the START OF A SHELL WORD comments out the rest of the
 * physical line (the terminating newline/connector is preserved as a normal
 * separator). `x#y`, `\#`, and quoted hashes are data; heredoc bodies and
 * delimiter lines take precedence, so `#` inside a body stays literal.
 * cmd.exe (`^` escape) has no `#` comment and keeps the old behavior.
 */
function shellSupportsHashComments(shell: string) {
  return shellEscapeCharacter(shell) !== "^"
}

type SegmentSplit = {
  segments: CommandSegment[]
  /** Position-preserving copy of the input with comment text blanked to
   *  spaces: same length, newlines/connectors/quotes intact. Downstream rule
   *  and path scans use this so a comment can neither smuggle a command past
   *  the split (a stray quote inside a comment used to corrupt quote state)
   *  nor manufacture findings (comment text is not executable). */
  commentView: string
}

function splitCommandSegmentsDetailed(script: string, shell: string): SegmentSplit | undefined {
  const escapeCharacter = shellEscapeCharacter(shell)
  const supportsSingleQuotes = shellSupportsSingleQuotes(shell)
  const comments = shellSupportsHashComments(shell)
  const segments: CommandSegment[] = []
  let current = ""
  let commentView = ""
  let quote: "'" | '"' | undefined
  let escaped = false
  let heredocDelim: string | undefined
  let incoming: SegmentConnector | undefined
  // The next unquoted character begins a new shell word (start of input,
  // after blank space, or right after a connector).
  let wordStart = true

  const push = (next?: SegmentConnector) => {
    const segment = current.trim()
    if (segment) segments.push({ text: segment, incoming })
    current = ""
    incoming = next
    wordStart = true
  }
  // A character that cannot start a comment (ordinary word text).
  const eatWordChar = (character: string) => {
    current += character
    commentView += character
    wordStart = false
  }
  // Blank space keeps `wordStart` armed; `\t` also separates words.
  const eatSpace = (character: string) => {
    current += character
    commentView += character
    wordStart = true
  }

  for (let index = 0; index < script.length; index += 1) {
    const character = script[index]

    if (heredocDelim !== undefined) {
      // A line holding only the closing delimiter ends the heredoc: the
      // delimiter is segment text, but the newline that follows it is a
      // normal line separator again so commands on later lines split off.
      if (character === "\n") {
        let lineStart = current.length
        while (lineStart > 0 && current[lineStart - 1] !== "\n") lineStart--
        if (current.slice(lineStart).trim() === heredocDelim) {
          current += character
          commentView += character
          heredocDelim = undefined
          push("newline")
          continue
        }
      }
      eatWordChar(character)
      continue
    }

    if (escaped) {
      eatWordChar(character)
      escaped = false
      continue
    }
    if (character === escapeCharacter && quote !== "'") {
      eatWordChar(character)
      escaped = true
      continue
    }
    if (quote) {
      eatWordChar(character)
      if (character === quote) quote = undefined
      continue
    }
    if (character === '"' || (character === "'" && supportsSingleQuotes)) {
      quote = character
      eatWordChar(character)
      continue
    }
    if (character === "`" && escapeCharacter !== "`") return undefined

    if (character === " " || character === "\t") {
      eatSpace(character)
      continue
    }

    // An unquoted, unescaped `#` starting a word is a shell comment: it is
    // dropped from the segment text and blanked in the neutralized view, but
    // never executed. Comment characters (quotes, backticks, separators)
    // must not alter parse state — this is the A/E1 fix: `rm -rf / #'` used
    // to leave quote state open and corrupt the split.
    if (comments && character === "#" && wordStart) {
      commentView += " "
      index += 1
      while (index < script.length && script[index] !== "\n") {
        commentView += " "
        index += 1
      }
      index -= 1 // reprocess the newline as a normal separator
      continue
    }

    if (character === "<" && script[index + 1] === "<") {
      let lookAhead = index + 2
      if (script[lookAhead] === "-") lookAhead += 1
      while (lookAhead < script.length && (script[lookAhead] === " " || script[lookAhead] === "\t")) lookAhead += 1
      let delim = ""
      let delimEnd = lookAhead
      if (script[lookAhead] === "'" || script[lookAhead] === '"') {
        const dq = script[lookAhead]
        delimEnd = lookAhead + 1
        while (delimEnd < script.length && script[delimEnd] !== dq) {
          delim += script[delimEnd]
          delimEnd += 1
        }
        delimEnd += 1
      } else {
        // A backslash-escaped delimiter (`<<\EOF`) is the quoted form: skip
        // the escape and read the bare word.
        if (script[delimEnd] === "\\") delimEnd += 1
        while (delimEnd < script.length && /\w/.test(script[delimEnd])) {
          delim += script[delimEnd]
          delimEnd += 1
        }
      }
      if (delim) {
        current += script.slice(index, delimEnd)
        commentView += script.slice(index, delimEnd)
        index = delimEnd - 1
        heredocDelim = delim
        wordStart = false
        continue
      }
    }

    if (character === ";" || character === "\n" || character === "\r") {
      commentView += character
      if (character === "\r" && script[index + 1] === "\n") {
        index += 1
        commentView += script[index]
      }
      push(character === ";" ? ";" : "newline")
      continue
    }
    if ((character === "&" || character === "|") && script[index + 1] === character) {
      index += 1
      commentView += character + character
      push(character === "&" ? "&&" : "||")
      continue
    }
    if (character === "&" && endsWithFdRedirectPrefix(current) && /^\d$/.test(script[index + 1] ?? "")) {
      eatWordChar(character)
      continue
    }
    if (character === "&" && script[index + 1] === ">") {
      eatWordChar(character)
      continue
    }
    if (character === "|" || character === "&") {
      commentView += character
      push(character as "|" | "&")
      continue
    }
    eatWordChar(character)
  }

  if (quote || escaped) return undefined
  if (heredocDelim !== undefined) {
    const lastLine = current.split("\n").at(-1)?.trim()
    if (lastLine !== heredocDelim) return undefined
  }
  push()
  return { segments, commentView }
}

function splitCommandSegments(script: string, shell: string) {
  return splitCommandSegmentsDetailed(script, shell)?.segments
}

/**
 * The script with every shell comment blanked to spaces (positions and
 * newlines preserved) for rule/path scans. Returns undefined when the script
 * cannot be fully lexed — callers keep the conservative raw text then.
 */
function commentNeutralizedView(script: string, shell: string): string | undefined {
  return splitCommandSegmentsDetailed(script, shell)?.commentView
}

export function splitSimpleSegments(script: string, shell: string) {
  return splitCommandSegments(script, shell)?.map((segment) => segment.text)
}

/**
 * Tracked working-directory base for a segment. `unverified` is set when the
 * base was produced by a `cd` whose success the connector does not guarantee:
 * `;`/newline run the next segment regardless, and `||`/`|`/`&` may skip or
 * subshell the `cd` entirely. Unverified bases may drive per-segment path
 * checks but must pass a canonical temp-root re-verification before they can
 * grant the temp cleanup exemptions.
 */
type SegmentBase = { dir: string | undefined; unverified: boolean }

const UNKNOWN_BASE: SegmentBase = { dir: undefined, unverified: true }

/**
 * Advances the tracked `cd` bases across one connector. Two tracks are kept:
 * `stable` is the directory the shell is in after unconditional (`;`/newline)
 * execution, while `cond` additionally follows `cd`s that ran conditionally
 * (`&&` chain position). `||`, `|`, `&` reset `cond` to `stable`: the `cd`
 * may have been skipped (`||`) or ran in a subshell (`|`, `&`) that cannot
 * move the shell's own cwd.
 */
function advanceSegmentBase(
  segment: CommandSegment,
  stable: SegmentBase,
  cond: SegmentBase,
  original: string,
): { stable: SegmentBase; cond: SegmentBase } {
  const incoming = segment.incoming
  const originalResolved = path.resolve(original)
  if (incoming === "||" || incoming === "|" || incoming === "&") {
    return { stable, cond: { dir: stable.dir, unverified: stable.unverified || stable.dir !== originalResolved } }
  }
  const unverified =
    cond.unverified ||
    ((incoming === ";" || incoming === "newline") &&
      cond.dir !== undefined &&
      cond.dir !== originalResolved)
  return { stable: { dir: cond.dir, unverified: cond.unverified }, cond: { dir: cond.dir, unverified } }
}

/**
 * Canonical-verifies a base that a `;`/`||`-style sequence claimed. The `cd`
 * may have failed (leaving the original cwd in force) or been skipped, so a
 * temp exemption may only ride the claim when the base itself canonically
 * lands inside a temp root. `/tmp` and `/var/tmp` are always recognized; the
 * session's trusted user-local temp roots (LOCALAPPDATA Temp) join them.
 */
async function baseInsideTempRoot(base: string, input: ClassifyShellCommandInput): Promise<boolean> {
  let canonical: string
  try {
    canonical = await realpath(base)
  } catch {
    return false
  }
  const tempRoots = ["/tmp", "/var/tmp", ...(await trustedUserLocalTempRoots(input))]
  for (const root of tempRoots) {
    let canonicalRoot: string
    try {
      canonicalRoot = await realpath(root)
    } catch {
      continue
    }
    if (isWithin(canonicalRoot, canonical)) return true
  }
  return false
}

/** Verdict used when an unverified `cd`-claimed base fails the temp-root
 * re-verification for a would-be temp cleanup exemption. */
function tempContextDeleteAsk(reason?: string): SegmentDecision {
  return {
    verdict: "ASK",
    rules: ["filesystem.temp-context-delete"],
    reason:
      reason ??
      "Deletion runs after a `cd` that is not guaranteed to have taken effect, and the claimed base is not a verified temp directory",
  }
}

async function unverifiedBasesAllInTemp(
  bases: string[],
  input: ClassifyShellCommandInput,
): Promise<boolean> {
  for (const base of bases) {
    if (!(await baseInsideTempRoot(base, input))) return false
  }
  return true
}

function normalizeCommandInSegment(segment: string): string {
  const callMatch = segment.match(/^&\s+(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+([\s\S]*))?$/)
  if (callMatch) {
    const exePath = callMatch[1] ?? callMatch[2] ?? callMatch[3] ?? ""
    const leaf = commandLeaf(exePath)
    const rest = callMatch[4] ?? ""
    return rest ? `${leaf} ${rest}` : leaf
  }
  const firstTokenMatch = segment.match(/^(\S+)/)
  if (firstTokenMatch) {
    const firstToken = firstTokenMatch[1]
    const leaf = commandLeaf(firstToken)
    return leaf + segment.slice(firstToken.length)
  }
  return segment
}

function isKnownSafeSegment(segment: string) {
  const value = normalizeCommandInSegment(
    stripTrailingFdMerges(segment)
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/, "")
      .trim(),
  )
  if (!value) return true
  const harmlessValue = value
    .replace(INERT_OUTPUT_REDIRECT, "")
    .replace(/<[ \t]*\/?dev\/(?:null|stdin)\b/gi, "")
    .replace(/(?:^|[\s;&|])<<</g, "")
    .replace(/(?:^|[\s;&|])\d*<[ \t]+[^\s<;&|()]+/g, "")
  if (/[<>](?![=])/.test(harmlessValue)) return false
  if (/^(?:true|false|:)\b/i.test(value)) return true
  // Duration literals only; the slow-command layer enforces the time budget.
  if (/^sleep\s+(?:\d+(?:\.\d+)?[smhd]?)(?:\s+\d+(?:\.\d+)?[smhd]?)*$/.test(value)) return true

  // Executor capability gate (fix C): an `rg`/`sed`/`git grep` form that runs
  // a child command is never known-safe on the strength of the outer leaf —
  // the child payload decides on the normal review path.
  if (executorCapabilityHazard(segment) !== undefined) return false

  if (
    /^(?:echo|printf|Write-Output|ls|dir|pwd|whoami|date|uname|hostname|df|du|free|ps|stat|file|head|tail|wc|sort|uniq|which|where|whereis|Get-ChildItem|Get-Location|Get-Content|Select-String|Test-Path|Resolve-Path)\b/i.test(
      value,
    )
  ) {
    return true
  }
  if (/^(?:tasklist|Get-Process|netstat|ss)\b/i.test(value)) return true
  // `command -v`/`-V` is a pure PATH lookup — never an execution. `hash`
  // with no arguments (or -l/-r session-cache listing/clearing) is inert.
  if (/^command\s+-[vV]\b/i.test(value)) return true
  if (/^hash\b/i.test(value)) return true
  if (/^docker\s+(?:ps|images)\b/i.test(value)) return true
  if (/^(?:Get-Command|Select-Object|Write-Host|findstr|iconv)\b/i.test(value)) return true
  if (/^base64\b/i.test(value) && !/\b(?:bash|sh|zsh|python|node|powershell|pwsh|eval)\b/i.test(value)) return true
  if (/^schtasks\b/i.test(value)) {
    return /\/Query\b/i.test(value) && !/\/(?:Create|Delete|Change|Run|End)\b/i.test(value)
  }
  if (/^wsl(?:\.exe)?\b/i.test(value)) {
    return /\s--(?:help|status|list|verbose)\b/i.test(value) && !/\s--(?:shutdown|terminate)\b/i.test(value)
  }
  if (/^(?:jq|diff)\b/i.test(value)) return true
  if (/^set\b/i.test(value)) {
    const tokens = value.split(/\s+/).slice(1)
    const safeOptions = new Set([
      "pipefail", "errexit", "nounset", "xtrace", "verbose",
      "noclobber", "ignoreeof", "allexport", "nolog", "privileged",
    ])
    if (tokens.every((t) => /^[-+][a-zA-Z]+$/.test(t) || safeOptions.has(t.toLowerCase()) || t === "--" || t === "-")) {
      return true
    }
  }
  if (/^(?:cat|type|more|less)\b/i.test(value)) {
    return !hasSensitiveCredentialReference(value) && !/\b(?:credential|token|secret|password|private)\b/i.test(value)
  }
  if (/^(?:rg|grep|Select-String)\b/i.test(value)) return true
  if (/^find\b/i.test(value)) return !/(?:^|\s)-(?:delete|exec|execdir|ok|okdir)(?:\s|$)/i.test(value)
  if (/^git\s+(?:status|diff|log|show|rev-parse|ls-files|grep|remote\s+-v|add|commit)\b/i.test(value)) return true
  if (/^git\s+(?:fetch|clone|checkout\s+-b|stash\s+(?:list|push)|branch\s+(?!-[dDm]\b)\S+|tag\s+(?!-[dD]\b)\S+|pull|switch|merge)\b/i.test(value)) return true
  if (/^git\s+push\b/i.test(value)) {
    // Semantic argv check (fix B): quoted/partially-quoted/ANSI flag and
    // refspec spellings resolve to the same policy, so `--fo"rce"`,
    // `'-'f`, `"+main"` and `"--force"` no longer slip past as known-safe.
    const argv = literalShellArgv(segment)
    if (!argv) return false
    const analysis = analyzeGitArgv(argv)
    if (!analysis || analysis.kind !== "push") return false
    return !analysis.dangerous
  }
  if (/^(?:mkdir|New-Item\s+[^\n]*-ItemType\s+Directory)\b/i.test(value)) return true
  if (/^(?:tar\s+-[a-z]*c[a-z]*f|zip\s+-r)\b/i.test(value)) return !/--remove-files\b/i.test(value)
  if (/^(?:cp|copy|Copy-Item)\b/i.test(value) && /[\s\S]*\s-[A-Za-z]/.test(value)) return false
  if (
    /^(?:(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?)\s+-m\s+pytest|pytest|bun\s+test|cargo\s+(?:test|check|fmt)|go\s+test|black|isort|prettier|eslint|tsc)\b/i.test(
      value,
    )
  ) {
    return true
  }
  if (
    /^(?:node\s+--test|npx\s+(?:--yes\s+)?(?:bun\s+test|vitest|jest|mocha|ava|tap|playwright\s+test|cypress\s+run)|vitest|jest|mocha|ava|tap|dotnet\s+test|mvnw?\s+test|gradlew?\s+test|ctest|make\s+test)\b/i.test(
      value,
    )
  ) {
    return true
  }
  if (/^(?:npm|pnpm|yarn|bun)\s+(?:test|run\s+(?:test|lint|format|check|build))\b/i.test(value)) return true
  if (/^(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|ci)\b/i.test(value)) return true
  if (/^(?:pip(?:3)?|pipx|uv)\s+(?:install|add|list|show|freeze|check)\b/i.test(value)) return true
  if (/^cargo\s+(?:add|fetch|update)\b/i.test(value)) return true
  if (/^go\s+(?:get|mod\s+download)\b/i.test(value)) return true
  if (/^dotnet\s+(?:restore|build)\b/i.test(value)) return true
  if (/^(?:cargo\s+build|go\s+build|cmake\s+--build|ninja|vite\s+build|next\s+build|nuxt\s+build|svelte-kit\s+build|webpack|rollup|esbuild|tsc)\b/i.test(value)) return true
  if (/^make\b/i.test(value) && !/\bclean\b/i.test(value)) return true
  if (/^(?:mvnw?|maven|gradlew?)\s+(?:build|package|compile|install|verify|assemble|bundle|jar|compileJava|deploy)\b/i.test(value) && !/\bclean\b/i.test(value)) return true

  // ===== M3 (P2) §4.9: false-positive reduction with P/E front-end =====
  // Text processing (read-only); `sed -i` write targets are validated by the path layer.
  if (/^(?:cut|column|tr|tac|nl|pr|fmt|fold|paste|join|comm|expand|shuf|strings|xxd|od|hexdump)\b/i.test(value)) return true
  // awk is only acceptable as a pure text filter; `system(` / `| getline` / `getline <`
  // primitives can execute commands or read files, so they force a review.
  if (/^awk\b(?![\s\S]*(?:system\s*\(|\|\s*getline|getline\s*<\s*))/i.test(value)) return true
  if (/^(?:md5sum|sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|basename|dirname|realpath|readlink|seq|expr)\b/i.test(value)) return true
  if (/^yq\b(?![\s\S]*-i\b)/i.test(value)) return true
  if (/^sed\b/i.test(value)) return true

  // Read-only system inspection
  if (/^(?:id|uptime|cal|type|lsattr|getfattr|lscpu|lsmod|lsusb|lspci|locale|getent|atq)\b/i.test(value)) return true
  if (/^(?:jobs|wait|bg|fg)\b/i.test(value)) return true
  if (/^history\s*(?:\d+)?\s*$/i.test(value)) return true
  if (/^alias\s*$/i.test(value)) return true
  if (/^lsof\b(?![\s\S]*\s-k\b)/i.test(value)) return true
  if (/^timedatectl\s+status\b/i.test(value)) return true
  if (/^ip\s+(?:addr|address|link|route)\b[\s\S]*\b(?:show|list)\b/i.test(value)) return true
  if (/^ip\s+(?:addr|address|link|route)\s*$/i.test(value)) return true
  if (/^ifconfig\b(?![\s\S]*(?:\s+up\b|\s+down\b|\s+add\b|\s+del\b|\s+remove\b))/i.test(value)) return true
  if (/^mount\s*(?:-l|l|--list)?\s*$/i.test(value)) return true
  if (/^crontab\s+-l\b/i.test(value)) return true
  if (/^fdisk\s+-[lL]\b/i.test(value)) return true
  if (/^parted\s+(?:--list|-l)\b/i.test(value)) return true
  if (/^parted\b(?![\s\S]*(?:mklabel|mkpart|mkpartfs|resizepart|mkswap|\srm\s|disk_set|disk_toggle))(?:-s\s+)?(?:\/dev\/\S+|-\S+)\s+print\b/i.test(value)) return true
  if (/^lsblk\b/i.test(value)) return true
  if (/^systemctl\s+(?:status|is-active|is-enabled|is-failed|list-units|list-unit-files|show|daemon-reload|cat|help)\b/i.test(value)) return true
  if (/^journalctl\b(?![\s\S]*--vacuum)/i.test(value)) return true
  if (/^ufw\s+status\b/i.test(value)) return true
  if (/^docker\s+(?:logs|inspect|top|events)\b/i.test(value)) return true
  if (/^docker\s+stats\s+--no-stream\b/i.test(value)) return true
  if (/^kubectl\s+(?:logs|top)\b/i.test(value)) return true
  // `kubectl get|describe` is read-only EXCEPT secret/secrets (credential material)
  if (/^kubectl\s+(?:get|describe)\b(?![\s\S]*\b(?:secret|secrets)\b)/i.test(value)) return true
  if (/^(?:test\b|\[)/.test(value)) return true

  // Package managers (declarative read / verify / safe uninstall / known run scripts)
  if (/^npm\s+run\s+(?:dev|start|serve)\b/i.test(value)) return true
  if (/^npm\s+run-script\s+(?:test|lint|format|check|build|dev|start|serve)\b/i.test(value)) return true
  if (/^npm\s+(?:start|list|ls|ll|la|lst|outdated|view|info|show|v|audit|search|s|se|find)\b/i.test(value)) return true
  if (/^npm\s+cache\s+verify\b/i.test(value)) return true
  if (/^npm\s+(?:uninstall|remove)\b/i.test(value)) return true
  if (/^(?:pip(?:3)?|pipx|uv)\s+uninstall\b/i.test(value)) return true
  if (/^(?:yarn|pnpm)\s+remove\b/i.test(value)) return true
  if (/^cargo\s+(?:clippy|tree|metadata|uninstall)\b/i.test(value)) return true
  if (/^go\s+(?:fmt|vet|list)\b/i.test(value)) return true
  if (/^npx\s+--no-install\s+(?:eslint|tsc|prettier|vitest|jest|mocha|bun\s+test)\b/i.test(value)) return true

  // git read-only / safe-mutating surface
  if (/^git\s+blame\b/i.test(value)) return true
  if (/^git\s+describe\b/i.test(value)) return true
  if (/^git\s+config\s+(?:--list|-l)\b/i.test(value)) return true
  if (/^git\s+stash\s+(?:push|pop|apply)\b/i.test(value)) return true
  if (/^git\s+tag\s*$/i.test(value)) return true
  if (/^git\s+branch\s+-d\b/.test(value)) return true
  if (/^git\s+branch\s*$/i.test(value)) return true
  if (/^node\s+(?:--version|-v\b|--help)\b/i.test(value)) return true
  if (/^(?:yarn|pnpm|bun)\s+(?:dev|start|serve|build|lint|format|check)\b/i.test(value)) return true
  if (/^poetry\s+(?:add|install|lock|update|export)\b/i.test(value)) return true
  if (/^uv\s+sync\b/i.test(value)) return true
  if (/^terraform\s+(?:plan|validate|fmt|version)\b/i.test(value)) return true
  if (/^(?:nslookup|dig)\b/i.test(value)) return true

  // File operations (write targets validated by the path layer)
  if (/^touch\b/i.test(value)) return true
  if (/^(?:cp|mv)\b(?![\s\S]*\s-[A-Za-z])\b/i.test(value)) return true
  if (/^install\s+-m\s+\d+\b/i.test(value)) return true
  // `rmdir` is the empty-directory remover on POSIX but a Remove-Item alias on
  // PowerShell/cmd: `-r/-recurse/-rf/-fr` and `/s` turn it into a forced
  // recursive delete. Only the plain empty-directory form is provably safe;
  // recursive forms must fall through to the destructive-delete rules.
  if (
    /^rmdir\b/i.test(value) &&
    !/-(?:recurse|rf|fr|\br\b)(?:\s|$)/i.test(value) &&
    !/(?:^|\s)[/\\][\s]*[sS](?=\s|$)/.test(value)
  ) {
    return true
  }

  // Build cleanup (disposable artifacts)
  if (/^make\s+(?:clean|distclean|mrproper)\b|^make\s*$/i.test(value)) return true
  if (/^(?:mvnw?|maven)\s+clean\b/i.test(value)) return true
  if (/^(?:\.?\/)?gradlew\s+clean\b/i.test(value)) return true

  // Scripts / interpreters (mode-agnostic safe surfaces)
  if (/^(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?)\s+-m\s+venv\b/i.test(value)) return true
  if (/^openssl\s+(?:genrsa|req|verify|x509|pkey|ecparam|genpkey|dhparam)\b/i.test(value)) return true
  if (/^gunzip\b|\bgzip\s+-d\b/i.test(value)) return true

  return false
}

function isKnownSafeCommand(script: string, shell: string) {
  if (/^git\s+add\b[^\n;&|]*&&\s*git\s+commit\b[^\n;&|]*$/i.test(stripLeadingDirectoryChanges(script))) return true
  const segments = splitSimpleSegments(script, shell)
  return Boolean(segments?.length && segments.every(isKnownSafeSegment))
}

function hasDynamicShellExpansion(text: string, shell: string) {
  if (/\$\(/.test(text)) return true
  return shellEscapeCharacter(shell) !== "`" && /`[^`\r\n]+`/.test(text)
}

// --- benign expansion vocabulary -------------------------------------------
// Exploration compounds like `cd X && echo "probe-$(date +%s)" && ls | head`
// are read-safe: every dynamic part resolves deterministically and locally.
// Only these inner commands qualify (literal args only): date/pwd/hostname/
// whoami/uname/basename/dirname (no state-setting operands) and echo/printf
// (literal output). Everything else — $(cat …), $(curl …), nested dynamic
// content, unknown variables — keeps the review path.
const BENIGN_SUB_LEAVES = new Set(["date", "pwd", "hostname", "whoami", "uname", "basename", "dirname", "echo", "printf"])
const BENIGN_VAR_RE = /\$(?:PWD|HOME|OLDPWD|USER|HOSTNAME|SHELL|[?$])|\$\{(?:PWD|HOME|OLDPWD|USER|HOSTNAME|SHELL)\}/g
/** Outer commands whose substitution output is printed text only. */
const BENIGN_OUTER_TEXT = new Set(["echo", "printf"])
/** Outer commands whose FIRST operand is a pattern (not a path): the benign
 *  sub may sit in pattern position but never as the final file operand. */
const BENIGN_OUTER_PATTERN = new Set(["grep", "rg", "egrep", "fgrep"])

function isBenignSubstitutionBody(body: string): boolean {
  // A single simple command only — `$(echo ok; rm -rf /)` is NOT benign.
  const pieces = splitSimpleSegments(body.trim(), "/bin/bash")
  if (!pieces || pieces.length !== 1) return false
  const tokens = simpleInvocationTokens(body.trim())
  const leaf = commandLeaf(tokens[0] ?? "")
  if (!leaf || !BENIGN_SUB_LEAVES.has(leaf)) return false
  const args = tokens.slice(1).map(stripMatchingQuotes)
  // `date -s`/`--set` writes the system clock; `hostname <name>` sets it.
  if (leaf === "date" && args.some((a) => /^--?s(?:et)?\b/i.test(a))) return false
  if ((leaf === "hostname" || leaf === "pwd" || leaf === "whoami") && args.some((a) => !a.startsWith("-"))) return false
  // Inside the body, only the safe variable set may appear (nested
  // substitutions and unknown expansions disqualify it).
  const cleaned = args.join(" ").replace(BENIGN_VAR_RE, "")
  if (/[$`]/.test(cleaned)) return false
  return true
}

/** True when every dynamic part of the segment is from the benign vocabulary:
 *  every $(…)/`…` substitution is a benign leaf and every surviving $VAR is in
 *  the safe set. `maskedOut` optionally returns the text with benign
 *  substitutions masked (used so path scans can still see the literal text
 *  around them — `cat ~/.ssh/$(date)` keeps its sensitive operand). */
function benignDynamicSurface(text: string, maskedOut?: { v: string }): boolean {
  const spans = substitutionSpans(text)
  let masked = "", end = 0
  for (const span of spans) {
    if (!isBenignSubstitutionBody(span.body)) return false
    masked += text.slice(end, span.start) + "x"
    end = span.end
  }
  masked += text.slice(end)
  // A benign sub's output must not be interpreted as a filesystem path:
  // `cat $(echo /etc/shadow)` would smuggle a read past the operand scan.
  // Allowed positions: echo/printf arguments (printed text) and grep/rg
  // pattern position (never the final operand, which names the file to read).
  if (spans.length) {
    const invocation = executableInvocation(masked)
    const leaf = invocation.leaf ?? ""
    if (BENIGN_OUTER_TEXT.has(leaf)) {
      // substitution output is printed text — always fine
    } else if (BENIGN_OUTER_PATTERN.has(leaf)) {
      const last = stripMatchingQuotes(invocation.args[invocation.args.length - 1] ?? "")
      if (!last || last.startsWith("-") || last === "x") return false
    } else {
      return false
    }
  }
  const residual = masked.replace(BENIGN_VAR_RE, "")
  if (/[$`]/.test(residual)) return false
  const hasDynamic = spans.length > 0 || /\$(?!\$)/.test(text)
  if (!hasDynamic) return false
  if (maskedOut) maskedOut.v = masked.replace(BENIGN_VAR_RE, "x")
  return true
}

function unwrapPowerShellCommand(script: string) {
  const value = stripLeadingDirectoryChanges(script)
  const invocation = value.match(/^(?:&\s*)?(?:powershell|pwsh)(?:\.exe)?\s+([\s\S]+)$/i)
  if (!invocation) return undefined

  const command = invocation[1].match(/^([\s\S]*?)-(?:command|c)\s+([\s\S]+)$/i)
  if (!command) return undefined

  const prefix = command[1].trim()
  const tokens = prefix.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
  const switchesWithoutValues = new Set(["-noprofile", "-noninteractive", "-nologo", "-sta", "-mta"])
  const switchesWithValues = new Set(["-executionpolicy", "-ep", "-windowstyle"])

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index].toLowerCase()
    if (switchesWithoutValues.has(token)) continue
    if (switchesWithValues.has(token) && tokens[index + 1]) {
      index += 1
      continue
    }
    return undefined
  }

  const payload = stripMatchingQuotes(command[2].trim()).trim()
  return payload || undefined
}

function recycleCommandInvocation(segment: string) {
  const match = segment
    .trim()
    .match(/^(?:&\s+)?(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+([\s\S]*))?$/)
  if (!match) return undefined

  const rawExecutable = match[1] ?? match[2] ?? match[3] ?? ""
  const executable = rawExecutable
    .replaceAll("\\", "/")
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase()
  if (!executable) return undefined
  return { executable, rawExecutable, args: (match[4] ?? "").trim() }
}

function hasPermanentTrashOperation(args: string) {
  return /(?:^|\s)(?:--?(?:empty|purge|delete)|\/(?:empty|purge)|empty|purge)(?:\s|$)/i.test(args)
}

function isPowerShellRecycleSetup(segment: string) {
  return /^add-type\s+-assemblyname\s+(?:"Microsoft\.VisualBasic"|'Microsoft\.VisualBasic'|Microsoft\.VisualBasic)\s*$/i.test(
    segment.trim(),
  )
}

function powerShellRecycleTarget(segment: string) {
  const value = segment.trim()
  const visualBasic = value.match(
    /^\[Microsoft\.VisualBasic\.FileIO\.FileSystem\]::Delete(?:File|Directory)\s*\(\s*(?:"[^"]*"|'[^']*'|\$[A-Za-z_][A-Za-z0-9_:]*)\s*,([\s\S]*)\)\s*$/i,
  )
  if (
    visualBasic &&
    /\bSendToRecycleBin\b/i.test(visualBasic[1]) &&
    /^[\s,'"\[\].:A-Za-z0-9_-]+$/.test(visualBasic[1])
  ) {
    return value.match(/Delete(?:File|Directory)\s*\(\s*("[^"]*"|'[^']*'|\$[A-Za-z_][A-Za-z0-9_:]*)/i)?.[1]
  }

  const shellTarget = value.match(
    /^\(\s*New-Object\s+-ComObject\s+Shell\.Application\s*\)\.Namespace\s*\(\s*(?:10|0xA)\s*\)\.MoveHere\s*\(\s*("[^"]*"|'[^']*'|\$[A-Za-z_][A-Za-z0-9_:]*)\s*(?:,\s*\d+\s*)?\)\s*$/i,
  )
  return shellTarget?.[1]
}

function recycleCliTargets(segment: string) {
  if (/[<>]/.test(segment) || /\$\(|`[^`\r\n]+`/.test(segment)) return false
  const invocation = recycleCommandInvocation(segment)
  if (!invocation) return false
  const { executable, rawExecutable, args } = invocation
  if (/[\\/]/.test(rawExecutable)) return undefined
  const tokens = simpleInvocationTokens(args)

  if (["trash", "recycle", "recycle-bin"].includes(executable)) {
    return hasPermanentTrashOperation(args) ? undefined : tokens.filter((token) => !token.startsWith("-"))
  }
  if (["trash-put", "gvfs-trash", "send2trash"].includes(executable)) {
    return tokens.filter((token) => !token.startsWith("-"))
  }
  if (executable === "gio" && /^trash\b/i.test(args) && !hasPermanentTrashOperation(args)) {
    return tokens.slice(1).filter((token) => !token.startsWith("-"))
  }
  if (/^kioclient(?:5|6)?$/.test(executable) && /^move\b[\s\S]+\strash:\/?\s*$/i.test(args)) {
    return tokens.length >= 3 ? [tokens[1]] : []
  }
  return undefined
}

function explicitRecycleBinOperation(script: string, shell: string) {
  const wrappedPowerShell = unwrapPowerShellCommand(script)
  const payload = wrappedPowerShell ?? script
  const payloadShell = wrappedPowerShell ? "powershell" : shell
  const segments = splitSimpleSegments(payload, payloadShell)
  if (!segments?.length) return undefined

  let recycleActions = 0
  const targets: string[] = []
  for (const segment of segments) {
    if (isPowerShellRecycleSetup(segment)) continue
    const powerShellTarget = powerShellRecycleTarget(segment)
    const cliTargets = recycleCliTargets(segment)
    if (powerShellTarget || cliTargets) {
      recycleActions += 1
      if (powerShellTarget) targets.push(powerShellTarget)
      if (cliTargets) targets.push(...cliTargets)
      continue
    }
    return undefined
  }
  return recycleActions > 0 && targets.length > 0 ? { targets } : undefined
}

function hasForbiddenRecycleDestruction(text: string) {
  if (/\bclear-recyclebin\b/i.test(text)) return true
  if (/\b(?:trash-empty|trash-rm)\b/i.test(text)) return true
  if (/\btrash\b[^\r\n;&|]*(?:--empty|--purge)\b/i.test(text)) return true
  if (/\bgio\s+trash\b[^\r\n;&|]*--empty\b/i.test(text)) return true
  return (
    hasDeletePrimitive(text) &&
    /(?:\$Recycle\.Bin(?:[\\/]|\b)|~[\\/]\.local[\\/]share[\\/]Trash[\\/]files(?:[\\/]|\b)|trash:\/\/)/i.test(text)
  )
}

function hasDataPathDestruction(text: string) {
  return (
    /(?:\b(?:shutil\.rmtree|os\.(?:remove|unlink))\b|\bfs(?:\.promises)?\.(?:rm|unlink)(?:Sync)?\s*\(|\brequire\s*\(\s*["'](?:node:)?fs["']\s*\)\.(?:rm|unlink)(?:Sync)?\s*\(|\.(?:rm|unlink)(?:Sync)?\s*\()/i.test(
      text,
    ) &&
    /(?:\/data\b|\/var\/data\b|\/project\b|\/production\b|\\data\\|\\project\\|\\production\\)/i.test(text)
  )
}

/** True only for a literal path that IS credential material: a file inside
 *  ~/.ssh, ~/.aws, ~/.gnupg (or those dirs themselves), an id_rsa/id_ed25519
 *  key, a .pem/.key/.p12/.gpg-style file, an authorized_keys/credentials/
 *  .env file. The pattern must match the TARGET itself — a `.ssh` substring
 *  in an unrelated token does not qualify. */
function isCredentialPathValue(target: string): boolean {
  const literal = literalPathToken(target)
  if (!literal) return false
  const norm = literal.replaceAll("\\", "/")
  const base = path.basename(norm.replace(/\/+$/, "")).toLowerCase()
  if (isCriticalOriginalPath(literal)) return true // .env / key exts / id_* / .ssh/.gnupg
  if (/^(?:\.aws|\.azure|\.kube)$/.test(base)) return true
  if (base === "credentials" || base === "config" || base === "authorized_keys" || base === "known_hosts") {
    if (/(?:^|\/)\.(?:ssh|aws|gnupg|azure|kube)(?:\/|$)/i.test(norm)) return true
  }
  if (CRITICAL_DATA_EXTENSION.test(base)) return true
  if (SENSITIVE_ENV_FILE.test("/" + base)) return true
  if (/^(?:id_(?:rsa|dsa|ecdsa|ed25519))/.test(base)) return true
  return false
}

/** Credential-like operands of the delete invocations in `text`: splits the
 *  surfaces into sub-commands and parses each rm/Remove-Item/find -delete /
 *  python delete call so only the real delete TARGETS are judged. A `.ssh`
 *  or `.aws` string in an echoed/grep'd token no longer counts — fixes the
 *  keyword false positive where deleting %TEMP% files while mentioning
 *  ".ssh" elsewhere in the command fired the credential-delete rule. */
function deleteTargetsInText(text: string, shell: string): string[] {
  const targets: string[] = []
  const deleteLeaves = new Set(["rm", "remove-item", "del", "erase", "unlink", "rmdir", "rd", "ri", "shred", "srm", "wipe"])
  const pieces = splitSimpleSegments(text, shell) ?? [text]
  for (const piece of pieces) {
    const trimmed = piece.trim()
    const invocation = executableInvocation(trimmed)
    const leaf = invocation.leaf ?? ""
    // Python / Node deletion APIs: os.remove("p"), shutil.rmtree("p").
    for (const match of trimmed.matchAll(/(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir|removedirs)|fs\.(?:rm|unlink|rmdir)(?:Sync)?)\s*\(\s*("[^"]*"|'[^']*'|[^,)]+)/gi)) {
      targets.push(match[1] ?? "")
    }
    if (!deleteLeaves.has(leaf)) {
      // `find <root> -delete` deletes what find traverses at <root>.
      if (leaf === "find" && /(?:^|\s)-delete(?:\s|$)/i.test(trimmed)) {
        const root = invocation.args.map(stripMatchingQuotes).find((a) => !a.startsWith("-"))
        if (root) targets.push(root)
      }
      continue
    }
    const rebuilt = invocation.tokens.slice(invocation.index).join(" ")
    const parsed = parseDeleteInvocation(rebuilt)
    if (parsed) targets.push(...parsed.targets)
  }
  return targets
}

function hasCriticalDataDestruction(text: string, shell = "/bin/bash") {
  if (!hasDeletePrimitive(text)) return false
  // Fire only when a delete TARGET itself is credential-like — keyword
  // co-occurrence anywhere in the command used to misfire.
  const targets = deleteTargetsInText(text, shell)
  return targets.some(isCredentialPathValue)
}

function hasGeneralDataDestruction(text: string) {
  if (!hasDeletePrimitive(text)) return false
  return GENERAL_DATA_EXTENSION.test(text) || hasDataPathDestruction(text)
}

function isCriticalDeletionTarget(target: string) {
  const literal = literalPathToken(target)
  return Boolean(literal && isCriticalOriginalPath(literal))
}

function isGeneralDataTarget(target: string) {
  const literal = literalPathToken(target)
  return Boolean(literal && GENERAL_DATA_EXTENSION.test(literal))
}

function hasDataDestruction(text: string) {
  if (!hasDeletePrimitive(text)) return false
  if (DATA_EXTENSION.test(text)) return true
  return hasDataPathDestruction(text)
}

function hasDestructiveOpenOverwrite(text: string) {
  const pattern = /\bopen\s*\([^)]*\)/gi
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    const call = match[0]
    if (!/\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(call)) continue
    if (/mode\s*=\s*["'][wax]/i.test(call)) return true
    if (/["'][wax][b+]*["']/.test(call)) return true
  }
  return false
}

function hasDestructiveOverwrite(text: string) {
  return (
    /\bsed\b[^\n]*(?:-i\b|--in-place\b)[^\n]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
    /\b(?:set-content|out-file)\b[^\n]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
    /\b(?:write_text|write_bytes)\s*\([^)]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
    hasDestructiveOpenOverwrite(text)
  )
}

/**
 * Blanks the interior of single- and double-quoted literals so raw text scans
 * (hasFileWritePrimitive, extractWriteTargets) only see write vocabulary that
 * actually reaches the shell — matching how bash parses the segment. Quoted
 * strings are DATA to read-class consumers (`echo "Set-Content x"`, `grep
 * "tee" file`); an unmatched quote keeps masking to end-of-segment, which is
 * also bash's behavior (the rest is literal). Quoted payloads that DO execute
 * (`bash -c "..."`, `pwsh -Command "..."`) are re-scanned separately via
 * extractQuotedWrappers, so this view is only for data surfaces.
 */
function maskQuotedLiteralContents(text: string): string {
  let out = ""
  let quote: "'" | '"' | undefined
  let escaped = false
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (escaped) {
        escaped = false
        out += ch
      } else if (ch === "\\") {
        escaped = true
        out += ch
      } else if (ch === quote) {
        quote = undefined
        out += ch
      } else {
        out += " "
      }
      continue
    }
    if (escaped) {
      escaped = false
      out += ch
      continue
    }
    if (ch === "\\") {
      escaped = true
      out += ch
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      out += ch
      continue
    }
    out += ch
  }
  return out
}

/** Output redirects that never reach a file: `>`/`>>`/`&>` (with an optional
 *  fd prefix) to /dev/null|stdout|stderr or PowerShell's $null/NUL. The
 *  non-exempted `>` family is what the write-shape scan keys on. */
const INERT_OUTPUT_REDIRECT =
  /(?:\d+|&)?>{1,2}\s*(?:\/dev\/(?:null|stdout|stderr)\b|\$null\b|\bNUL\b)/gi

function hasFileWritePrimitive(text: string): boolean {
  if (/\btee\b/i.test(text)) return true
  if (/\btouch\b/i.test(text)) return true
  if (/\bmkdir\b/i.test(text)) return true
  if (/\b(?:cp|copy|copy-item)\b/i.test(text)) return true
  if (/\b(?:mv|move|move-item|rename-item|ren)\b/i.test(text)) return true
  if (/\bsed\b[^\n]*-i\b/i.test(text)) return true
  if (/\b(?:set-content|out-file)\b/i.test(text)) return true
  if (/\bnew-item\b/i.test(text)) return true
  if (/open\s*\([^)]*['"][wax]/i.test(text)) return true
  if (/\.write_text\s*\(/i.test(text) || /\.write_bytes\s*\(/i.test(text)) return true
  if (/\b(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync)\s*\(/i.test(text)) return true
  if (/\bcreateWriteStream\s*\(/i.test(text)) return true
  const redirectCleaned = text
    .replace(INERT_OUTPUT_REDIRECT, "")
    .replace(/\d*>&\d+/g, "")
    .replace(/\d*>&-/g, "")
    // fd-to-fd duplication is not a write: >&1 >&2 >&- (and the 2>&1 / 2>&-
    // forms above) only merge or close descriptors.
    .replace(/>&(?=\s*[\d-])/g, "")
  if (/(?:^|[^=>])>(?![=>])/m.test(redirectCleaned)) return true
  return false
}

function hasLocalScriptReviewSignal(text: string): boolean {
  // Script content is matched raw: quote stripping is only safe for command text,
  // where extractQuotedWrappers re-surfaces quoted payloads; string literals inside
  // a script file have no such secondary surface, so stripping would hide payloads.
  if (SCRIPT_DESTRUCTIVE_PRIMITIVE.test(text)) return true
  if (hasFileWritePrimitive(text)) return true
  return false
}

function stripMatchingQuotes(value: string) {
  if (value.length < 2) return value
  const first = value[0]
  const last = value[value.length - 1]
  return (first === '"' || first === "'") && first === last ? value.slice(1, -1) : value
}

type DeletionTargetCandidate = { target: string; cwd: string }

function deletionTargetCandidates(script: string, shell: string, cwd: string) {
  const items: DeletionTargetCandidate[] = []
  const seen = new Set<string>()
  let truncated = false
  const surfaces = [script, ...extractQuotedWrappers(script)]

  const add = (target: string, base: string) => {
    const cleaned = stripMatchingQuotes(target)
    const key = `${path.resolve(base)}\0${cleaned}`
    if (seen.has(key)) return
    seen.add(key)
    if (items.length >= MAX_TARGET_DIRECTORIES) {
      truncated = true
      return
    }
    items.push({ target: cleaned, cwd: base })
  }

  for (const surface of surfaces) {
    const segments = splitCommandSegments(surface, shell) ?? [{ text: surface }]
    let stable: SegmentBase = { dir: path.resolve(cwd), unverified: false }
    let cond: SegmentBase = stable
    for (const item of segments) {
      ;({ stable, cond } = advanceSegmentBase(item, stable, cond, cwd))
      const segment = stripHarmlessPrefixes(item.text)
      const cd = parseCdSegment(segment)
      if (cd) {
        if (item.incoming !== "|" && item.incoming !== "&") {
          const resolvedDir = resolveCdBase(cd.dir, cond.dir)
          cond = { dir: resolvedDir, unverified: cond.unverified }
          if (item.incoming === undefined || item.incoming === ";" || item.incoming === "newline") stable = cond
        }
        continue
      }
      const base = cond.dir
      if (!base) continue
      const deletion = parseDeleteInvocation(segment)
      if (deletion?.parseable) {
        for (const target of deletion.targets) add(target, base)
      }
      const recycle = explicitRecycleBinOperation(segment, shell)
      if (recycle) {
        for (const target of recycle.targets) add(target, base)
      }
    }
  }
  return { items, truncated }
}

function referencedPathCandidates(script: string, shell: string) {
  const candidates = new Set<string>()
  let truncated = false
  const surfaces = [script, ...extractQuotedWrappers(script)]

  const add = (candidate: string) => {
    if (candidates.has(candidate)) return false
    if (candidates.size >= MAX_REFERENCED_PATHS) {
      truncated = true
      return true
    }
    candidates.add(candidate)
    return false
  }

  const consider = (rawToken: string) => {
    if (rawToken.startsWith("-") || /^\d*(?:>>?|<<?|&>)\S*/.test(rawToken)) return false
    const literal = literalPathToken(rawToken)
    if (!literal || /^(?:https?:|data:)/i.test(literal)) return false
    const normalizedPath = normalizeMsysPath(expandHome(literal))
    const looksLikePath =
      path.isAbsolute(normalizedPath) ||
      /^\.{1,2}[\\/]/.test(normalizedPath) ||
      normalizedPath.startsWith("~/") ||
      /[\\/]/.test(normalizedPath) ||
      /\.[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/.test(normalizedPath)
    return looksLikePath ? add(literal) : false
  }

  for (const surface of surfaces) {
    const segments = splitSimpleSegments(surface, shell) ?? [surface]
    for (const segment of segments) {
      const tokens = simpleInvocationTokens(segment)
      const start = tokens[0] && /[\\/]/.test(stripMatchingQuotes(tokens[0])) ? 0 : 1
      for (const rawToken of tokens.slice(start)) {
        if (consider(rawToken)) return { paths: [...candidates], truncated }
      }
      for (const match of segment.matchAll(/["']([^"'\r\n]+)["']/g)) {
        if (consider(match[1] ?? "")) return { paths: [...candidates], truncated }
      }
    }
  }
  return { paths: [...candidates], truncated }
}

function directoryEntryType(entry: Dirent) {
  if (entry.isDirectory()) return "directory" as const
  if (entry.isFile()) return "file" as const
  if (entry.isSymbolicLink()) return "symlink" as const
  return "other" as const
}

async function inspectTargetDirectory(candidate: string, cwd: string, worktree: string) {
  const expanded = expandHome(candidate)
  if (!expanded || /[*?[\]`$%]/.test(expanded)) return { uninspected: candidate }
  const absolute = path.isAbsolute(expanded) ? expanded : path.resolve(cwd, expanded)

  let canonical: string
  try {
    canonical = await realpath(absolute)
  } catch {
    return { uninspected: candidate }
  }
  if (!isWithin(worktree, canonical)) return { uninspected: candidate }

  let info
  try {
    info = await stat(canonical)
  } catch {
    return { uninspected: candidate }
  }
  if (!info.isDirectory()) return {}

  try {
    const all = await readdir(canonical, { withFileTypes: true })
    all.sort((left, right) => left.name.localeCompare(right.name))
    const entries = all.slice(0, MAX_DIRECTORY_ENTRIES).map((entry) => ({
      name: entry.name.slice(0, MAX_DIRECTORY_ENTRY_NAME_CHARS),
      type: directoryEntryType(entry),
    }))
    return {
      context: {
        path: path.relative(worktree, canonical).replaceAll("\\", "/") || ".",
        entries,
        truncated: all.length > entries.length,
      } satisfies TargetDirectoryReviewContext,
    }
  } catch {
    return { uninspected: candidate }
  }
}

function localScriptCandidates(script: string, shell: string) {
  const candidates = new Set<string>()
  const segments = splitSimpleSegments(script, shell) ?? [script]

  for (const segment of segments) {
    let tokens = simpleInvocationTokens(segment)
      .map(stripMatchingQuotes)
      .filter((token) => !/^\d*>&\d+$/.test(token))
    while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    if (["command", "sudo"].includes((tokens[0] ?? "").toLowerCase())) tokens = tokens.slice(1)
    if ((tokens[0] ?? "").toLowerCase() === "env") {
      tokens = tokens.slice(1)
      while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    }
    if ((tokens[0] ?? "").toLowerCase() === "wsl") {
      const separator = tokens.indexOf("--")
      tokens = separator >= 0 ? tokens.slice(separator + 1) : tokens.slice(1)
    }
    if (tokens.length === 0) continue

    const command = commandLeaf(tokens[0]) ?? ""
    let candidate: string | undefined
    if (["python", "python3", "py"].includes(command)) {
      for (let index = 1; index < tokens.length; index += 1) {
        const token = tokens[index]
        if (["-c", "-m", "-e"].includes(token.toLowerCase())) {
          candidate = undefined
          break
        }
        if (token.startsWith("-")) continue
        candidate = token
        break
      }
    } else if (["node", "bash", "sh", "zsh"].includes(command)) {
      if (command === "node" && tokens.slice(1).some((token) => token.toLowerCase() === "--test")) {
        candidate = undefined
        continue
      }
      for (let index = 1; index < tokens.length; index += 1) {
        const token = tokens[index]
        if (["-c", "-e"].includes(token.toLowerCase())) {
          candidate = undefined
          break
        }
        if (token.startsWith("-")) continue
        candidate = token
        break
      }
    } else if (["powershell", "pwsh"].includes(command)) {
      const fileIndex = tokens.findIndex((token) => token.toLowerCase() === "-file")
      if (fileIndex >= 0) candidate = tokens[fileIndex + 1]
    } else if (/^\.{1,2}[\\/]/.test(tokens[0])) {
      candidate = tokens[0]
    }

    if (!candidate || candidate.startsWith("-") || /^(?:https?:|data:)/i.test(candidate)) continue
    candidates.add(candidate)
    if (candidates.size >= MAX_LOCAL_SCRIPTS) return [...candidates]
  }
  return [...candidates]
}

async function fingerprintLocalScript(candidate: string, cwd: string, worktree: string) {
  if (isCriticalOriginalPath(candidate) || /(?:^|[\\/])\.env(?:\.|$)/i.test(candidate)) return undefined
  const expanded = expandHome(candidate)
  const absolute = path.isAbsolute(expanded) ? expanded : path.resolve(cwd, expanded)
  let canonical: string
  try {
    canonical = await realpath(absolute)
  } catch {
    return undefined
  }
  if (!isWithin(worktree, canonical)) return undefined

  const info = await stat(canonical)
  if (!info.isFile() || info.size > MAX_LOCAL_SCRIPT_BYTES) return undefined
  const content = await readFile(canonical)
  if (content.includes(0)) return undefined

  let linkPath: string | undefined
  let linkDev: number | undefined
  let linkIno: number | undefined
  let linkMtimeMs: number | undefined
  if (canonical !== absolute) {
    try {
      const linkInfo = await lstat(absolute)
      if (linkInfo.isSymbolicLink()) {
        linkPath = absolute
        linkDev = linkInfo.dev
        linkIno = linkInfo.ino
        linkMtimeMs = linkInfo.mtimeMs
      }
    } catch {
      return undefined
    }
  }

  return {
    content: content.toString("utf8"),
    reviewPath: path.relative(worktree, canonical).replaceAll("\\", "/") || path.basename(canonical),
    fingerprint: {
      path: canonical,
      size: info.size,
      mtimeMs: info.mtimeMs,
      sha256: createHash("sha256").update(content).digest("hex"),
      ...(linkPath !== undefined
        ? { linkPath, linkDev: linkDev as number, linkIno: linkIno as number, linkMtimeMs: linkMtimeMs as number }
        : {}),
    } satisfies ScriptFingerprint,
  }
}

export async function verifyScriptFingerprints(fingerprints: ScriptFingerprint[]) {
  for (const fingerprint of fingerprints) {
    if (fingerprint.linkPath !== undefined) {
      let linkInfo
      try {
        linkInfo = await lstat(fingerprint.linkPath)
      } catch {
        return false
      }
      if (!linkInfo.isSymbolicLink()) return false
      if (
        linkInfo.dev !== fingerprint.linkDev ||
        linkInfo.ino !== fingerprint.linkIno ||
        linkInfo.mtimeMs !== fingerprint.linkMtimeMs
      ) {
        return false
      }
      let canonical
      try {
        canonical = await realpath(fingerprint.linkPath)
      } catch {
        return false
      }
      if (canonical !== fingerprint.path) return false
    }
    let info
    let content
    try {
      info = await stat(fingerprint.path)
      content = await readFile(fingerprint.path)
    } catch {
      return false
    }
    if (!info.isFile() || info.size !== fingerprint.size || info.mtimeMs !== fingerprint.mtimeMs) return false
    if (createHash("sha256").update(content).digest("hex") !== fingerprint.sha256) return false
  }
  return true
}

type SegmentDecision = {
  verdict: SecurityVerdict
  rules: string[]
  reason: string
}

const MAX_WRAPPER_DEPTH = 4

function combineSegmentDecisions(results: SegmentDecision[]): SegmentDecision {
  const denied = results.find((result) => result.verdict === "DENY")
  if (denied) return denied
  const asks = results.filter((result) => result.verdict === "ASK")
  if (asks.length > 0) {
    return {
      verdict: "ASK",
      rules: [...new Set(asks.flatMap((result) => result.rules))],
      reason: asks[0].reason,
    }
  }
  return {
    verdict: "ALLOW",
    rules: [...new Set(results.flatMap((result) => result.rules))],
    reason: "All segments are recognized safe operations",
  }
}

async function classifyHardDeletionPolicy(
  segment: string,
  input: InternalClassifyInput,
): Promise<StaticSecurityDecision | undefined> {
  const ruleSurface = dataLiteralView(segment) ?? segment
  const surfaces = [
    ruleSurface,
    ...extractDecodedPayloads(ruleSurface, { executedOnly: true }),
    ...ruleScanWrappers(ruleSurface),
  ]
  // Heredoc bodies are masked consumer-aware: proven-inert bodies never reach
  // the forced-delete scan, while unquoted bodies (which expand `$()`/`…`
  // before the consumer reads them) stay visible. Language `-c`/`-e` payloads
  // reduce to their execution-sink view (payloadRuleView) — string literals
  // inside them are data, not commands.
  const combined = surfaces
    .flatMap((surface) => {
      const view = payloadRuleView(surface, input.shell)
      return [...view.segments, ...view.sinks]
    })
    .map((surface) => maskHeredocDataBodies(surface, input.shell))
    .join("\n\n")
  const bypassed = input.bypassedCategories

  // HARD-mode exemption for clearing recognized disposable directories inside
  // the working tree (node_modules, dist, .venv, .next, out, ... §4.9).
  if (
    input.cwd !== undefined &&
    input.worktree !== undefined &&
    await isDisposableDirectoryDelete(segment, input.cwd, input.worktree)
  ) {
    // The exemption may not ride a `cd` claim that is not guaranteed (`;` /
    // `||` chains): only a canonically temp-confined base qualifies.
    if (input.baseUnverified === true && !(await baseInsideTempRoot(input.cwd, input))) {
      return {
        verdict: "ASK",
        rules: ["filesystem.temp-context-delete"],
        reason:
          "Deletion runs after a `cd` that is not guaranteed to have taken effect, and the claimed base is not a verified temp directory",
        fingerprints: [],
      }
    }
    return {
      verdict: "ALLOW",
      rules: ["cleanup.disposable"],
      reason: "Forced deletion is limited to a recognized disposable directory inside the working tree",
      fingerprints: [],
    }
  }

  // An echo/printf of a delete-looking string is documentation, not deletion.
  // Trust that only for a bare output command with no extra decoded or wrapped
  // surfaces and no command substitution.
  const inertOutput =
    surfaces.length === 1 &&
    commandSubstitutionBodies(segment).length === 0 &&
    /^(?:echo|printf|write-output|write-host)\b/i.test(stripHarmlessPrefixes(segment).trim())

  if (hasForcedRecursiveDelete(combined) && !inertOutput && !ruleBypassed("hard.forced-recursive-delete", bypassed)) {
    // Path-aware floor (fix C): the textual `rm -rf` shape still denies, unless
    // every forced delete target across the surfaces is proven — against the
    // tracked cd/runtime-workdir base — to land inside a trusted temp root.
    // Absolute floors (`rm -rf /`, system roots, root globs) stay unconditional.
    if (!(await forcedDeletesConfinedToTemp(surfaces, input))) {
      return {
        verdict: "DENY",
        rules: ["hard.forced-recursive-delete"],
        reason: "Forced recursive deletion is blocked by filesystem policy because it can destroy an entire directory tree at once",
        fingerprints: [],
      }
    }
  }

  const roots = await trustedUserLocalTempRoots(input)
  for (const surface of surfaces) {
    const wrappedPowerShell = unwrapPowerShellCommand(surface)
    const payload = wrappedPowerShell ?? surface
    const payloadShell = wrappedPowerShell ? "powershell" : input.shell
    const segments = splitCommandSegments(payload, payloadShell)
    if (!segments) continue

    let stable: SegmentBase = { dir: path.resolve(input.cwd), unverified: input.baseUnverified === true }
    let cond: SegmentBase = stable
    for (const item of segments) {
      ;({ stable, cond } = advanceSegmentBase(item, stable, cond, input.cwd))
      const seg = item.text
      const cd = parseCdSegment(seg)
      if (cd) {
        if (item.incoming !== "|" && item.incoming !== "&") {
          const resolvedDir = resolveCdBase(cd.dir, cond.dir)
          cond = { dir: resolvedDir, unverified: cond.unverified }
          if (item.incoming === undefined || item.incoming === ";" || item.incoming === "newline") stable = cond
        }
        continue
      }
      const base = cond.dir

      const deletion = parseDeleteInvocation(seg)
      if (!deletion?.parseable || deletion.targets.length === 0) continue

      for (const target of deletion.targets) {
        const cleaned = stripMatchingQuotes(target)
        const pathFinding = classifyPathTarget(cleaned, "delete", {
          cwd: base ?? input.cwd,
          worktree: input.worktree,
          strictness: "HARD",
        })
        if (pathFinding.kind === "deny" && !ruleBypassed(pathFinding.rule, bypassed)) {
          return {
            verdict: "DENY",
            rules: [pathFinding.rule],
            reason: pathFinding.reason,
            fingerprints: [],
          }
        }
        if (hasNamedTempPathSegment(cleaned) && !ruleBypassed("hard.temp-target-delete", bypassed)) {
          return {
            verdict: "DENY",
            rules: ["hard.temp-target-delete"],
            reason: `Permanent deletion of temp/tmp targets is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
        const literal = literalPathToken(target)
        if (literal && backupPathIdentity(literal) && !ruleBypassed("hard.backup-target-delete", bypassed)) {
          return {
            verdict: "DENY",
            rules: ["hard.backup-target-delete"],
            reason: `Permanent deletion of backup targets is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
        if (
          base &&
          roots.length > 0 &&
          (await isTrustedTempPath(target, base, roots)) &&
          !ruleBypassed("hard.local-temp-delete", bypassed)
        ) {
          return {
            verdict: "DENY",
            rules: ["hard.local-temp-delete"],
            reason: `Permanent deletion inside the trusted Local Temp directory is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
      }
    }
  }
  return undefined
}

async function recycleTargetsFinding(
  targets: string[],
  base: string,
  input: ClassifyShellCommandInput,
  strictness: Strictness,
): Promise<SegmentDecision | undefined> {
  const ctx: PathContext = { cwd: base, worktree: input.worktree, strictness }
  const home = expandHome("~")
  const tempRoots = await trustedUserLocalTempRoots(input)
  for (const target of targets) {
    const literal = literalPathToken(target)
    if (!literal) {
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin-unverified"],
        reason: "The recycle-bin target is not a verifiable literal path",
      }
    }
    const decision = classifyPathTarget(literal, "delete", ctx)
    if (decision.kind !== "pass") {
      return {
        verdict: decision.kind === "deny" ? "DENY" : "ASK",
        rules: [decision.rule],
        reason: decision.reason,
      }
    }
    const resolved = resolveLexical(literal, base, home)
    const absolute = resolved.absolute
    if (!absolute) {
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin-unverified"],
        reason: "The recycle-bin target cannot be resolved to a concrete path",
      }
    }
    const inWorktree = isWithinLexical(input.worktree, absolute)
    const inTemp = tempRoots.some((root) => isWithinLexical(root, absolute))
    if (!inWorktree && !inTemp && !hasNamedTempPathSegment(literal)) {
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin-outside"],
        reason: "Moving a target outside the working tree to the recycle bin requires review",
      }
    }
  }
  return undefined
}

/** Heredoc language leaves whose bodies use `#` comments: the shell lexer's
 * quote-aware comment blanking (commentNeutralizedView) fits them directly.
 * `php` also accepts `//` comments — those simply stay visible, since comment
 * stripping may only ever narrow the rule surface. */
const HASH_COMMENT_LANGS = new Set([
  "python", "python3", "py", "perl", "ruby", "php", "lua", "rscript",
  "pwsh", "powershell",
])

/**
 * Comment-stripped view of a script-language body. `hash` reuses the shell
 * lexer (# comments, quote-aware, position-preserving); an unlexable body
 * returns the original text (fail closed). `slash` blanks `//` line comments
 * and slash-star block comments outside quotes; a confused lex (unterminated
 * quote or block comment) likewise leaves the text unmodified.
 */
function stripScriptComments(text: string, style: "hash" | "slash"): string {
  if (style === "hash") return commentNeutralizedView(text, "/bin/bash") ?? text
  let out = ""
  let quote: "'" | '"' | "`" | undefined
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (quote) {
      out += character
      if (character === "\\") {
        out += text[index + 1] ?? ""
        index += 1
      } else if (character === quote) {
        quote = undefined
      }
      continue
    }
    if (character === "/" && text[index + 1] === "/") {
      while (index < text.length && text[index] !== "\n") {
        out += " "
        index += 1
      }
      if (index < text.length) out += "\n"
      continue
    }
    if (character === "/" && text[index + 1] === "*") {
      let closed = false
      out += "  "
      index += 2
      while (index < text.length) {
        if (text[index] === "*" && text[index + 1] === "/") {
          out += "  "
          index += 2
          closed = true
          break
        }
        out += text[index] === "\n" ? "\n" : " "
        index += 1
      }
      if (!closed) return text
      continue
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character
      out += character
      continue
    }
    out += character
  }
  if (quote !== undefined) return text
  return out
}

/** Execution/file-mutation sinks whose ARGUMENTS the DEFINITE-destructive
 * shell-syntax rule scan may judge inside a language body; matched text
 * outside these calls (comments, plain string literals) is not executed. */
const LANG_SINK_PATTERN =
  /\b(?:os\.(?:system|popen|exec\w*|spawn\w*)|subprocess\.(?:Popen|call|run|check_output|check_call|getoutput|getstatusoutput)|child_process|(?:exec(?:Sync|File(?:Sync)?)?|spawn(?:Sync)?)\s*\(|system\s*\(|popen\s*\(|exec\s*\(|Process\.(?:start|builder)|shutil\.rmtree|os\.(?:remove|unlink|rmdir|removedirs)|fs(?:\.promises)?\.(?:rm|unlink|rmdir)(?:Sync)?|unlink\s*\(|File\.(?:delete|unlink)\s*\()/g

/** The sink call's argument block: text from `start` through the balanced
 * closing paren of its first `(`, parens counted quote-aware and capped. A
 * window that runs off the cap still open keeps its visible text (fail
 * closed); a match with no paren yields nothing. */
function sinkParenBlock(text: string, start: number): string | undefined {
  const limit = Math.min(text.length, start + 2000)
  let depth = 0
  let quote: string | undefined
  for (let index = start; index < limit; index += 1) {
    const character = text[index]
    if (quote) {
      if (character === "\\") index += 1
      else if (character === quote) quote = undefined
      continue
    }
    if (character === "'" || character === '"' || character === "`") {
      quote = character
      continue
    }
    if (character === "(") {
      depth += 1
      continue
    }
    if (character === ")" && depth > 0) {
      depth -= 1
      if (depth === 0) return text.slice(start, index + 1)
    }
  }
  return depth > 0 ? text.slice(start, limit) : undefined
}

/** A backtick execution block (perl/ruby/php): text through the matching
 * closing backtick, capped the same way. */
function sinkBacktickBlock(text: string, start: number): string {
  const limit = Math.min(text.length, start + 2000)
  for (let index = start + 1; index < limit; index += 1) {
    const character = text[index]
    if (character === "\\") index += 1
    else if (character === "`") return text.slice(start, index + 1)
  }
  return text.slice(start, limit)
}

/**
 * The only text from a language-heredoc body the DEFINITE-destructive rule
 * scan may judge: the comment-stripped body reduced to the argument blocks of
 * execution/file-mutation sink calls. SECURITY_SIGNAL_RULES are shell-syntax
 * regexes; applied to raw Python/JS they false-positively deny on `#`/`//`
 * comments and plain string literals that are never executed. Empty means "no
 * static hit": every lang body still pushes the unconditional
 * execution.local-script ASK, so nothing escapes review.
 */
function langDestructiveRuleView(body: string, leaf: string): string {
  const commentFree = stripScriptComments(body, HASH_COMMENT_LANGS.has(leaf) ? "hash" : "slash")
  const blocks: string[] = []
  for (const match of commentFree.matchAll(LANG_SINK_PATTERN)) {
    const block = sinkParenBlock(commentFree, match.index ?? 0)
    if (block) blocks.push(block)
  }
  // Backticks execute their content in perl/ruby/php; in node they only build
  // strings, so a JS template literal must stay out of the rule scan.
  if (leaf === "perl" || leaf === "ruby" || leaf === "php") {
    for (const match of commentFree.matchAll(/`/g)) {
      blocks.push(sinkBacktickBlock(commentFree, match.index ?? 0))
    }
  }
  return blocks.join("\n")
}

/** Interpreter leaves whose inline-code operand (`-c`, `-e`, `--eval`,
 *  `-r`, `deno eval`) carries a LANGUAGE payload, not shell text: shell-shaped
 *  words inside it (`rm -rf /` in a string literal, a comment) are program
 *  data and must not hit the shell-syntax rule scan. Only the sink-argument
 *  view (os.system/subprocess/fs.rm/…) may carry destructive signals, exactly
 *  like lang-heredoc bodies. */
const LANG_INLINE_LEAVES = new Set([
  "python", "python2", "python3", "py", "node", "deno", "bun",
  "ruby", "perl", "php", "lua", "luajit", "rscript",
])

/** Index in `argv` of the word carrying inline code for a language leaf,
 *  plus how many leading chars of that word are the flag itself (attached
 *  `-eCODE`/`--eval=CODE` forms). undefined when the invocation is not a
 *  recognizable inline-eval form (script file, `-m`, bare REPL, `--`
 *  operands, unknown flag layout) — the raw payload then stays scanned
 *  (fail closed). */
function langInlineCodeIndex(
  leaf: string,
  argv: string[],
): { index: number; flagChars: number } | undefined {
  for (let i = 1; i < argv.length; i += 1) {
    const token = argv[i] ?? ""
    if (token === "--") return undefined
    if (leaf === "deno") {
      if (token === "eval") return { index: i + 1, flagChars: 0 }
      if (["run", "test", "repl", "eval-file"].includes(token)) return undefined
    }
    if (leaf === "python" || leaf === "python2" || leaf === "python3" || leaf === "py") {
      if (token === "-c") return { index: i + 1, flagChars: 0 }
      if (token === "-m") return undefined
    } else if (leaf === "node" || leaf === "bun") {
      if (token === "-e" || token === "-p" || token === "--eval" || token === "--print") {
        return { index: i + 1, flagChars: 0 }
      }
      if (/^-(?:e|p)(?=\S)/.test(token)) return { index: i, flagChars: 2 }
      if (/^--(?:eval|print)=(?=\S)/.test(token)) {
        return { index: i, flagChars: token.indexOf("=") + 1 }
      }
    } else if (leaf === "ruby" || leaf === "perl") {
      if (token === "-e" || token === "--eval") return { index: i + 1, flagChars: 0 }
      if (/^--eval=/.test(token)) return { index: i, flagChars: token.indexOf("=") + 1 }
      if (/^-e(?=\S)/.test(token)) return { index: i, flagChars: 2 }
    } else if (leaf === "php") {
      if (token === "-r") return { index: i + 1, flagChars: 0 }
      if (/^-r(?=\S)/.test(token)) return { index: i, flagChars: 2 }
    } else if (leaf === "lua" || leaf === "luajit" || leaf === "rscript") {
      if (token === "-e") return { index: i + 1, flagChars: 0 }
      if (/^-e(?=\S)/.test(token)) return { index: i, flagChars: 2 }
    }
    if (token === "-") return undefined // stdin program
    if (token.startsWith("-") && token.length > 1) {
      // Unknown single-dash option: assume it consumes the next token, so a
      // flag value is never mistaken for the inline code (fail closed).
      const next = argv[i + 1]
      if (next !== undefined && !next.startsWith("-")) i += 1
      continue
    }
    return undefined // positional operand = script path
  }
  return undefined
}

/**
 * The DEFINITE-destructive rule-scan view of one surface: shell-shaped text
 * unchanged, but language-interpreter inline payloads are reduced to their
 * sink-argument blocks (`os.system(…)`, `fs.rmSync(…)`, `subprocess.run(…)`…)
 * and the code word is blanked in the surface itself. String/comment content
 * that merely LOOKS like a command (`python3 -c 'print("rm -rf /")'`,
 * `node -e 'require("fs").writeFileSync("x","rm -rf /")'`) is program data —
 * writing or storing a payload is judged by the write/path pipeline and the
 * unconditional execution.wrapper ASK, never by the shell floors. The
 * detected execution sinks inside the payload keep their full deny power.
 */
function payloadRuleView(text: string, shell: string): { segments: string[]; text: string; sinks: string[] } {
  const parsed = splitCommandSegmentsDetailed(text, shell)
  if (!parsed) return { segments: [text], text, sinks: [] }
  const out: string[] = []
  const connectors: string[] = [] // connector BETWEEN out[i-1] and out[i]
  const sinks: string[] = []
  for (const item of parsed.segments) {
    const piece = item.text
    connectors.push(
      item.incoming === "&&" ? " && "
      : item.incoming === "||" ? " || "
      : item.incoming === "|" ? " | "
      : item.incoming === "&" ? " & "
      : item.incoming === ";" ? "; "
      : "\n",
    )
    const trimmed = piece.trim()
    // Proven-inert quoted data (grep/rg patterns, `git commit -m` messages)
    // is message text, not a command — blank it exactly like the data-literal
    // rule view so a `nc -e /bin/sh` inside a commit message cannot trip the
    // floor scans. Anything not positively proven data stays raw.
    const dataMasked = dataLiteralView(trimmed) ?? trimmed
    // Output redirects are inert for the payload-code check but poison the
    // literal lexer; strip them first so `python3 -c '…' > log` still gets
    // its code word masked. Unparseable redirects keep the raw piece.
    const lexTarget = stripOutputRedirects(dataMasked) ?? dataMasked
    const argv = literalShellArgvDetailed(lexTarget)
    if (!argv) {
      out.push(dataMasked)
      continue
    }
    const resolved = resolveLiteralInvocation(argv.words)
    if (resolved === "unresolved" || argv.words.length === 0) {
      out.push(dataMasked)
      continue
    }
    const leaf = commandLeaf(argv.words[resolved.index] ?? "") ?? ""
    if (!LANG_INLINE_LEAVES.has(leaf)) {
      out.push(dataMasked)
      continue
    }
    const codeInfo = langInlineCodeIndex(leaf, argv.words.slice(resolved.index))
    const codeArgvIndex = codeInfo === undefined ? undefined : resolved.index + codeInfo.index
    const codeWord = codeArgvIndex === undefined ? undefined : argv.words[codeArgvIndex]
    if (codeWord === undefined) {
      out.push(piece)
      continue
    }
    const code = codeWord.slice(codeInfo!.flagChars)
    // Blank the proven-literal quoted fragments of the code word — those carry
    // the language payload text. Unquoted fragments stay (fail closed).
    // Spans are offsets into the lexed text (trimmed, redirects stripped);
    // mask that lexed form so the view stays consistent.
    const spans = argv.spans[codeArgvIndex] ?? []
    if (spans.length > 0) {
      const chars = lexTarget.split("")
      for (const span of spans) {
        for (let k = span.start; k < span.end && k < chars.length; k += 1) chars[k] = " "
      }
      out.push(chars.join(""))
    } else {
      out.push(piece)
    }
    const sinkText = langDestructiveRuleView(code, leaf).trim()
    if (sinkText && sinks.length < MAX_DECODED_PAYLOADS) sinks.push(sinkText)
  }
  // Re-join with the real connectors so pipe-spanned floors (literal-shell,
  // remote-pipe) still see `|`; the sink surfaces append as extra lines.
  let joined = ""
  for (let i = 0; i < out.length; i += 1) joined += (i > 0 ? connectors[i] : "") + out[i]
  return { segments: out, text: joined, sinks }
}

/** Any DEFINITE-destructive signal inside text: used to hard-deny code bodies
 * carried by heredocs (shell/remote/lang consumers) the same way the combined
 * scan denies them inline. */
function definiteDestructiveHit(text: string, bypassed: ReadonlySet<BypassCategory> | undefined): Rule | undefined {
  for (const rule of SECURITY_SIGNAL_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (!DEFINITE_DESTRUCTIVE_RULES.has(rule.id)) continue
    if (rule.test(text)) return rule
  }
  return undefined
}

/** Recognized inert heredoc writers whose write target is validated by the
 * path layer (`tee`, `dd of=…`, `sponge`, `cat`). */
function isInertHeredocWriter(part: string): boolean {
  const tokens = simpleInvocationTokens(part.trim())
  const leaf = commandLeaf(tokens[0] ?? "")
  if (leaf === "tee" || leaf === "sponge") {
    return tokens.slice(1).every((token) => !token.startsWith("-") || token === "-a" || token === "--append")
  }
  if (leaf === "dd") {
    return tokens.slice(1).every((token) => token.includes("=") || token.startsWith("-"))
  }
  return false
}

/**
 * Consumer-aware heredoc classification. Returns a decision when every
 * heredoc's consumer is recognized (data consumers → inert write check; code
 * consumers → recursive body classification plus the ASK floor for
 * interpreter-injection); undefined means "leave the segment to the normal
 * flow" (unknown consumers fail closed there, unmasked).
 */
async function classifyHeredocSegment(
  segment: string,
  base: string,
  input: InternalClassifyInput,
  depth: number,
): Promise<SegmentDecision | undefined> {
  const heredocs = parseHeredocs(segment)
  if (heredocs.length === 0) return undefined
  const strictness: Strictness = input.strictness ?? "LOOSE"
  const bypassed = input.bypassedCategories
  const m3ctx: PathContext = { cwd: base, worktree: input.worktree, strictness }
  const residual = heredocResidualText(segment, heredocs)
  const consumers = heredocs.map(heredocConsumer)
  const hasCode = consumers.some((consumer) => consumer !== "data" && consumer !== "unknown")
  const hasUnknown = consumers.some((consumer) => consumer === "unknown")

  // Under a read-only session a code-consumer heredoc executes its body —
  // deny the channel before the normal consumer review can defer to ASK.
  // Kernel-enforced LOOSE passes it through after the non-write gate: the
  // body's write syscalls are kernel-bound, while floors/credentials inside
  // the body still gate. HARD and kernel-absent RO keep the static deny.
  // Unknown consumers are equally unprovable under RO (they may execute the
  // body) — deny instead of letting an ASK reach the dynamic reviewer.
  if ((hasCode || hasUnknown) && input.permScope && !input.permScope.w) {
    if (input.roKernelEnforced && strictness !== "HARD") {
      return (await roNonWriteGate(segment, base, input, strictness)) ?? kernelEnforcedAllow()
    }
    return readOnlyExecutionDeny()
  }

  // An unknown consumer whose own output provably pipes into a KNOWN executor
  // (`sometool <<EOF | sh`) is a provable execution chain, not ambiguous
  // payload text: keep the body visible to the raw fall-through scans so the
  // DENY floor still applies.
  if (
    hasUnknown &&
    heredocs.some((h, i) => consumers[i] === "unknown" && heredocFlowsToKnownExecutor(h))
  ) {
    return undefined
  }

  // All-data consumers: the heredoc is a write surface only. The residual
  // pipeline parts must be provably inert (`cat`/`tee`/`dd`/redirections or
  // known-safe readers), unquoted bodies must carry no expansions, and the
  // write target still goes through the normal path checks.
  if (!hasCode && consumers.every((consumer) => consumer === "data")) {
    if (input.cwdUnknown) {
      if (input.permScope && !input.permScope.w) return undefined
      // Unknown base: the write target of a data-consumer heredoc cannot be
      // proven safe or unsafe — ambiguous payload goes to dynamic review.
      return {
        verdict: "ASK",
        rules: ["execution.ambiguous-heredoc"],
        reason:
          "The heredoc write target cannot be verified from the tracked working directory and requires review",
      }
    }
    const bodiesStatic = heredocs.every(
      (h) => h.quoted || !hasUnquotedExpansion(segment.slice(h.bodyRange.start, h.bodyRange.end), input.shell),
    )
    // Bodies that may carry live expansions (`$(cmd)`, backticks, `$VAR`)
    // are NOT mere payload text: an unquoted `$(rm -rf /)` provably runs at
    // heredoc-read time, so the raw fall-through scan must keep seeing them.
    if (!bodiesStatic) return undefined
    // The residual may still chain commands (`cat <<EOF; rm -rf /`), so it is
    // re-split and every piece must be a provably inert reader/writer.
    const residualParts = splitSimpleSegments(residual, input.shell) ?? [residual]
    const inert = residualParts
      .map((part) => part.trim())
      .filter(Boolean)
      .every((part) => {
        const strippedPart = stripOutputRedirects(part) ?? part
        return isKnownSafeSegment(strippedPart) || isInertHeredocWriter(strippedPart)
      })
    if (!inert) {
      if (input.permScope && !input.permScope.w) return undefined
      // Distinguish provable execution from mere ambiguity: a `; rm -rf /`
      // chained after the heredoc is a real command, and a body piped into a
      // KNOWN executor (`| sh`) is provably consumed as code — both keep the
      // raw fall-through scan (DENY path). Only a pipeline the static layer
      // cannot prove writes/stores vs executes (`| sometool`) defers to the
      // dynamic reviewer as ambiguous payload text.
      const provablyExecuted =
        definiteDestructiveHit(residual, bypassed) !== undefined ||
        heredocs.some((h) => heredocFlowsToKnownExecutor(h))
      if (provablyExecuted) return undefined
      return {
        verdict: "ASK",
        rules: ["execution.ambiguous-heredoc"],
        reason:
          "The heredoc pipeline cannot be proven to only write/store its body and requires review",
      }
    }
    const finding = analyzeSegmentPaths(residual, m3ctx)
    if (finding.kind === "pass") {
      return {
        verdict: "ALLOW",
        rules: ["operation.heredoc"],
        reason: "Writes recognized heredoc content to stdout or a working-tree file",
      }
    }
    // A heredoc file write whose target is canonically confined to a trusted
    // temp root gets the same "all targets confined" exemption (fix B). An
    // unverified base may only carry it when the base itself canonically sits
    // inside a temp root — otherwise the claimed confinement may be imaginary.
    const tempRoots =
      finding.kind === "ask" && (!input.baseUnverified || (await baseInsideTempRoot(base, input)))
        ? await trustedTempRoots(input)
        : []
    if (tempRoots.length > 0) {
      const confinement = await writeTargetsConfinedToTemp(residual, base, tempRoots, input.shell)
      if (confinement.confined && confinement.targets > 0) {
        return {
          verdict: "ALLOW",
          rules: ["cleanup.temp-confined"],
          reason: "Every write and deletion target is canonically confined to a trusted temp directory",
        }
      }
    }
    if (!ruleBypassed(finding.rule, bypassed)) {
      return {
        verdict: finding.kind === "deny" ? "DENY" : "ASK",
        rules: [finding.rule],
        reason: finding.reason,
      }
    }
    return undefined
  }

  const decisions: SegmentDecision[] = []
  const bodyInput: InternalClassifyInput = { ...input, cwd: base, baseUnverified: input.baseUnverified }

  for (const [index, h] of heredocs.entries()) {
    const consumer = consumers[index]
    const body = segment.slice(h.bodyRange.start, h.bodyRange.end)
    if (consumer === "shell" || consumer === "remote") {
      // The body is shell code (locally for `bash`, on the remote side for
      // `ssh`/container exec): classify it recursively like any other script.
      const hit = definiteDestructiveHit(body, bypassed)
      if (hit) decisions.push({ verdict: "DENY", rules: [hit.id], reason: hit.reason })
      else {
        const bodyDecision = await classifySegments(body, bodyInput, depth + 1)
        // Non-ALLOW body decisions carry: a privilege or review ASK inside
        // the body must not vanish behind the generic local-script ask.
        if (bodyDecision.verdict !== "ALLOW") decisions.push(bodyDecision)
      }
      decisions.push({
        verdict: "ASK",
        rules: ["execution.local-script"],
        reason:
          consumer === "remote"
            ? "The command pipes shell code into a remote execution context and requires review"
            : "The command pipes a shell script into an interpreter and requires contextual review",
      })
      continue
    }
    if (consumer === "lang") {
      // Rule scan on the sink-argument view only (FP fix): SECURITY_SIGNAL_RULES
      // are shell-syntax regexes; a raw Python/JS body denies on comments and
      // plain string literals that are never executed.
      const leaf = commandLeaf(heredocConsumerTokens(h)[0] ?? "") ?? ""
      const hit = definiteDestructiveHit(langDestructiveRuleView(body, leaf), bypassed)
      if (hit) decisions.push({ verdict: "DENY", rules: [hit.id], reason: hit.reason })
      else if (
        hasLocalScriptReviewSignal(body) &&
        !ruleBypassed("execution.local-script-signal", bypassed)
      ) {
        decisions.push({
          verdict: "ASK",
          rules: ["execution.local-script-signal"],
          reason: "The piped program contains a review-requiring primitive",
        })
      }
      decisions.push({
        verdict: "ASK",
        rules: ["execution.local-script"],
        reason: "The command pipes a program into a language interpreter and requires contextual review",
      })
      continue
    }
    if (consumer === "db") {
      if (DB_SHELL_ESCAPE.test(body)) {
        decisions.push({
          verdict: "ASK",
          rules: ["execution.db-shell-escape"],
          reason: "The piped database script contains a shell-escape primitive and requires review",
        })
      }
      decisions.push({
        verdict: "ASK",
        rules: ["execution.local-script"],
        reason: "The command pipes a script into a database shell and requires contextual review",
      })
      continue
    }
    // `data` consumers need no body scan here. An `unknown` consumer is the
    // ambiguity case: static analysis cannot prove whether the body is stored
    // as payload text or executed, so instead of letting the raw body hit the
    // floor scans as a hard DENY it defers to the dynamic reviewer (ASK).
    // Provably-executed forms keep their DENYs: shells/interpreters are
    // classified recursively above, and `cat <<EOF | sh`-style pipelines keep
    // the body visible to the full-script floor view (heredocFlowsToCode).
    if (consumer === "unknown") {
      decisions.push({
        verdict: "ASK",
        rules: ["execution.ambiguous-heredoc"],
        reason:
          "The heredoc consumer is unrecognized; the body may be stored data or executed code and requires review",
      })
      continue
    }
  }

  // The residual command still classifies normally (pipeline tails, file
  // arguments, redirects): `python3 script.py <<'EOF'` keeps its local-script
  // review, `ssh host <<'EOF'` keeps its network review.
  if (residual) decisions.push(await classifySegments(residual, bodyInput, depth + 1))
  return combineSegmentDecisions(decisions)
}

async function expandSafeReadGlobs(segment: string, input: InternalClassifyInput): Promise<string | undefined> {
  if (input.cwdUnknown || shellEscapeCharacter(input.shell) === "`") return undefined
  if (!/^(?:grep|rg|cat|head|tail|wc|ls)\s/.test(segment)) return undefined
  if (/["'`$\\;|&<>(){}\[\]\n]/.test(segment)) return undefined
  const tokens = segment.trim().split(/\s+/)
  const ctx: PathContext = { cwd: input.cwd, worktree: input.worktree, strictness: input.strictness ?? "LOOSE" }
  // Do not broaden command options (rg --pre can execute a program).
  const flags = /^(?:--|-[rnHhilcvswExq]+|-\d+|--line-number|--count|--files-with-matches)$/
  if (tokens.slice(1).some((token) => token.startsWith("-") && !flags.test(token))) return undefined
  if (!tokens.some((token) => /[*?]/.test(token))) return undefined
  const out: string[] = []
  let matchCount = 0
  for (const token of tokens) {
    if (!/[*?]/.test(token)) { out.push(token); continue }
    // A literal directory prefix avoids option injection from bare globs.
    if (!token.includes("/") || token.split("/").includes("..")) return undefined
    const dir = path.resolve(input.cwd, path.dirname(token))
    if (/[*?]/.test(dir) || !isWithin(input.worktree, dir)) return undefined
    try {
      if (await realpath(dir) !== dir) return undefined
      const pattern = path.basename(token)
      const regex = new RegExp("^" + [...pattern].map((ch) => ch === "*" ? ".*" : ch === "?" ? "." : ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("") + "$")
      const matches: string[] = []
      const handle = await opendir(dir)
      let seen = 0
      for await (const entry of handle) {
        if (++seen > MAX_DIRECTORY_ENTRIES) return undefined
        if (entry.name.startsWith(".") && !pattern.startsWith(".")) continue
        if (!regex.test(entry.name)) continue
        const absolute = path.join(dir, entry.name)
        if (!entry.isFile() || !/^[\w./-]+$/.test(absolute)) return undefined
        if (checkPathSensitivity(absolute, ctx).sensitive) return undefined
        if (classifyPathTarget(absolute, "read", ctx).kind !== "pass") return undefined
        if (++matchCount > MAX_REFERENCED_PATHS) return undefined
        matches.push(absolute)
      }
      if (!matches.length) return undefined
      out.push(...matches.sort())
    } catch { return undefined }
  }
  return out.join(" ")
}

// --- RO interop payload semantics -------------------------------------------
//
// Windows interop processes spawned through the WSL interop socket run outside
// the Linux LSM/sandbox reach, but a read-only session does not blanket-deny
// them: the payload is classified by what it actually does. Read-class
// payloads (Get-* cmdlets, `cmd.exe /c dir`, …) earn a static ALLOW under RO
// once every operand passes the same sensitive-path hygiene the native
// proven-read allow applies. Write-class payloads (Set-Content, Remove-Item,
// `>` redirects, .NET/python writers, the \\wsl$ reverse-write hole, …) are
// unconditional permission.write DENYs — RO means no mutation anywhere,
// including the Windows side. Spawn-class payloads (Start-Process, taskkill,
// interactive shells, script files, wsl.exe, rundll32, …) and opaque payloads
// (-EncodedCommand, unparseable statements) are ASK under LOOSE — the dynamic
// reviewer adjudicates them with its read-only advisory — and static DENYs
// under HARD.

type InteropClass = "read" | "write" | "spawn" | "opaque" | "ask"
type InteropResult = {
  kind: InteropClass
  /** Rule carried when the caller emits an ASK verdict. */
  rule?: string
  reason?: string
}

const INTEROP_EXECUTABLE_NAMES = new Set(["wsl", "wslpath", "pwsh", "powershell", "cmd"])
const INTEROP_EXECUTABLE_SUFFIX = /\.(?:exe|bat|cmd|ps1)$/i

/** Statement-text write vocabulary shared by PowerShell/cmd/generic-EXE
 *  payloads: the filesystem-mutating cmdlets and .NET writers. Bare
 *  single-word cmd verbs (del, mkdir, format, …) live in the leaf-level
 *  sets below so `Format-List`/`format:` labels cannot collide with them.
 *  Scans run on the quote-masked view so `"del x"` inside an echoed string
 *  stays data. */
const INTEROP_WRITE_RE =
  /\b(?:set-content|add-content|clear-content|new-item|remove-item|clear-item|clear-itemproperty|copy-item|copy-itemproperty|move-item|move-itemproperty|rename-item|rename-itemproperty|set-item|set-itemproperty|new-itemproperty|remove-itemproperty|out-file|tee-object|format-volume)\b|::(?:writeall|appendall|create|write|delete|move|copy|encrypt|decrypt)/i
/** Inline python payload write surface: open() for writing/appending, the
 *  os/shutil/pathlib delete+move calls, and file-object writes. Comparison
 *  `>` is python data, not a redirect — not matched here. */
const INTEROP_PY_WRITE_RE =
  /\b(?:os\.(?:remove|unlink|rmdir|removedirs|rename|replace|makedirs|mkdir|chmod|chown|truncate|fdopen)|io\.open|shutil\.(?:rmtree|move|copy|copyfile|copy2|copytree|chown|make_archive)|pathlib\.Path|tempfile\.|fileinput\.|pickle\.(?:dump|load)|csv\.writer)\b|\.(?:write|writelines|write_text|write_bytes|truncate)\s*\(|\bprint\s*\([^)]*file\s*=/i
/** Interpreter/process spawn vocabulary: a payload whose work is launching
 *  or re-entering an execution engine can never be proven read-only. */
const INTEROP_SPAWN_LEAVES = new Set([
  "start", "start-process", "saps", "invoke-item", "ii", "new-object",
  "invoke-command", "icm", "invoke-expression", "iex", "add-type",
  "stop-process", "kill", "spps", "taskkill", "stop-service",
  "suspend-service", "pause", "restart-computer", "stop-computer",
  "shutdown", "logoff", "rundll32", "mshta", "msiexec", "regsvr32",
  "cscript", "wscript", "wmic", "explorer", "wsl", "wslpath",
  "powershell", "pwsh", "cmd", "bash", "sh", "python", "python2",
  "python3", "py", "node", "perl", "ruby", "php", "start-job",
  "start-service", "set-service", "wait-process", "debug-process",
  "netsh", "diskpart", "diskshadow", "bitsadmin", "winget", "notepad",
  "calc", "call",
])
const INTEROP_PS_SPAWN_PREFIX = /^(?:start|stop|restart|suspend|resume)-/i

/** cmd.exe bare-leaf writes (kept leaf-level — see INTEROP_WRITE_RE). */
const INTEROP_WRITE_LEAVES = new Set([
  "mkdir", "md", "del", "erase", "rd", "rmdir", "ri", "rm", "ren", "rename",
  "copy", "xcopy", "robocopy", "move", "attrib", "mklink", "icacls", "cacls",
  "takeown", "cipher", "compact", "format", "setx", "fsutil", "subst",
])
/** cmd.exe / pwsh bare-leaf reads and PowerShell read aliases. */
const INTEROP_READ_LEAVES = new Set([
  // cross-shell read aliases (pwsh maps dir/ls/cat/type/echo/cd onto Get-*)
  "echo", "dir", "ls", "gci", "cat", "gc", "type", "pwd", "cd", "sl", "chdir",
  "where", "find", "findstr", "more", "ver", "whoami", "hostname", "systeminfo",
  "tasklist", "ipconfig", "netstat", "chcp", "prompt", "title", "cls", "clear",
  "clear-host", "exit", "timeout", "date", "time", "popd", "pushd",
  "set-location", "pop-location", "push-location", "driverquery",
  "nslookup", "ping", "tracert", "getmac", "defrag", "chkdsk",
  // pwsh alias leaves
  "gcm", "gm", "gv", "ghy", "h", "gl", "select", "sls",
  "measure", "sort", "group", "compare", "diff", "foreach", "foreach-object",
  "where-object", "%", "?",
])
/** Proven-read flag vocabulary for generic `.exe` read leaves: a flag not in
 *  this set keeps the invocation opaque (denied) rather than a proven read.
 *  `-s` is included for netstat -s; arp's mutating `-s`/`-d` are intercepted
 *  earlier by interopSubDispatch so they cannot ride this allow. */
const INTEROP_EXE_READ_FLAGS = new Set([
  "-a", "-g", "-n", "-v", "-r", "-o", "-b", "-e", "-f", "-p", "-t", "-s",
  "-4", "-6", "-l", "-w", "-i",
  "/all", "/v", "/fo", "/nh", "/fi", "/si", "/m", "/svc", "/u", "/s", "/r",
  "/query", "/verbose", "/list", "/?", "-h", "-l",
])

/** Read-only cmdlet verb prefixes (Get-*, Out-String, …). Writers named with
 *  these prefixes are already caught by INTEROP_WRITE_RE above.
 *  `import-` is excluded: Import-Module executes arbitrary .psm1 content.
 *  `compress-`/`expand-` are excluded: the Archive cmdlets write their target
 *  operand (dispatched to write in interopSubDispatch); any other member is
 *  opaque rather than a proven read. */
const INTEROP_PS_READ_PREFIX =
  /^(?:get|test|resolve|measure|select|where|sort|group|compare|format|out|write|convertto|convertfrom|convert|trace|debug|wait|receive|read|show|watch)-/i

/** `$(`, `${`, `$env:` or a `$variable` reference — but never the literal `$`
 *  that ends the `wsl$` share name. */
const INTEROP_DYNAMIC_OPERAND_RE = /\$(?:\(|\{|[A-Za-z_$:])/i

/** Order of severity for merging per-statement classes. Operand `ask`
 *  findings outrank `spawn` so the reason that reaches the user explains the
 *  sensitive target rather than the generic spawn. */
const INTEROP_CLASS_RANK: Record<InteropClass, number> = {
  read: 0,
  opaque: 1,
  ask: 2,
  spawn: 3,
  write: 4,
}

const INTEROP_SPAWN_REASON =
  "The interop payload launches a process, script, or interactive shell and requires review"
const INTEROP_OPAQUE_REASON =
  "The interop payload cannot be statically proven read-only and requires review"

function interopResult(kind: InteropClass, extra?: Partial<InteropResult>): InteropResult {
  return { kind, ...extra }
}

/** Masks single/double-quoted literal contents for the PowerShell dialect and
 *  double-quoted contents for cmd (cmd has no single-quote literals). Also
 *  blanks escaped pairs (backtick outside quotes, `^x` in cmd) so a backticked
 *  `>` never looks like a redirect. */
function maskInteropLiterals(text: string, dialect: "powershell" | "cmd"): string {
  let out = ""
  let quote: "'" | '"' | undefined
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (dialect === "powershell" && quote === '"' && ch === "`") {
        out += "  "
        i += 1
        continue
      }
      out += ch
      if (ch === quote) quote = undefined
      continue
    }
    if (dialect === "powershell" && ch === "`") {
      out += "  "
      i += 1
      continue
    }
    if (dialect === "cmd" && ch === "^") {
      out += "  "
      i += 1
      continue
    }
    if (ch === '"' || (dialect === "powershell" && ch === "'")) {
      quote = ch
      out += ch
      continue
    }
    out += ch
  }
  return out
}

/** Stronger variant used ONLY by the write-vocabulary scans: quoted literal
 *  *contents* are blanked, so `Write-Output "a > b"` and
 *  `Write-Host "Set-Content x"` scan as inert data instead of code. Delimiter
 *  quotes survive so statement splitting and leaf resolution are unaffected
 *  (they run on the unmasked stage). cmd has no single-quote literals —
 *  `del 'x'` still scans `del`. */
function maskInteropLiteralContents(text: string, dialect: "powershell" | "cmd"): string {
  let out = ""
  let quote: "'" | '"' | undefined
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (quote) {
      if (dialect === "powershell" && quote === '"' && ch === "`") {
        out += "  "
        i += 1
        continue
      }
      if (ch === quote) {
        quote = undefined
        out += ch
        continue
      }
      out += " "
      continue
    }
    if (dialect === "powershell" && ch === "`") {
      out += "  "
      i += 1
      continue
    }
    if (dialect === "cmd" && ch === "^") {
      out += "  "
      i += 1
      continue
    }
    if (ch === '"' || (dialect === "powershell" && ch === "'")) {
      quote = ch
      out += ch
      continue
    }
    out += ch
  }
  return out
}

/** Splits an interop payload into statements. PowerShell: `;`, newlines,
 *  `&&`/`||`, `{`/`}` (script-block contents classify too), and `|` between
 *  pipeline stages. cmd: `&`/`&&`/`|`/`||` — never the `&` inside `2>&1`. */
function splitInteropStatements(payload: string, dialect: "powershell" | "cmd"): string[] {
  const statements: string[] = []
  let current = ""
  let quote: "'" | '"' | undefined
  const push = () => {
    const text = current.trim()
    if (text) statements.push(text)
    current = ""
  }
  for (let i = 0; i < payload.length; i += 1) {
    const ch = payload[i]
    if (quote) {
      current += ch
      if (dialect === "powershell" && quote === '"' && ch === "`") {
        if (i + 1 < payload.length) current += payload[++i]
        continue
      }
      if (ch === quote) quote = undefined
      continue
    }
    if (dialect === "powershell" && ch === "`") {
      current += ch
      if (i + 1 < payload.length) current += payload[++i]
      continue
    }
    if (ch === '"' || (dialect === "powershell" && ch === "'")) {
      quote = ch
      current += ch
      continue
    }
    const next = payload[i + 1]
    if (ch === ";" || ch === "\n" || ch === "\r") {
      push()
      continue
    }
    if (dialect === "powershell" && (ch === "{" || ch === "}")) {
      push()
      continue
    }
    if (ch === "&" && next === "&") {
      push()
      i += 1
      continue
    }
    if (ch === "|" && next === "|") {
      push()
      i += 1
      continue
    }
    if (dialect === "powershell" && ch === "|") {
      push()
      continue
    }
    if (dialect === "cmd" && (ch === "&" || ch === "|")) {
      // `2>&1`: the & between a digit pair is fd duplication, not a separator.
      if (ch === "&" && /\d/.test(payload[i - 1] ?? "") && /\d/.test(next ?? "")) {
        current += ch
        continue
      }
      push()
      continue
    }
    current += ch
  }
  push()
  return statements
}

/** Maps `\\wsl$\<distro>\rest` / `\\wsl.localhost\<distro>\rest` (and the
 *  `//wsl$/` slash form) onto the WSL absolute path for the sensitivity scan. */
function interopUncToWslPath(operand: string): string | undefined {
  const match = operand.match(/^[/\\]{2}(?:wsl\$|wsl\.localhost)[/\\]([^/\\]+)[/\\]([\s\S]+)$/i)
  if (!match) return undefined
  return "/" + (match[2] ?? "").replaceAll("\\", "/")
}

/** Whether an operand spells an absolute-ish path worth sensitivity-checking
 *  (UNC, drive-letter, POSIX-absolute, or ~-rooted). */
function interopPathOperand(operand: string): boolean {
  return (
    operand.startsWith("/") ||
    operand.startsWith("\\") ||
    operand.startsWith("~") ||
    /^[A-Za-z]:/.test(operand)
  )
}

/** Operand hygiene for a proven-read interop statement: dynamic operands are
 *  unparseable (ASK), UNC WSL paths map to the native sensitivity scan,
 *  Windows paths match the credential-target registry, and plain
 *  POSIX-looking operands go through checkPathSensitivity. */
function interopReadOperandResult(
  tokens: string[],
  ctx: PathContext,
  dialect: "powershell" | "cmd",
): InteropResult | undefined {
  let finding: InteropResult | undefined
  const worse = (next: InteropResult) => {
    if (!finding || INTEROP_CLASS_RANK[next.kind] > INTEROP_CLASS_RANK[finding.kind]) finding = next
  }
  let optionsEnded = false
  for (const raw of tokens) {
    const operand = stripMatchingQuotes(raw)
    if (!optionsEnded) {
      if (operand === "--") {
        optionsEnded = true
        continue
      }
      if (operand.startsWith("-")) continue
      // cmd-style `/x` flags; UNC (`\\`) and POSIX (`/tmp`) operands are not flags.
      if (dialect === "cmd" && /^\/[^/\\]/.test(operand)) continue
    }
    if (INTEROP_DYNAMIC_OPERAND_RE.test(operand)) {
      return interopResult("ask", {
        rule: "execution.unparseable-path",
        reason: "The interop read operand contains dynamic expansion and cannot be proven safe",
      })
    }
    const wslMapped = interopUncToWslPath(operand)
    if (wslMapped !== undefined) {
      if (checkPathSensitivity(wslMapped, ctx).sensitive) {
        worse(
          interopResult("ask", {
            rule: "credentials.sensitive-access",
            reason: "The interop read targets credential or sensitive system data",
          }),
        )
      }
      continue
    }
    if (isCredentialPathValue(operand)) {
      worse(
        interopResult("ask", {
          rule: "credentials.sensitive-access",
          reason: "The interop read targets credential or key material",
        }),
      )
      continue
    }
    if (interopPathOperand(operand) && checkPathSensitivity(operand, ctx).sensitive) {
      worse(
        interopResult("ask", {
          rule: "credentials.sensitive-access",
          reason: "The interop read targets credential or sensitive system data",
        }),
      )
    }
  }
  return finding
}

/** cmd.exe sub-dispatch for commands whose subcommand decides the class
 *  (`reg add` writes, `reg query` reads; `sc start` spawns; …). */
function interopSubDispatch(
  leaf: string,
  args: string[],
  dialect: "powershell" | "cmd",
): InteropResult | undefined {
  const rest = args.map((arg) => stripMatchingQuotes(arg))
  const sub = (rest.find((arg) => !/^[-/]/.test(arg)) ?? "").toLowerCase()
  switch (leaf) {
    case "reg":
      if (sub === "query" || sub === "compare") return interopResult("read")
      if (["add", "delete", "copy", "import", "export", "save", "restore", "load", "unload"].includes(sub)) {
        return interopResult("write")
      }
      return interopResult("opaque")
    case "net":
      if (!sub) return interopResult("read") // bare `net` prints help
      if (["start", "stop", "pause", "continue"].includes(sub)) return interopResult("spawn")
      if (["user", "localgroup", "group", "accounts", "share", "use", "config", "computername", "session", "file", "print", "name", "send"].includes(sub)) {
        return interopResult("write")
      }
      if (["view", "statistics", "stats", "time", "help", "helpmsg"].includes(sub)) return interopResult("read")
      return interopResult("opaque")
    case "sc": {
      if (dialect === "powershell") return undefined // pwsh `sc` is Set-Content
      if (!sub) return interopResult("read")
      if (["start", "stop", "pause", "continue", "interrogate", "control"].includes(sub)) return interopResult("spawn")
      if (["config", "create", "delete", "description", "failure", "failureflag", "privs", "sdset", "sidtype", "triggerinfo", "preferrednode", "boot", "lock"].includes(sub)) {
        return interopResult("write")
      }
      if (["query", "queryex", "qc", "qdescription", "qfailure", "qtriggerinfo", "qprivs", "qsidtype", "qmanagedaccount", "qpreferrednode", "enumdepend", "getdisplayname", "getkeyname", "sdshow"].includes(sub)) {
        return interopResult("read")
      }
      return interopResult("opaque")
    }
    case "schtasks": {
      const lowered = args.map((arg) => stripMatchingQuotes(arg).toLowerCase())
      if (lowered.some((arg) => /^\/(create|delete|change|enable|disable)\b/.test(arg))) return interopResult("write")
      if (lowered.some((arg) => /^\/(run|end)\b/.test(arg))) return interopResult("spawn")
      if (!sub || lowered.some((arg) => arg.startsWith("/query"))) return interopResult("read")
      return interopResult("opaque")
    }
    case "route":
      if (["add", "delete", "change"].includes(sub)) return interopResult("write")
      return interopResult("read") // bare `route`/`route print` list the table
    case "assoc":
    case "ftype":
      return rest.some((arg) => arg.includes("=")) ? interopResult("write") : interopResult("read")
    case "set":
    case "path":
      if (dialect !== "cmd") return undefined // pwsh `set` isn't cmd set; opaque
      if (rest.length === 0) return interopResult("read") // bare listing
      if (rest[0] === "/p" || rest[0] === "/a") return interopResult("read")
      return interopResult("opaque") // `set x=y` mutates the cmd process env
    case "attrib":
      return interopResult("write") // any attrib invocation can set attributes
    case "powercfg":
      if (rest.some((arg) => /^\/(?:set|change|create|import|delete|hibernate|energy|batteryreport|sleepstudy|systempowerreport|requests|requestsoverride|powerthrottling|attributes)/i.test(arg))) {
        return interopResult("write")
      }
      return interopResult("read")
    case "gpresult":
      // `/h` and `/x` write an HTML/XML report file; everything else prints.
      if (rest.some((arg) => /^\/[hx]\b/i.test(arg))) return interopResult("write")
      return interopResult("read")
    case "arp":
      // `arp -s`/`arp -d` mutate the ARP table; `-a`/`-g`/`-v`/`-n` list it.
      if (rest.some((arg) => /^-[sd]$/i.test(arg))) return interopResult("write")
      return interopResult("read")
    case "compress-archive":
    case "expand-archive": {
      if (dialect !== "powershell") return undefined
      // Any target operand — positional, -Path/-LiteralPath, or
      // -DestinationPath — is a filesystem write; the bare cmdlet errors.
      const hasTarget = rest.some(
        (arg) => !arg.startsWith("-") || /^-(?:path|literalpath|destinationpath)$/i.test(arg),
      )
      return hasTarget ? interopResult("write") : interopResult("opaque")
    }
  }
  return undefined
}

/** Classifies a single interop statement (PowerShell or cmd dialect). */
function interopStageResult(stage: string, ctx: PathContext, dialect: "powershell" | "cmd"): InteropResult {
  // Redirects to a file are writes in both dialects; the contents mask keeps
  // quoted `>`/write-verbs inert (a print command's literal is data), and
  // hasFileWritePrimitive exempts fd duplication and $null.
  const masked = maskInteropLiteralContents(stage, dialect)
  if (hasFileWritePrimitive(masked)) return interopResult("write")
  if (INTEROP_WRITE_RE.test(masked)) return interopResult("write")

  const tokens = simpleInvocationTokens(stage.trim())
  if (tokens.length === 0) return interopResult("read")
  // PowerShell call/dot-source operators and grouping parens: unwrap one
  // layer (`& "pwsh" ...`, `(Get-Content x)`) and classify the inner call.
  let head = stripMatchingQuotes(tokens[0])
  if (dialect === "powershell") {
    if (head === "&" || head === "." || head === "(") {
      const inner = tokens.slice(1).join(" ")
      return inner ? interopStageResult(inner, ctx, dialect) : interopResult("opaque")
    }
    if (/^\$\(/.test(head)) return interopResult("opaque") // $(…) subexpression
    if (head === "%" || head === "?" || /^foreach\b/i.test(head)) {
      // ForEach/Where pipeline stage: the script-block body was already split
      // out and classified; the stage itself only maps/filters objects.
      return interopResult("read")
    }
    if (head === ")" || head === "{") return interopResult("read") // split artifacts
  }
  if (dialect === "cmd" && head === "@") head = stripMatchingQuotes(tokens[1] ?? "")
  const leaf = commandLeaf(head)
  const args = tokens.slice(1)

  const sub = leaf ? interopSubDispatch(leaf, args, dialect) : undefined
  if (sub) {
    if (sub.kind === "read") return interopReadOperandResult(args, ctx, dialect) ?? sub
    return sub
  }

  if (leaf && INTEROP_SPAWN_LEAVES.has(leaf)) {
    // Nested `cmd /c` / `powershell -Command` inside a payload re-classifies
    // the inner command text instead of blanket-spawning.
    if (leaf === "cmd") {
      const cIndex = args.findIndex((arg) => /^\/c$/i.test(stripMatchingQuotes(arg)))
      if (cIndex >= 0) {
        return interopPayloadResult(stripMatchingQuotes(args.slice(cIndex + 1).join(" ")), ctx, "cmd")
      }
    }
    if (leaf === "powershell" || leaf === "pwsh") {
      const cIndex = args.findIndex((arg) => /^-(?:command|c)$/i.test(stripMatchingQuotes(arg)))
      if (cIndex >= 0) {
        return interopPayloadResult(stripMatchingQuotes(args.slice(cIndex + 1).join(" ")), ctx, "powershell")
      }
    }
    return interopResult("spawn")
  }
  if (INTEROP_PS_SPAWN_PREFIX.test(leaf ?? "")) return interopResult("spawn")

  if (leaf && INTEROP_WRITE_LEAVES.has(leaf)) return interopResult("write")
  // pwsh write-verb alias at leaf level (the statement regex cannot see `sc`
  // as Set-Content without colliding with Format-*/format: strings).
  if (dialect === "powershell" && leaf === "sc") return interopResult("write")

  if (
    leaf &&
    (INTEROP_READ_LEAVES.has(leaf) ||
      (dialect === "powershell" && INTEROP_PS_READ_PREFIX.test(leaf)))
  ) {
    return interopReadOperandResult(args, ctx, dialect) ?? interopResult("read")
  }

  // .NET type literal: `[IO.File]::ReadAllText('x')` reads; the write-side
  // `::Write*/::Delete/…` methods were already caught by INTEROP_WRITE_RE.
  if (head.startsWith("[")) {
    return interopReadOperandResult(tokens.slice(1), ctx, dialect) ?? interopResult("read")
  }

  // Direct .ps1/.bat/.cmd/.exe invocation inside a payload is a spawn.
  if (INTEROP_EXECUTABLE_SUFFIX.test(head)) return interopResult("spawn")

  return interopResult("opaque")
}

/** Merges per-statement classes: any write wins, then spawn, then operand
 *  asks, then opaque; every statement read-class → read. */
function interopPayloadResult(
  payload: string,
  ctx: PathContext,
  dialect: "powershell" | "cmd",
): InteropResult {
  const statements = splitInteropStatements(payload, dialect)
  if (statements.length === 0) return interopResult("opaque")
  let merged = interopResult("read")
  for (const stage of statements) {
    const result = interopStageResult(stage, ctx, dialect)
    if (INTEROP_CLASS_RANK[result.kind] > INTEROP_CLASS_RANK[merged.kind]) merged = result
    if (merged.kind === "write") break
  }
  return merged
}

/** `pwsh[.exe]`/`powershell[.exe]` argument surface under RO. */
function interopPwshResult(args: string[], ctx: PathContext): InteropResult {
  let noExit = false
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    if (/^-noexit$/i.test(token)) {
      noExit = true
      continue
    }
    if (/^-(?:encodedcommand|enc|ec|e)$/i.test(token)) {
      const encoded = stripMatchingQuotes(args[i + 1] ?? "")
      if (!encoded) return interopResult("opaque")
      for (const decoded of decodePowerShellBase64(encoded)) {
        const inner = interopPayloadResult(decoded, ctx, "powershell")
        // A proven write inside the encoded blob still denies; anything else
        // stays opaque — the reviewer adjudicates decoded reads/mixes.
        if (inner.kind === "write") return inner
      }
      return interopResult("opaque")
    }
    if (/^-(?:command|c)$/i.test(token)) {
      const payload = stripMatchingQuotes(args.slice(i + 1).join(" ").trim())
      const inner = interopPayloadResult(payload, ctx, "powershell")
      // `-NoExit -Command <read>` leaves an interactive shell behind: the
      // payload stays spawn rather than a pure read.
      return noExit && inner.kind === "read" ? interopResult("spawn") : inner
    }
    if (/^-(?:file|f)$/i.test(token) || token === "-") {
      return interopResult("spawn") // script execution / stdin program
    }
  }
  // Bare pwsh (no command payload) is an interactive shell.
  return interopResult("spawn")
}

/** `cmd[.exe]` argument surface under RO: `/c` re-classifies the payload,
 *  `/k` and bare cmd stay spawn (a shell is left running). */
function interopCmdResult(args: string[], ctx: PathContext): InteropResult {
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    if (/^\/[ck]$/i.test(token)) {
      const payload = stripMatchingQuotes(args.slice(i + 1).join(" ").trim())
      const inner = interopPayloadResult(payload, ctx, "cmd")
      return /^\/k$/i.test(token) && inner.kind === "read" ? interopResult("spawn") : inner
    }
  }
  return interopResult("spawn")
}

/** `wsl[.exe]`/`wslpath`: proven writes inside the inner command still deny
 *  (closing the bash -c 'echo > /wsl/path' hole); every other surface stays
 *  spawn — wsl launches a Linux process Windows-side. */
function interopWslResult(args: string[], _ctx: PathContext): InteropResult {
  const valueFlags = new Set([
    "-d", "--distribution", "-u", "--user", "--cd", "--system", "--mount",
    "--manage", "-p", "--package",
  ])
  let inner: string | undefined
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    if (token === "--" || token === "--exec" || token === "-e") {
      inner = args.slice(i + 1).join(" ")
      break
    }
    if (valueFlags.has(token)) {
      i += 1
      continue
    }
    if (token.startsWith("-")) continue
    inner = args.slice(i).join(" ")
    break
  }
  if (inner?.trim()) {
    // The inner command is bash-shaped: scan its quote-masked view for
    // outer redirects (`bash -c x > out`) plus every quoted-executor payload
    // (mask inside again — `echo "a > b"` stays data) and decoded blobs.
    // Bare delete/move verbs at executable position are proven writes too —
    // the redirect scans above do not see `rm -f /home/x/f`.
    const surfaces = [inner, ...extractQuotedWrappers(inner), ...extractDecodedPayloads(inner)]
    for (const surface of surfaces) {
      const view = maskQuotedLiteralContents(maskHeredocDataBodies(surface, "/bin/bash"))
      if (
        hasFileWritePrimitive(view) ||
        extractWriteTargets(view).targets.length > 0 ||
        hasDeletePrimitive(view) ||
        parseDeleteInvocation(view) !== undefined ||
        parseMoveInvocation(view) !== undefined
      ) {
        return interopResult("write")
      }
    }
  }
  return interopResult("spawn")
}

/** Classify a python `-c` payload once for both the interop and the native
 *  RO gates: "write" for mutating calls, "read" for pure print/read inline
 *  code, "spawn" for everything unproven (import/subprocess/eval/unknown
 *  calls). The payload is a SINGLE argv element — shell suffixes like
 *  `2>&1`/`2>/dev/null` never reach it because the caller tokenizes after
 *  dropping inert redirects. */
function pyInlineClass(code: string): "write" | "read" | "spawn" {
  if (INTEROP_PY_WRITE_RE.test(code)) return "write"
  // open() for writing (the read-mode open("x") is a pure read).
  if (/\bopen\s*\([^)]*["'`]\s*[wax+]/i.test(code) || /\bopen\s*\([^)]*\bmode\s*=\s*["'`]\s*[wax+]/i.test(code)) {
    return "write"
  }
  if (hasDeletePrimitive(code)) return "write"
  if (/\b(?:subprocess|pty\.spawn|ctypes|eval|exec)\s*\(|\b__import__\s*\(|\bos\.(?:system|exec\w*|spawn\w*)\s*\(|\b(?:import|from)\s+\w+/i.test(code)) {
    return "spawn"
  }
  // Every call expression must be a recognized read/print builtin or
  // read-named method; an unknown call keeps the code unproven.
  let opaque = false
  for (const match of code.matchAll(/([A-Za-z_][\w.$]*)\s*\(/g)) {
    const leafName = (match[1] ?? "").split(".").pop() ?? ""
    if (
      !/^(?:print|len|str|int|float|bool|list|tuple|dict|set|repr|type|enumerate|zip|range|open|sorted|sum|min|max|abs|round|any|all|map|filter|input|ord|chr|hex|oct|bin|isinstance|issubclass|hasattr|getattr|vars|dir|id|hash|iter|next|slice|bytes|bytearray|frozenset|complex|help|read|readline|readlines|exists|isfile|isdir|islink|getsize|getmtime|getctime|getatime|abspath|basename|dirname|join|splitext|split|getcwd|listdir|scandir|glob|stat|environ|name|version|platform|count|index|find|replace|upper|lower|strip|startswith|endswith|keys|values|items|get|append|extend|match|search|findall|finditer|compile|loads|dumps|encode|decode|utcnow|now|today|Path|PathLike|re|json|math|datetime|date|timedelta)$/i.test(
        leafName,
      )
    ) {
      opaque = true
      break
    }
  }
  return opaque ? "spawn" : "read"
}

/** `python[.exe] -c <code>` under RO: pure print/read inline code allows,
 *  write-shaped calls deny, import/subprocess/eval stay unproven. `-m`,
 *  script files, and the bare REPL are spawn surfaces. */
function interopPythonResult(args: string[]): InteropResult {
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    if (token === "-c") {
      const code = stripMatchingQuotes(args[i + 1] ?? "")
      if (!code.trim()) return interopResult("spawn")
      const cls = pyInlineClass(code)
      return interopResult(cls === "spawn" ? "opaque" : cls)
    }
    if (token === "-m" || token === "-") return interopResult("spawn")
    if (/\.(?:py|bat|cmd|ps1)$/i.test(token)) return interopResult("spawn")
  }
  return interopResult("spawn") // bare python = interactive REPL
}

// --- JS inline payload analysis (node -e / node -p / deno eval) --------------

/** The `-e`/`--eval`/`-p`/`--print` payload of a `node`/`deno eval`
 *  invocation: exactly the token after the flag (script argv beyond it is
 *  process.argv, not code). Returns the code text or undefined when the
 *  invocation is not an inline-eval form. */
function jsInlineCode(leaf: string, args: string[]): string | undefined {
  const stripped = args.map(stripMatchingQuotes)
  if (leaf === "deno") {
    const evalIndex = stripped.findIndex((token) => token === "eval")
    if (evalIndex < 0) return undefined
    const code = stripped[evalIndex + 1]
    return code === undefined ? "" : code
  }
  for (let i = 0; i < stripped.length; i += 1) {
    const token = stripped[i] ?? ""
    if (token === "--") return undefined // operands after -- are script paths
    if (/^-(?:e|p)(?=\S)/.test(token)) return token.slice(2)
    if (/^--(?:eval|print)=(?=\S)/.test(token)) return token.slice(token.indexOf("=") + 1)
    if (token === "-e" || token === "-p" || token === "--eval" || token === "--print") {
      return stripped[i + 1] ?? ""
    }
    if (token.startsWith("-")) continue
    return undefined // a positional operand is a script file, not inline code
  }
  return undefined
}

/** Pure print/read JS payloads resolve statically: every identifier is a
 *  print sink or a known read builtin and every call expression names a
 *  safe leaf — no fs/net/process-spawn/require/import/eval/Buffer surface.
 *  Anything else stays unproven (ASK under RW, kernel- or static-gated
 *  under RO). */
function jsInlineReadOnly(code: string): boolean {
  const masked = maskQuotedLiteralContents(code)
  if (hasFileWritePrimitive(masked) || hasDeletePrimitive(masked)) return false
  // The recognized print sinks and pure-read process properties are masked
  // to benign names BEFORE the banned-identifier scan so process.stdout.write
  // and process.env survive while process.exit/kill/execPath stay banned.
  const scrubbed = masked
    .replace(/\bconsole\s*\.\s*(?:log|info|warn|error|debug|trace|dir|table|count|countReset|timeLog|timeEnd|group|groupEnd|assert)\b/g, "print")
    .replace(/\bprocess\s*\.\s*(?:stdout|stderr)\s*\.\s*write\b/g, "print")
    .replace(/\bprocess\s*\.\s*(?:env|argv|version|versions|platform|arch|pid|ppid|cwd|memoryUsage|uptime|hrtime|title|config|features|release|report)\b/g, "x")
    .replace(/\bprocess\s*\.\s*(?:cwd|memoryUsage|uptime|hrtime|getuid|getgid|geteuid|getegid|getgroups|availableMemory|constrainedMemory)\b/g, "x")
  if (
    /\b(?:require|import|eval|Function|Buffer|child_process|dgram|cluster|worker_threads|vm|fs|net|http|https|tls|dns|os|path|crypto|zlib|stream|readline|repl|inspector|async_hooks|perf_hooks|v8|tty|util|url|querystring|module|process|global|globalThis|setTimeout|setInterval|setImmediate|queueMicrotask|fetch|XMLHttpRequest|WebSocket|Deno|Bun|spawn|exec|execFile|fork|exit|kill|abort|umask|chdir|setuid|setgid|dlopen|ffi|syscall|ptr|open|unlink|rename|remove|mkdir|writeFile|write|appendFile|createWriteStream|openSync|writeFileSync|rm|rmSync|rmdir|rmdirSync|truncate|chmod|chown|chownSync|chmodSync|symlink|link|mkdtemp|utimes|openAsBlob)\b/i.test(
      scrubbed,
    )
  ) {
    return false
  }
  if (/\bawait\b/.test(scrubbed)) return false
  const SAFE_JS_CALL =
    /^(?:print|log|info|warn|error|debug|dir|table|trace|count|countReset|assert|timeLog|timeEnd|group|groupEnd|write|parse|stringify|keys|values|entries|fromEntries|assign|freeze|isFrozen|create|defineProperty|getOwnPropertyNames|getPrototypeOf|is|from|of|isArray|slice|concat|join|map|filter|reduce|forEach|find|findIndex|findLast|some|every|includes|indexOf|lastIndexOf|push|pop|shift|unshift|splice|sort|reverse|flat|flatMap|fill|copyWithin|at|with|toSorted|toReversed|toSpliced|toUpperCase|toLowerCase|trim|trimStart|trimEnd|padStart|padEnd|repeat|replace|replaceAll|split|startsWith|endsWith|substring|substr|charAt|charCodeAt|codePointAt|normalize|localeCompare|match|matchAll|search|test|exec|toFixed|toPrecision|toExponential|toString|toLocaleString|valueOf|toJSON|now|parse|getTime|getDate|getDay|getMonth|getFullYear|getHours|getMinutes|getSeconds|getMilliseconds|getTimezoneOffset|toISOString|toDateString|toTimeString|UTC|random|floor|ceil|round|trunc|abs|sign|sqrt|cbrt|pow|exp|log|log2|log10|sin|cos|tan|asin|acos|atan|atan2|min|max|hypot|PI|E|isNaN|isFinite|parseInt|parseFloat|Number|String|Boolean|Array|Object|Date|Math|JSON|Symbol|BigInt|Set|Map|WeakMap|WeakSet|Promise|RegExp|Error|TypeError|RangeError|SyntaxError|encodeURI|encodeURIComponent|decodeURI|decodeURIComponent|btoa|atob|structuredClone|isNaN|NaN|Infinity|print|x)$/i
  for (const match of scrubbed.matchAll(/([A-Za-z_$][\w.$]*)\s*\(/g)) {
    const leafName = (match[1] ?? "").split(".").pop() ?? ""
    if (!SAFE_JS_CALL.test(leafName)) return false
  }
  return true
}

/** Read-only interop gate: classifies the payload of an executable-position
 *  interop binary and maps the class onto the RO verdict ladder. Returns
 *  undefined when the segment's executable is not interop, leaving the
 *  caller on the normal RO path (local-script/unknown-executor denials). */
function readOnlyInteropDecision(
  segment: string,
  roView: string,
  input: InternalClassifyInput,
  strictness: Strictness,
): SegmentDecision | undefined {
  const invocation = executableInvocation(segment)
  if (invocation.unresolved) return undefined
  const rawExe = stripMatchingQuotes(invocation.tokens[invocation.index] ?? "")
  if (!rawExe) return undefined
  const leaf = commandLeaf(rawExe)
  const isInterop =
    INTEROP_EXECUTABLE_SUFFIX.test(rawExe) ||
    (leaf !== undefined && INTEROP_EXECUTABLE_NAMES.has(leaf))
  if (!isInterop) return undefined

  // HARD: blanket interop deny — any Windows-side execution is unproven
  // under the strictest mode, reads included. LOOSE keeps the payload
  // ladder below.
  if (strictness === "HARD") return readOnlyExecutionDeny()

  // Bash-level redirects outside the payload still write — `foo.exe > out`
  // is a write regardless of the exe's own semantics.
  if (hasFileWritePrimitive(roView)) return readOnlyWriteDeny()

  const ctx: PathContext = { cwd: input.cwd, worktree: input.worktree, strictness }
  let result: InteropResult
  if (leaf === "pwsh" || leaf === "powershell") {
    result = interopPwshResult(invocation.args, ctx)
  } else if (leaf === "cmd") {
    result = interopCmdResult(invocation.args, ctx)
  } else if (leaf === "wsl" || leaf === "wslpath") {
    result = interopWslResult(invocation.args, ctx)
  } else if (
    leaf &&
    ["python", "python2", "python3", "py"].includes(leaf) &&
    INTEROP_EXECUTABLE_SUFFIX.test(rawExe)
  ) {
    result = interopPythonResult(invocation.args)
  } else {
    // Generic .exe/.bat/.cmd/.ps1: a known read leaf (.exe suffix already
    // stripped into `leaf`) whose arguments are all proven-read flags or
    // plain operands earns a static read — `whoami.exe`, `tasklist.exe /v`,
    // `ipconfig.exe` stay cheap local allows. Unknown flags or an
    // unrecognized leaf stay opaque and deny below; scripts
    // (.bat/.cmd/.ps1) never qualify.
    result = interopStageResult([rawExe, ...invocation.args].join(" "), ctx, "cmd")
    if (result.kind === "read") {
      const flagsOk =
        /\.exe$/i.test(rawExe) &&
        leaf !== undefined &&
        INTEROP_READ_LEAVES.has(leaf) &&
        invocation.args.every((arg) => {
          const operand = stripMatchingQuotes(arg)
          return !operand.startsWith("-") && !operand.startsWith("/")
            ? true
            : INTEROP_EXE_READ_FLAGS.has(operand.toLowerCase())
        })
      if (!flagsOk) result = interopResult("opaque")
    }
  }
  if (invocation.hadPrivilegeLauncher && result.kind === "read") {
    result = interopResult("spawn")
  }

  switch (result.kind) {
    case "write":
      return readOnlyWriteDeny()
    case "read":
      return {
        verdict: "ALLOW",
        rules: ["operation.read-only"],
        reason: "The interop payload is a proven read-only invocation",
      }
    case "ask":
      return {
        verdict: "ASK",
        rules: [result.rule ?? "execution.interop"],
        reason: result.reason ?? INTEROP_OPAQUE_REASON,
      }
    case "spawn":
    case "opaque":
    default:
      // C1: unproven interop is a static deny in BOTH modes — the reviewer
      // is no longer load-bearing for interop kill decisions (fail_open
      // used to admit this whole surface on any outage). Interop is also
      // excluded from the kernel pass-through: Landlock cannot see
      // Windows-side effects.
      return readOnlyExecutionDeny()
  }
}

// --- RO mutating-invocation vocabulary --------------------------------------
//
// A read-only session forbids authorized filesystem mutation, not only the
// direct write/delete primitives. The predicate below recognizes invocations
// that mutate through the executable itself (package installs, builds, cleans,
// git worktree/index/ref changes, archive writes, system installers) or that
// execute project code whose side effects cannot be proven (test/task runners,
// formatters, interpreters, `find -exec`/`xargs` consumers).
//
// Matching is exact-name/exact-subcommand at executable position after the
// simple launchers (`sudo`, `doas`, `env`, `command`, `busybox`), never
// prefix-fuzzy: a literal "install" inside a quoted grep pattern is data, not
// a subcommand. The result is a reason kind, not a verdict — "write" and
// "unproven" are unconditional `permission.write` DENYs under RO, applied
// before every ordinary ALLOW/ASK producer, and category bypass never relaxes
// them (permissions outrank bypass). "read" marks a proven read-only surface
// (`git status`, `npm ls`, `make -n`, `unzip -l`, `zcat`): under RO it earns a
// static ALLOW once the segment passes the provably-safe hygiene checks and
// every non-flag operand classifies as a plain read path. `undefined` keeps
// the invocation on the normal classification path (known-safe reads, review
// signals, the unproven fallback).

type ExecutableInvocation = {
  /** Basename of the executable-position token (lowercased, suffix-stripped). */
  leaf: string | undefined
  /** Index of that token inside `tokens`. */
  index: number
  /** All invocation tokens (needed to re-join a payload after sudo/doas). */
  tokens: string[]
  /** Tokens after the executable token. */
  args: string[]
  /** A launcher chain could not be resolved to a command (`env -S`, …). */
  unresolved: boolean
  /** `sudo -e`/`--edit` edits a file as root; `sudo -i|-s`, `doas -s` spawn a
   *  root shell. */
  sudoMode: "edit" | "shell" | undefined
  /** sudo/doas appeared in the launcher chain. */
  hadPrivilegeLauncher: boolean
}

// sudo/doas options that consume the NEXT token as their value.
const SUDO_OPERAND_FLAGS = new Set([
  "-u", "-g", "-h", "-p", "-c", "-t", "-r", "-a",
  "--user", "--group", "--host", "--prompt", "--chdir", "--close-from",
  "--command-timeout", "--role", "--type", "--login-class", "--other-user",
])
const ENV_OPERAND_FLAGS = new Set(["-u", "--unset", "-c", "--chdir", "-a", "--argv0"])
const ENV_BOOL_FLAGS = new Set([
  "-i", "--ignore-environment", "-0", "--null", "-v", "--debug",
  "--block-signal", "--default-signal", "--ignore-signal", "--list-signal-handling",
])

/** Resolve the executable position behind the harmless launchers so
 *  `sudo rm`, `env FOO=1 cargo build`, `doas npm install`, `busybox sh -c x`
 *  reach the same vocabulary as the bare command. `command -v|-V` is a shell
 *  lookup, not an execution — it resolves to no executable. Unresolvable
 *  launcher chains (`env -S`, dangling operands) report `unresolved` so the
 *  RO gate can deny them as unproven execution. */
function executableInvocation(segment: string): ExecutableInvocation {
  const tokens = dropInertRedirectTokens(simpleInvocationTokens(segment.trim()))
  let index = 0
  let unresolved = false
  let sudoMode: "edit" | "shell" | undefined
  let hadPrivilegeLauncher = false
  // Leading shell variable assignments precede the command word.
  while (tokens[index] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index] ?? "")) index += 1

  for (let depth = 0; depth < 8; depth += 1) {
    const leaf = commandLeaf(tokens[index] ?? "")
    if (leaf === "command") {
      const next = tokens[index + 1]
      if (next === "-v" || next === "-V") {
        return { leaf: undefined, index, tokens, args: [], unresolved, sudoMode, hadPrivilegeLauncher }
      }
      index += 1
      continue
    }
    if (leaf === "sudo" || leaf === "doas") {
      hadPrivilegeLauncher = true
      index += 1
      while (index < tokens.length) {
        const token = tokens[index] ?? ""
        if (token === "--") {
          index += 1
          break
        }
        if (token === "-e" || token === "--edit") {
          if (leaf === "sudo") sudoMode = "edit"
          index += 1
          continue
        }
        if (token === "-i" || token === "-s" || token === "--login" || token === "--shell") {
          sudoMode = "shell"
          index += 1
          continue
        }
        if (SUDO_OPERAND_FLAGS.has(token.toLowerCase())) {
          index += 2
          continue
        }
        if (token.startsWith("-")) {
          index += 1
          continue
        }
        break
      }
      // sudo passes VAR=val environment assignments through to the command.
      while (tokens[index] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index] ?? "")) index += 1
      continue
    }
    if (leaf === "env") {
      index += 1
      while (index < tokens.length) {
        const token = tokens[index] ?? ""
        if (token === "--") {
          index += 1
          continue
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) {
          index += 1
          continue
        }
        if (ENV_OPERAND_FLAGS.has(token.toLowerCase())) {
          index += 2
          continue
        }
        // The split string IS the command line; the executable is unresolvable.
        if (token === "-S" || token === "--split-string" || token === "-P") {
          return { leaf: undefined, index, tokens, args: [], unresolved: true, sudoMode, hadPrivilegeLauncher }
        }
        if (ENV_BOOL_FLAGS.has(token.toLowerCase()) || token.startsWith("-")) {
          index += 1
          continue
        }
        break
      }
      continue
    }
    if (leaf === "busybox") {
      index += 1
      continue
    }
    const args = tokens.slice(index + 1)
    return { leaf, index, tokens, args, unresolved, sudoMode, hadPrivilegeLauncher }
  }
  return { leaf: undefined, index: tokens.length, tokens, args: [], unresolved: true, sudoMode, hadPrivilegeLauncher }
}

/** Leaves that cross a privilege or isolation boundary when they are the
 * command being run — mirrors sandbox.ts PRIVILEGE_COMMAND_WORDS minus the
 * kernel-module loaders, which keep their execution.kernel-module-load rule.
 * The account/identity tools match the router set so the static category
 * and the host-direct routing agree. */
const PRIVILEGE_BOUNDARY_LEAVES = new Set([
  "sudo",
  "sudoedit",
  "doas",
  "pkexec",
  "runas",
  "su",
  "chown",
  "chgrp",
  "setcap",
  "setfacl",
  "mount",
  "umount",
  "unshare",
  "nsenter",
  "chroot",
  "useradd",
  "usermod",
  "userdel",
  "passwd",
  "chpasswd",
  "visudo",
  "runuser",
  "setpriv",
  "capsh",
])

/** Wrapper leaves that execute a later operand: the operand is scanned as a
 * nested command surface (`eval "doas id"`, `xargs sudo chown …`, an
 * unquoted `sh -c` payload). */
const PRIVILEGE_WRAPPER_LEAVES = new Set(["sh", "bash", "zsh", "dash", "ksh", "eval", "exec", "xargs"])

/** True when a privilege-boundary word sits at command position in `text`:
 * the resolved executable of a sub-command is a boundary word, a sudo/doas
 * launcher prefixes it, a wrapper leaf executes it, or `find -exec` runs it.
 * Words inside plain arguments, quoted strings, or commit messages never
 * count. */
function hasPrivilegeBoundaryAtCommandPosition(text: string, shell: string, depth = 0): boolean {
  if (depth > 3) return false
  const pieces = splitSimpleSegments(text, shell) ?? [text]
  for (const piece of pieces) {
    const invocation = executableInvocation(piece.trim())
    if (invocation.hadPrivilegeLauncher) return true
    if (invocation.leaf && PRIVILEGE_BOUNDARY_LEAVES.has(invocation.leaf)) return true
    if (invocation.leaf && PRIVILEGE_WRAPPER_LEAVES.has(invocation.leaf)) {
      // The first non-flag operand is the command the wrapper runs.
      const operand = invocation.args.map(stripMatchingQuotes).find((token) => token && !token.startsWith("-"))
      if (operand && hasPrivilegeBoundaryAtCommandPosition(operand, shell, depth + 1)) return true
    }
    if (invocation.leaf === "find") {
      // `find … -exec/-execdir <cmd> …` runs <cmd> on every match.
      for (let i = 0; i + 1 < invocation.args.length; i += 1) {
        const flag = stripMatchingQuotes(invocation.args[i] ?? "")
        if (flag === "-exec" || flag === "-execdir") {
          const operand = commandLeaf(stripMatchingQuotes(invocation.args[i + 1] ?? ""))
          if (operand && PRIVILEGE_BOUNDARY_LEAVES.has(operand)) return true
          i += 1
        }
      }
    }
  }
  return false
}

/** Executable surfaces of a segment for the privilege-boundary scan: the
 * segment itself plus payloads that are themselves executed — quoted
 * `-c`/`/c`/`-command` wrapper payloads, decoded payloads, `$(…)`/backtick
 * command-substitution bodies, and heredoc bodies whose consumer runs them
 * as a script (`bash <<EOF`; an unknown consumer may shell out, so its body
 * stays in the scan fail-closed). Launcher words in plain arguments,
 * comments, or commit messages never count. */
function privilegeExecutableSurfaces(segment: string): string[] {
  const surfaces = [
    segment,
    // Language `-c`/`-e` payloads join as their sink-argument view: a `sudo`
    // inside `os.system("sudo …")` counts, one inside a stored string does not.
    ...ruleScanWrappers(segment),
    ...extractDecodedPayloads(segment, { executedOnly: true }),
    ...commandSubstitutionBodies(segment),
  ]
  for (const h of parseHeredocs(segment)) {
    const consumer = heredocConsumer(h)
    if (consumer === "shell" || consumer === "unknown") {
      surfaces.push(segment.slice(h.bodyRange.start, h.bodyRange.end))
    }
  }
  return surfaces
}

/** First non-flag operand and its index, skipping options that consume a
 *  value so `npm --prefix x install` still sees `install` as the subcommand. */
function roSubcommand(
  args: string[],
  valueFlags: ReadonlySet<string> = new Set(),
): { sub: string | undefined; index: number } {
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    if (token === "--") {
      if (i + 1 < args.length) {
        const next = stripMatchingQuotes(args[i + 1] ?? "")
        return { sub: next.toLowerCase(), index: i + 1 }
      }
      break
    }
    if (valueFlags.has(token) || valueFlags.has(token.toLowerCase())) {
      i += 1
      continue
    }
    if (token.startsWith("-")) continue
    return { sub: token.toLowerCase(), index: i }
  }
  return { sub: undefined, index: args.length }
}

const PM_VALUE_FLAGS = new Set([
  "-c", "-w", "-f", "-C",
  "--prefix", "--dir", "--cwd", "--cache", "--cache-dir", "--userconfig",
  "--globalconfig", "--registry", "--proxy", "--https-proxy", "--cafile",
  "--certfile", "--keyfile", "--workspace", "--filter", "--project",
])

// Git global options that consume the NEXT token as a value.
const GIT_VALUE_FLAGS = new Set([
  "-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env",
  "--exec-path", "--html-path", "--man-path", "--info-path",
])

/** Git subcommands that mutate the worktree, index, refs, or repository
 *  state. Inspection subcommands (status/diff/log/show/…) are absent and keep
 *  flowing to the normal classification path. `fetch` is included: it rewrites
 *  remote-tracking refs under .git (ls-remote is the read-only equivalent). */
const RO_GIT_MUTATORS = new Set([
  "add", "stage", "commit", "stash", "merge", "rebase", "reset", "revert",
  "cherry-pick", "checkout", "switch", "restore", "mv", "rm", "clean", "pull",
  "push", "fetch", "clone", "init", "gc", "prune", "pack-refs", "repack",
  "update-index", "update-ref", "read-tree", "write-tree", "checkout-index",
  "commit-tree", "mktree", "unpack-objects", "hash-object", "symbolic-ref",
  "apply", "am", "format-patch", "bisect", "notes", "replace", "rerere",
  "worktree", "submodule", "sparse-checkout", "filter-branch", "filter-repo",
  "instaweb", "maintenance", "bundle", "daemon", "receive-pack", "send-pack",
  "upload-archive", "shell", "imap-send", "for-each-repo", "p4", "svn",
])

/** npm install-family subcommands (mutate package.json / node_modules /
 *  config or publish state). Read surfaces (ls/view/audit/…) are absent. */
const NPM_WRITE_SUBS = new Set([
  "install", "i", "add", "ci", "install-ci-test", "install-test", "it",
  "update", "up", "upgrade", "uninstall", "un", "unlink", "remove", "rm", "r",
  "prune", "dedupe", "shrinkwrap", "pack", "publish", "unpublish", "deprecate",
  "login", "logout", "adduser", "version", "rebuild", "rb", "sbom", "link",
  "ln", "fund",
])
/** npm subcommands that execute project code: script runners, exec bridges,
 *  editors/subshells. */
const NPM_EXEC_SUBS = new Set([
  "run", "run-script", "start", "stop", "restart", "test", "t", "tst", "exec",
  "x", "init", "create", "explore", "edit", "npx",
])
/** npm subcommands that mutate config or registry state through a nested
 *  action word (`npm config set`, `npm pkg fix`, `npm access grant`, …). */
const NPM_STATE_SUBS = new Set([
  "config", "pkg", "access", "hook", "org", "team", "profile", "dist-tag",
  "token", "owner", "star", "stars", "unstar", "cache",
])
/** npm metadata/inspection subcommands that keep their existing checks. */
const NPM_READ_SUBS = new Set([
  // `npm list` aliases: ls, ll, la, lst. `npm view` aliases: info, show, v.
  // `npm search` aliases: s, se, find.
  "ls", "list", "ll", "la", "lst", "outdated", "view", "info", "show", "v",
  "whoami", "ping", "explain", "why", "help", "help-search", "search", "s",
  "se", "find", "doctor", "bin", "root", "prefix", "diff", "query",
  "docs", "repo", "bugs",
])

const PIP_READ_SUBS = new Set(["list", "show", "freeze", "check", "inspect", "help", "debug", "hash", "completion"])
const PIP_WRITE_SUBS = new Set(["install", "uninstall", "download", "wheel", "config", "cache", "index"])

const CARGO_READ_SUBS = new Set([
  "tree", "metadata", "search", "locate-project", "pkgid", "verify-project",
  "version", "list", "read-manifest", "help",
])
const CARGO_EXEC_SUBS = new Set([
  "run", "r", "test", "t", "bench", "watch", "script", "nextest", "expand",
])

const RO_DELETE_LEAVES = new Set([
  "rm", "remove-item", "del", "erase", "unlink", "rmdir", "rd", "ri",
  "shred", "srm", "wipe",
])

/** xargs options that consume the next token as a value. */
const XARGS_OPERAND_FLAGS = new Set([
  "-n", "--max-args", "-s", "--max-chars", "-p", "--max-procs", "-i", "-l",
  "--max-lines", "-d", "--delimiter", "-e", "--eof", "-a", "--arg-file",
  "--process-slot-var",
])

/** find primaries that consume a value operand (the NEXT token is data, not
 *  an action). Keeps `find . -name '-delete'` from matching the action scan.
 *  The -exec family is handled separately before this set is consulted. */
const FIND_VALUE_OPTS = new Set([
  "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex",
  "-iregex", "-lname", "-ilname", "-type", "-xtype", "-size", "-user", "-group",
  "-uid", "-gid", "-perm", "-newer", "-anewer", "-cnewer", "-mnewer", "-newermt",
  "-newerxy", "-amin", "-cmin", "-mmin", "-atime", "-ctime", "-mtime", "-used",
  "-context", "-samefile", "-inum", "-links", "-d", "-depth", "-maxdepth",
  "-mindepth", "-mount", "-xdev", "-daystart", "-follow", "-regextype",
  "-warn", "-nowarn", "-printf",
])
/** find primaries that write a file. */
const FIND_WRITE_ACTIONS = new Set(["-fls", "-fprint", "-fprint0", "-fprintf"])
const FIND_EXEC_ACTIONS = new Set(["-exec", "-execdir", "-ok", "-okdir"])

/** Executable leaves whose every form mutates the filesystem or installs or
 *  changes system/project state — denied as `permission.write` under RO even
 *  behind `sudo`/`env`/`doas`/`busybox`. */
const RO_WRITE_LEAVES = new Set([
  // package managers whose read surface is marginal; deny outright under RO
  "apt", "apt-get", "aptitude", "dnf", "yum", "zypper", "pacman", "yay", "paru",
  "apk", "snap", "flatpak", "brew", "port", "pkg", "pkgin", "emerge", "nix-env",
  "nix", "guix", "xbps-install", "xbps-remove", "opkg", "slackpkg", "slapt-get",
  "winget", "scoop", "choco", "chocolatey", "mas", "rpm", "dpkg", "dpkg-deb",
  "dpkg-reconfigure", "dpkg-divert", "update-alternatives", "alternatives",
  "gem", "bundle", "bundler", "composer", "poetry", "pipenv", "pdm", "rye",
  "hatch", "conda", "mamba", "micromamba", "corepack", "volta", "nvm", "asdf",
  "mise", "rbenv", "pyenv", "rustup", "goenv", "nodenv", "jenv", "sdk", "opam",
  "cabal", "stack", "luarocks", "pear", "pecl", "cpan", "cpanm", "mix",
  "rebar3", "npm-check-updates", "ncu", "helm",
  // archive writers
  "zip", "zipcloak", "zipnote", "zipsplit", "cpio", "jar", "ar", "rar", "unrar",
  "7z", "7za", "7zr", "zpaq", "dar", "lz4", "unlz4", "lzip", "lunzip", "plzip",
  "compress", "uncompress", "mkisofs", "genisoimage", "xorriso", "xorrisofs",
  "mksquashfs",
  // file creators / in-place modifiers not covered by hasFileWritePrimitive
  "truncate", "install", "mktemp", "mkfifo", "mknod", "ln", "patch", "sponge",
  "rename", "prename", "file-rename",
  // permission/attribute writers (chmod safe-mode has its own classifier; under
  // RO there is no permitted write at all)
  "chmod", "chown", "chgrp", "chattr", "setfacl", "setfattr", "setcap", "attr",
  // disk/filesystem/boot mutators
  "mkfs", "mke2fs", "mkdosfs", "mkntfs", "ntfsformat", "mkswap", "fdformat",
  "fsck", "e2fsck", "resize2fs", "tune2fs", "e2label", "badblocks", "debugfs",
  "wipefs", "sfdisk", "sgdisk", "gdisk", "cfdisk", "partprobe", "blockdev",
  "kpartx", "losetup", "dmsetup", "cryptsetup", "mdadm", "pvcreate", "pvremove",
  "pvresize", "pvmove", "pvchange", "vgcreate", "vgremove", "vgextend",
  "vgreduce", "vgchange", "vgrename", "lvcreate", "lvremove", "lvextend",
  "lvreduce", "lvresize", "lvrename", "lvchange", "lvconvert", "zpool", "zfs",
  "btrfs", "xfs_admin", "xfs_growfs", "xfs_repair", "xfs_db", "xfs_fsr",
  "mkinitcpio", "mkinitramfs", "update-initramfs", "dracut", "grub-install",
  "grub2-install", "grub-mkconfig", "grub2-mkconfig", "update-grub", "grubby",
  "efibootmgr", "efivar",
  // identity / account / service mutators
  "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod", "passwd",
  "chpasswd", "chsh", "chfn", "newusers", "vipw", "vigr", "chage", "pwconv",
  "grpconv", "service", "invoke-rc.d", "update-rc.d", "chkconfig", "telinit",
  "at", "batch", "atrm", "anacron",
  // object-file / binary modifiers and code generators
  "objcopy", "strip", "patchelf", "ranlib", "keytool", "jarsigner", "javac",
  "protoc", "swig", "doxygen", "sphinx-build", "flex", "bison", "yacc", "lex",
  "makeinfo", "gcc", "g++", "clang", "clang++", "cc", "c++", "rustc", "as", "ld",
  // credential / key material writers
  "mysqladmin", "htpasswd", "ssh-copy-id", "ssh-add", "kinit", "kdestroy",
  "kpasswd", "kadmin", "certbot", "gpgconf", "gpg-connect-agent", "certutil",
  // transfers that write local files by default
  "scp", "sftp", "wget2", "httrack", "yt-dlp",
])

/** Executable leaves that cannot be proven free of side effects: interpreters
 *  and shells, task/test runners, formatters/linters/compilers that execute
 *  project code, container/infra drivers, editors, and db shells. */
const RO_UNPROVEN_LEAVES = new Set([
  "sh", "bash", "zsh", "fish", "ksh", "dash", "csh", "tcsh", "eval", "exec",
  "builtin", "source", ".",
  "python", "python2", "python3", "py", "node", "deno", "perl", "ruby", "php",
  "lua", "luajit", "r", "rscript", "java", "javaws", "jshell", "groovy",
  "scala", "kotlin", "clojure", "clj", "erl", "elixir", "julia", "racket",
  "guile", "tclsh", "wish", "octave", "osascript", "expect",
  "npx", "bunx", "uvx", "pnpx", "dlx",
  "pytest", "vitest", "jest", "mocha", "ava", "tap", "playwright", "cypress",
  "ctest",
  "black", "isort", "prettier", "eslint", "stylelint", "biome", "rome",
  "standard", "tslint", "xo", "jshint", "shellcheck", "luacheck", "ruff",
  "flake8", "pylint", "mypy", "pyright", "bandit", "autopep8", "yapf", "blue",
  "gofmt", "gofumpt", "goimports", "golint", "staticcheck", "golangci-lint",
  "revive", "errcheck", "clang-format", "clang-tidy", "rustfmt", "stylua",
  "shfmt", "yamlfmt", "taplo", "dprint", "buf",
  "tsc", "esbuild", "webpack", "rollup", "vite", "next", "nuxt", "svelte-kit",
  "turbo", "nx", "lerna", "parcel", "swc", "tsup", "babel", "babel-node", "tsx",
  "ts-node", "jiti", "rspack", "rolldown", "unbuild", "wrangler", "vite-node",
  "ng", "ember", "astro", "remix", "snowpack", "zig",
  "ldd", "valgrind", "gdb", "lldb", "strace", "ltrace",
  "just", "task", "invoke", "nox", "tox", "doit", "snakemake", "nextflow",
  "rake", "thor", "fabric", "fab", "grunt", "gulp", "bazel", "buck", "buck2",
  "pants", "please", "sbt", "mill", "lein", "dune",
  "ansible", "ansible-playbook", "ansible-galaxy", "ansible-vault",
  "ansible-pull", "ansible-console", "ansible-config", "ansible-inventory",
  "terraform", "pulumi", "packer", "vagrant", "nomad", "consul", "vault",
  "kustomize", "k9s", "minikube", "kind", "skaffold", "tilt", "helmfile",
  "qemu", "virsh", "vboxmanage", "lima", "colima", "multipass",
  "watch", "parallel", "flock", "chroot", "unshare", "nsenter", "setpriv",
  "capsh", "runuser", "su", "sg", "newgrp", "pkexec", "systemd-run",
  "systemd-nspawn", "machinectl", "bwrap", "firejail", "nsjail", "ssh-agent",
  "script", "tmux", "screen", "zellij", "byobu",
  "vim", "nvim", "vi", "nano", "emacs", "emacsclient", "micro", "helix", "hx",
  "kak", "code", "codium", "subl", "gedit", "kate",
  "mysql", "mysqldump", "psql", "pg_dump", "pg_restore", "sqlite3", "redis-cli",
  "mongo", "mongosh", "influx", "clickhouse-client", "sqlcmd", "isql", "usql",
  "cqlsh", "duckdb", "litestream",
  "socat", "nc", "ncat", "netcat", "telnet", "ftp", "lftp", "ncftp", "mc",
])

/** True when the args of an `awk`/`gawk`/`mawk`/`yq` invocation request the
 *  gawk `inplace` extension or yq's `-i` in-place write — the only write
 *  surface inside the otherwise read-only text processors. */
function roInplaceProcessor(args: string[]): "write" | undefined {
  for (const raw of args) {
    const token = stripMatchingQuotes(raw)
    if (token === "-i" || token.toLowerCase() === "--inplace") return "write"
    if (/^-i[a-z]+$/i.test(token)) return "write" // gawk -iinplace
  }
  return undefined
}

/** `git -c key=value` / `--config-env=key=envvar` values can arm executable
 *  configuration: `alias.log='!id'` runs shell code for a read subcommand and
 *  `core.pager`/`sshCommand`-style keys spawn external programs on otherwise
 *  read-only operations. Such invocations stay unproven under RO. */
function roGitConfigExecKey(args: string[]): boolean {
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    let assignment: string | undefined
    if (token === "-c" || token === "--config-env") assignment = args[i + 1]
    else if (token.startsWith("-c")) assignment = token.slice(2)
    else if (token.startsWith("--config-env=")) assignment = token.slice("--config-env=".length)
    if (assignment === undefined) continue
    const key = stripMatchingQuotes(assignment).split("=", 1)[0]?.toLowerCase() ?? ""
    if (/^(?:alias\.|core\.(?:pager|editor|askpass|sshcommand|fsmonitor)|gpg\.(?:program|\S*program)$|\S*\.(?:cmd|command|program|helper)$)/.test(key)) {
      return true
    }
  }
  return false
}

function roGitKind(args: string[]): "write" | "unproven" | "read" | undefined {
  if (roGitConfigExecKey(args)) return "unproven"
  const { sub, index } = roSubcommand(args, GIT_VALUE_FLAGS)
  if (!sub) return "read" // bare `git` prints help
  const rest = args.slice(index + 1)
  if (RO_GIT_MUTATORS.has(sub)) return "write"
  // Read-only porcelain/plumbing keeps its existing checks.
  if (["status", "diff", "log", "show", "rev-parse", "rev-list", "ls-files", "ls-tree", "ls-remote", "grep", "blame", "annotate", "describe", "shortlog", "whatchanged", "var", "count-objects", "verify-tag", "verify-commit", "fsck", "cat-file", "check-ignore", "check-attr", "check-ref-format", "cherry", "range-diff", "merge-base", "name-rev", "show-ref", "show-branch", "stripspace", "for-each-ref", "diff-tree", "diff-index", "diff-files", "merge-file", "mktag", "pack-objects", "index-pack", "verify-pack", "show-index", "get-tar-commit-id", "interpret-trailers", "mailinfo", "mailsplit", "patch-id", "version", "help"].includes(sub)) {
    return "read"
  }
  if (sub === "lfs" || sub === "diagnose" || sub === "bugreport") return "write"
  if (sub === "branch" || sub === "tag") {
    // Listing forms have no operands; any operand mutates (create/delete/
    // rename). Flags are skipped — `git branch -d x` still lands on `x`.
    const operand = roSubcommand(rest).sub
    return operand ? "write" : "read"
  }
  if (sub === "reflog") {
    const operand = roSubcommand(rest).sub
    return operand === "expire" || operand === "delete" ? "write" : "read"
  }
  if (sub === "remote") {
    // `git remote`/`-v` lists; `add|remove|set-url|…` rewrites .git/config.
    const operand = roSubcommand(rest).sub
    return operand === undefined ? "read" : "write"
  }
  if (sub === "config") {
    const mutatingFlag = rest.some((raw) => {
      const token = stripMatchingQuotes(raw).toLowerCase()
      return (
        token === "--add" || token === "--unset" || token === "--unset-all" ||
        token === "--replace-all" || token === "--rename-section" ||
        token === "--remove-section" || token === "-e" || token === "--edit"
      )
    })
    if (mutatingFlag) return "write"
    const valueFlags = new Set(["-f", "--file", "--blob", "--default", "--type", "-t", "--value"])
    let operandCount = 0
    for (let i = 0; i < rest.length; i += 1) {
      const token = stripMatchingQuotes(rest[i] ?? "")
      if (token === "--") continue
      if (valueFlags.has(token.toLowerCase())) {
        i += 1
        continue
      }
      if (token.startsWith("-")) continue
      operandCount += 1
    }
    return operandCount >= 2 ? "write" : "read" // `config k v` sets; `config k` gets
  }
  return "unproven" // plumbing or unknown subcommand: execution unproven
}

/** `find` action recognition for the RO gate: `-delete`, file-writing
 *  primaries (-fprint/-fls/-fprintf), and the `-exec`/`execdir`/`-ok`/`-okdir`
 *  consumers. A delete consumer is a write; any other (or an unresolvable)
 *  consumer is unproven execution. Both `\;` and `+` terminators end the
 *  consumer payload. */
function roFindKind(args: string[]): "write" | "unproven" | "read" | undefined {
  for (let i = 0; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    const lower = token.toLowerCase()
    if (lower === "-delete") return "write"
    if (FIND_WRITE_ACTIONS.has(lower)) return "write"
    if (FIND_EXEC_ACTIONS.has(lower)) {
      const consumer: string[] = []
      for (let j = i + 1; j < args.length; j += 1) {
        const c = stripMatchingQuotes(args[j] ?? "")
        if (c === "\\;" || c === ";" || c === "+") break
        consumer.push(args[j] ?? "")
      }
      const invocation = executableInvocation(consumer.join(" "))
      if (!invocation.leaf || invocation.unresolved) return "unproven"
      if (RO_DELETE_LEAVES.has(invocation.leaf)) return "write"
      return "unproven"
    }
    if (FIND_VALUE_OPTS.has(lower)) {
      i += 1
      continue
    }
  }
  return "read" // pure search: no write/exec primaries found
}

/** `xargs` consumer recognition: the consumer command follows the options.
 *  A delete consumer is a write; every other consumer — including a missing
 *  one — is unproven execution (xargs exists to run commands). */
function roXargsKind(args: string[]): "write" | "unproven" | undefined {
  let i = 0
  let consumerStart = -1
  for (; i < args.length; i += 1) {
    const token = stripMatchingQuotes(args[i] ?? "")
    if (token === "--") {
      i += 1
      break
    }
    if (XARGS_OPERAND_FLAGS.has(token) || XARGS_OPERAND_FLAGS.has(token.toLowerCase())) {
      i += 1
      continue
    }
    if (token.startsWith("-")) continue
    consumerStart = i
    break
  }
  if (consumerStart < 0 && i < args.length) consumerStart = i
  if (consumerStart < 0) return "unproven"
  const invocation = executableInvocation(args.slice(consumerStart).join(" "))
  if (!invocation.leaf || invocation.unresolved) return "unproven"
  if (RO_DELETE_LEAVES.has(invocation.leaf)) return "write"
  return "unproven"
}

/** True only for invocations that are flag-only help/version output. */
function roHelpVersionOnly(args: string[]): boolean {
  return args.length > 0 && args.every((a) =>
    /^--?(?:help|version|info|h|v|V)$/i.test(stripMatchingQuotes(a)) ||
    /^--list-(?:sdks|runtimes|templates)$/i.test(stripMatchingQuotes(a)),
  )
}

/** Known-safe executable leaves that only ever inspect state (resolve names,
 *  print, measure): a proven-read surface under RO with the same operand
 *  hygiene the vocabulary "read" class applies. Members must all be in
 *  isKnownSafeSegment — mutating forms of a leaf that known-safe also covers
 *  (e.g. `sed -i`, `cp`) still deny earlier on the write-shape path. */
const RO_RESOLVER_LEAVES = new Set([
  "which", "whereis", "where", "type", "hash", "true", "false", ":",
  "echo", "printf", "write-output", "write-host",
  "ls", "dir", "get-childitem", "pwd", "get-location", "whoami", "uname",
  "df", "du", "free", "ps", "get-process", "stat", "file", "head",
  "tail", "wc", "sort", "uniq", "cat", "type", "more", "less", "get-content",
  "readlink", "realpath", "basename", "dirname", "seq", "expr", "id", "uptime",
  "cal", "lsattr", "getfattr", "lscpu", "lsmod", "lsusb", "lspci", "locale",
  "getent", "atq", "jobs", "lsblk", "iconv", "tasklist", "netstat", "ss",
  "jq", "diff", "select-string", "test-path", "resolve-path", "get-command",
  "select-object", "findstr", "cut", "column", "tr", "tac", "nl", "pr", "fmt",
  "fold", "paste", "join", "comm", "expand", "shuf", "strings", "xxd", "od",
  "hexdump", "md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
  "sha512sum", "base64", "sed", "yq", "awk", "test", "[", "sleep",
])

/** Executable-position mutation/execution check for the RO gate. Returns the
 *  deny reason kind for recognized mutators and "read" for proven read-only
 *  invocations; `undefined` keeps the invocation on the normal classification
 *  path (known-safe reads, review signals, the unproven fallback). */
function readOnlyMutatingInvocation(segment: string): "write" | "unproven" | "execute" | "read" | undefined {
  // Executor forms run a child command whose reads/network use the kernel's
  // write boundary cannot contain: under RO they are denied outright, never
  // "proven read" and never kernel-passed.
  if (executorCapabilityHazard(segment) !== undefined) return "execute"
  const invocation = executableInvocation(segment)
  const kind = roInvocationKind(invocation, segment)
  if (kind !== undefined) {
    // A privileged launcher keeps its reviewer path even for proven reads:
    // `sudo git status` stays an ASK instead of a static allow.
    return invocation.hadPrivilegeLauncher && kind === "read" ? undefined : kind
  }
  const { leaf, tokens, index, hadPrivilegeLauncher } = invocation
  if (hadPrivilegeLauncher) {
    // sudo/doas with an unrecognized payload is an unproven privileged
    // execution: under fail_open the ASK trigger path would run it without
    // review, and a privilege-escalated unknown command cannot be proven
    // write-free. Recognized reads (sudo cat, sudo ls) keep their ASK path.
    const rest = tokens.slice(index).join(" ")
    if (!isKnownSafeSegment(rest)) return "unproven"
    return undefined
  }
  // Proven pure-read leaves that carry no vocabulary entry: `which`, `wc`,
  // `stat`, `sed` (non -i), `jq`, `command -v`, … earn the same "read" class
  // the vocabulary gives `git status`. The leaf must BOTH be on the resolver
  // list and pass isKnownSafeSegment so write-capable forms (`sed -i`,
  // `shuf -o`, `yq -i`) stay on the normal write/scan path.
  const strippedSeg = stripOutputRedirects(segment) ?? segment
  // Write-vocab flags on otherwise-read leaves (`sed -i`, `shuf -o`,
  // `sort -o`, `base64 -o`) must still reach the write-shape deny — the
  // "read" exemption skips extractWriteTargets on the main gate path.
  const knownSafe =
    isKnownSafeSegment(strippedSeg) && extractWriteTargets(strippedSeg).targets.length === 0
  if (knownSafe && (leaf === undefined || RO_RESOLVER_LEAVES.has(leaf))) {
    return "read"
  }
  return undefined
}

function roInvocationKind(invocation: ExecutableInvocation, segment: string): "write" | "unproven" | "read" | undefined {
  const { leaf, args, unresolved, sudoMode } = invocation
  if (unresolved) return "unproven"
  if (sudoMode === "edit") return "write"
  if (sudoMode === "shell") return "unproven"
  if (!leaf) return undefined

  switch (leaf) {
    case "rm":
    case "remove-item":
    case "del":
    case "erase":
    case "unlink":
    case "rmdir":
    case "rd":
    case "ri":
    case "shred":
    case "srm":
    case "wipe":
      return "write"

    case "find":
      return roFindKind(args)
    case "xargs":
      return roXargsKind(args)

    case "git":
      return roGitKind(args)

    case "npm": {
      const { sub } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "read" // bare npm prints help
      if (sub === "audit") {
        return args.some((a) => stripMatchingQuotes(a).toLowerCase() === "fix") ? "write" : "read"
      }
      // docs/repo/bugs launch a browser — side-effecting, keep the normal path.
      if (NPM_READ_SUBS.has(sub) && !["docs", "repo", "bugs"].includes(sub)) return "read"
      if (NPM_EXEC_SUBS.has(sub)) return "unproven"
      if (NPM_STATE_SUBS.has(sub) || NPM_WRITE_SUBS.has(sub)) return "write"
      return "unproven" // unknown/plugin subcommand
    }
    case "pnpm": {
      const { sub } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "read"
      if (["ls", "list", "ll", "la", "outdated", "audit", "licenses", "bin", "root", "info", "view", "search", "help", "why"].includes(sub)) return "read"
      if (["run", "start", "test", "exec", "dlx", "dev", "build", "preview", "serve", "create", "init"].includes(sub)) return "unproven"
      return "write"
    }
    case "yarn": {
      const { sub } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "write" // bare yarn == yarn install
      if (["list", "info", "why", "outdated", "audit", "licenses", "bin", "help", "explain", "search"].includes(sub)) return "read"
      if (["run", "dlx", "exec", "node", "start", "dev", "test", "build", "serve", "watch", "workspace", "workspaces", "foreach", "unplug", "create", "constraints"].includes(sub)) return "unproven"
      return "write"
    }
    case "bun": {
      const { sub } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "unproven" // bare bun is a REPL
      if (["install", "i", "add", "a", "remove", "rm", "update", "link", "unlink", "publish", "patch", "pm", "completions", "init", "create", "build"].includes(sub)) return "write"
      if (["outdated", "help"].includes(sub)) return "read"
      return "unproven" // bun x/run/test/dev and bare script operands execute
    }

    case "pip":
    case "pip3": {
      const { sub } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "read"
      if (PIP_READ_SUBS.has(sub)) return "read"
      if (PIP_WRITE_SUBS.has(sub)) return "write"
      return "unproven"
    }
    case "pipx": {
      const { sub } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "read"
      if (sub === "list" || sub === "environment" || sub === "version" || sub === "help") return "read"
      if (sub === "run" || sub === "runpip") return "unproven"
      return "write"
    }
    case "uv": {
      const { sub, index } = roSubcommand(args, PM_VALUE_FLAGS)
      if (!sub) return "read"
      if (sub === "run" || sub === "x" || sub === "exec") return "unproven"
      if (sub === "pip") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        if (nested === "list" || nested === "freeze" || nested === "show" || nested === "check" || nested === "inspect") return "read"
        return "write"
      }
      if (sub === "tool") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        return nested === "list" || nested === "dir" || nested === "help" ? "read" : "write"
      }
      if (sub === "python") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        return nested === "list" || nested === "find" || nested === "dir" || nested === "help" ? "read" : "write"
      }
      if (sub === "cache") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        return nested === "dir" || nested === "help" ? "read" : "write"
      }
      if (sub === "version" || sub === "help" || sub === "help-check") return "read"
      return "write" // add/sync/lock/remove/build/publish/venv/init/export/self…
    }

    case "cargo": {
      const { sub } = roSubcommand(args, new Set(["--config", "-Z"]))
      if (!sub) return "read"
      if (CARGO_READ_SUBS.has(sub)) return "read"
      if (CARGO_EXEC_SUBS.has(sub)) return "unproven"
      return "write"
    }
    case "go": {
      const { sub } = roSubcommand(args)
      if (!sub) return "read"
      if (sub === "version" || sub === "doc" || sub === "help") return "read"
      if (sub === "env") {
        return args.some((a) => {
          const t = stripMatchingQuotes(a)
          return t === "-w" || t === "-u"
        }) ? "write" : "read"
      }
      if (sub === "test" || sub === "run" || sub === "tool") return "unproven"
      return "write" // build/install/get/mod/work/fix/clean/fmt/vet/list/generate
    }

    case "make":
    case "gmake": {
      // Dry-run (-n/--dry-run/--recon/--just-print/-q) prints recipes without
      // executing; every other invocation (bare build, clean, test, arbitrary
      // targets incl. `help`) executes project recipes or writes artifacts.
      const dryRun = args.some((a) => {
        const t = stripMatchingQuotes(a)
        return (
          t === "-n" || t === "--dry-run" || t === "--recon" ||
          t === "--just-print" || t === "-q" || t === "--question" ||
          (/^-[a-zA-Z]*n[a-zA-Z]*$/.test(t) || /^-[a-zA-Z]*q[a-zA-Z]*$/.test(t))
        )
      })
      if (dryRun) return "read"
      if (roHelpVersionOnly(args)) return "read"
      return "unproven"
    }
    case "ninja": {
      if (args.some((a) => stripMatchingQuotes(a) === "-n")) return "read"
      const toolIndex = args.findIndex((a) => stripMatchingQuotes(a) === "-t" || stripMatchingQuotes(a) === "--tool")
      if (toolIndex >= 0) {
        const tool = stripMatchingQuotes(args[toolIndex + 1] ?? "").toLowerCase()
        if (tool === "clean" || tool === "cleandead" || tool === "recompact") return "write"
        if (["list", "targets", "rules", "deps", "graph", "commands", "query", "inputs", "all", "restat", "missingdeps"].includes(tool)) return "read"
        return "unproven"
      }
      if (roHelpVersionOnly(args)) return "read"
      return "unproven" // builds artifacts
    }
    case "cmake": {
      if (args.length > 0 && args.every((a) =>
        /^(--version|--help(?:-\S*)?|-h|-N|--system-information)$/i.test(stripMatchingQuotes(a)),
      )) return "read"
      const eIndex = args.findIndex((a) => stripMatchingQuotes(a) === "-E")
      if (eIndex >= 0) {
        const eCmd = stripMatchingQuotes(args[eIndex + 1] ?? "").toLowerCase()
        if (["capabilities", "help", "echo", "echo_append", "env", "true", "false", "time", "sleep", "directory"].includes(eCmd)) return "read"
        return "write"
      }
      return "write" // configure/generate/build/install/open all write
    }
    case "meson": {
      const { sub } = roSubcommand(args)
      if (sub === "introspect" || sub === "info" || sub === "help" || sub === "version") return "read"
      if (roHelpVersionOnly(args)) return "read"
      return "unproven"
    }
    case "mvn":
    case "mvnw":
    case "maven":
    case "gradle":
    case "gradlew":
      // Goals/tasks run build plugins and write artifacts or ~/.m2 ~/.gradle;
      // only pure --version/--help output is free of side effects.
      return roHelpVersionOnly(args) ? "read" : "unproven"

    case "docker":
    case "podman":
    case "nerdctl":
    case "docker-compose": {
      const dockerValueFlags = new Set(["-H", "--host", "-c", "--context", "--config", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey"])
      const { sub, index } = roSubcommand(args, dockerValueFlags)
      if (!sub) return "read"
      if (sub === "exec" || sub === "run" || sub === "attach" || sub === "cp") return "unproven"
      const topReads = new Set([
        "ps", "images", "logs", "top", "events", "stats", "version",
        "info", "diff", "history", "port", "search", "help",
      ])
      if (topReads.has(sub)) return "read"
      // `docker inspect` can expose env/credential material: keep the normal
      // classification path (same choice as kubectl and the nested inspects).
      if (sub === "inspect") return undefined
      // Grouped verbs: only their listing/inspection actions read. `inspect`
      // surfaces can expose env/credential material, so like kubectl they keep
      // the normal classification path instead of a static read allow.
      const nested = roSubcommand(args.slice(index + 1)).sub
      if (sub === "image" || sub === "container" || sub === "volume" || sub === "network" || sub === "plugin" || sub === "node" || sub === "service") {
        return ["ls", "list", "inspect", "ps", "logs", "history", "help", "exists", "stats", "top"].includes(nested ?? "") ? undefined : "write"
      }
      if (sub === "system") return ["df", "info", "events", "help"].includes(nested ?? "") ? undefined : "write"
      if (sub === "context" || sub === "builder" || sub === "trust" || sub === "secret" || sub === "config" || sub === "stack" || sub === "swarm" || sub === "checkpoint") {
        return nested === "ls" || nested === "inspect" || nested === "show" || nested === "help" ? undefined : "write"
      }
      if (sub === "manifest") return nested === "inspect" ? undefined : "write"
      if (sub === "compose") {
        return ["ps", "ls", "logs", "config", "images", "top", "version", "port", "events", "help", "stats"].includes(nested ?? "") ? undefined : "write"
      }
      return "write"
    }
    case "kubectl": {
      const kubectlValueFlags = new Set([
        "-n", "--namespace", "--context", "--cluster", "--user", "--kubeconfig",
        "--server", "-s", "--token", "--as", "--as-group", "--cache-dir",
        "--certificate-authority", "--client-certificate", "--client-key",
        "--request-timeout", "--tls-server-name", "-f", "--filename", "-k",
        "--kustomize", "-o", "--output", "-l", "--selector", "--field-selector",
        "--sort-by", "--as-uid",
      ])
      const { sub, index } = roSubcommand(args, kubectlValueFlags)
      if (!sub) return undefined
      if (sub === "config") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        return ["view", "current-context", "get-contexts", "get-clusters", "get-users", "help"].includes(nested ?? "") ? undefined : "write"
      }
      if (sub === "auth") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        return nested === "can-i" || nested === "help" ? undefined : "write"
      }
      if (["get", "describe", "logs", "top", "version", "explain", "api-resources", "api-versions", "cluster-info", "events", "diff", "wait", "options", "completion", "kustomize", "plugin"].includes(sub)) return undefined
      if (["exec", "run", "attach", "debug", "proxy", "port-forward", "cp"].includes(sub)) return "unproven"
      return "write"
    }
    case "crictl":
    case "ctr": {
      const { sub } = roSubcommand(args)
      if (!sub) return "read"
      return ["ps", "images", "image", "inspect", "inspecti", "inspectp", "info", "version", "help", "stats", "logs", "containers", "pods", "tasks", "namespaces", "content", "leases", "plugins", "snapshots", "events"].includes(sub) ? "read" : "write"
    }

    case "ssh-keygen": {
      // Print/read actions (-y/-l/-L/-e/-i/-F/-B) read; generation, signing,
      // passphrase changes and known_hosts edits write. `-f <key>` operands
      // still pass through the read-path sensitivity scan.
      const readFlag = new Set(["-y", "-l", "-L", "-e", "-i", "-F", "-B"])
      return args.some((a) => readFlag.has(stripMatchingQuotes(a))) ? "read" : "write"
    }
    case "openssl": {
      const { sub } = roSubcommand(args)
      if (!sub) return "unproven" // bare openssl is an interactive REPL
      if (sub === "version" || sub === "help" || sub === "list" || sub === "engines" || sub === "ciphers") return "read"
      const writesByDefault = new Set([
        "genrsa", "genpkey", "gendsa", "genec", "req", "ca", "ecparam",
        "dsaparam", "dhparam", "rand", "rehash", "c_rehash", "pkcs12", "cms",
        "smime", "ts", "tsget", "ocsp", "nseq", "crl2pkcs7", "s_server",
        "passwd", "crl", "pkcs7", "pkcs8", "storeutl", "mac", "kdf", "enc",
        "dgst", "rsautl", "pkeyutl", "asn1parse", "s_client", "s_time",
        "sess_id", "speed", "verify", "prime", "errstr", "engine", "x509",
        "pkey", "dh", "dsa", "rsa", "ec",
      ])
      const hasOut = args.some((a) => /^(?:-out|-keyout|-sigopt|-passout|-writerand)$/i.test(stripMatchingQuotes(a)))
      if (hasOut) return "write"
      if (writesByDefault.has(sub)) return "write"
      return "unproven"
    }

    case "tar":
    case "bsdtar": {
      // Operation letter decides: c/x/r/u (and --delete/--concatenate/--append)
      // write; t/d list or compare. Old-style leading operand (tar xf a.tgz)
      // counts as an op letter too.
      for (const raw of args) {
        const token = stripMatchingQuotes(raw)
        if (/^--?(create|extract|get|append|update|delete|concatenate|catenate)\b/i.test(token)) return "write"
        if (/^--?(list|diff|compare|test-label)\b/i.test(token)) return "read"
        if (token.startsWith("-") && !token.startsWith("--")) {
          if (/[cxruA]/.test(token.slice(1))) return "write"
          if (/[td]/.test(token.slice(1))) return "read"
          continue
        }
        if (!token.startsWith("-") && /^[a-zA-Z]+$/.test(token)) {
          if (/[cxruA]/.test(token)) return "write"
          if (/[td]/.test(token)) return "read"
        }
      }
      return "write" // bare tar is a mutator shape
    }
    case "unzip": {
      // Listing/stdout/test modes read; plain extraction and overwrite/
      // freshen flags write. "read" exempts the implicit extraction-dir
      // target that extractWriteTargets emits for every unzip invocation.
      const hasReadAction = args.some((a) => /^-[lvtpczZ1]/.test(stripMatchingQuotes(a)))
      const hasWriteFlag = args.some((a) => /^-[oDuUfnj]/.test(stripMatchingQuotes(a)))
      if (hasReadAction && !hasWriteFlag) return "read"
      return "write"
    }
    case "zipinfo":
      return "read" // always a listing tool
    case "gzip":
    case "gunzip":
    case "bzip2":
    case "bunzip2":
    case "xz":
    case "unxz":
    case "zstd":
    case "unzstd":
    case "lz4":
    case "lzip": {
      // -c writes to stdout, -l lists, -t tests; the rest (including bare
      // `gunzip x.gz`) writes a decompressed file.
      const reads = args.some((a) => {
        const t = stripMatchingQuotes(a)
        return /-[clt]/.test(t) || /^--(?:stdout|to-stdout|list|test|decompress|uncompress)$/i.test(t)
      })
      return reads ? "read" : "write"
    }
    case "zcat":
    case "bzcat":
    case "xzcat":
    case "zstdcat":
    case "gzcat":
      return "read"

    case "curl": {
      const writesToStdout = new Set(["-o", "--output", "-D", "--dump-header", "-c", "--cookie-jar", "--trace", "--trace-ascii"])
      for (let i = 0; i < args.length; i += 1) {
        const token = stripMatchingQuotes(args[i] ?? "")
        if (token === "--") break
        if (/^--(?:output|remote-name|remote-header-name|remote-name-all|cookie-jar|dump-header|output-dir|create-dirs|trace(?:-ascii|-config|-ids|-time)?|save-headers|xattr|clobber|upload-file|remove-on-error|fail-early|junk-session-cookies)$/i.test(token)) {
          if (writesToStdout.has(token.toLowerCase()) && stripMatchingQuotes(args[i + 1] ?? "") === "-") continue
          return "write"
        }
        if (/^-[oODJcT]$/.test(token)) {
          if ((token === "-o" || token === "-D" || token === "-c") && stripMatchingQuotes(args[i + 1] ?? "") === "-") continue
          return "write"
        }
        if (/^-[a-zA-Z]*[oODJcT][a-zA-Z]*$/.test(token)) return "write" // bundled -o/-O/-D/-J/-c/-T
      }
      return undefined
    }
    case "wget": {
      if (args.some((a) => stripMatchingQuotes(a).toLowerCase() === "--spider")) return undefined
      for (let i = 0; i < args.length; i += 1) {
        const token = stripMatchingQuotes(args[i] ?? "")
        if (/^--(?:output-document|output-file|append-output|save-headers|save-cookies|load-cookies|timestamping|backup-converted|convert-links|page-requisites|recursive|mirror|continue|background|input-file|force-html|base|directory-prefix|cut-dirs|no-directories|trust-server-names|content-disposition|adjust-extension|backup-converted|delete-after|retr-symlinks|restrict-file-names|warc-file|warc-dedup|post-file|post-data|method|body-data|body-file)$/i.test(token)) {
          if ((token === "-O" || token === "--output-document") && stripMatchingQuotes(args[i + 1] ?? "") === "-") continue
          return "write"
        }
        if (/^-[ObacrkmpiFNB]$/.test(token)) {
          if (token === "-O" && stripMatchingQuotes(args[i + 1] ?? "") === "-") continue
          return "write"
        }
      }
      return "write" // any URL invocation downloads to a file
    }
    case "rsync": {
      const dryRun = args.some((a) => {
        const t = stripMatchingQuotes(a)
        return t === "-n" || t === "--dry-run" || t === "--list-only" || (/^-[a-zA-Z]*n[a-zA-Z]*$/.test(t) && !t.startsWith("--"))
      })
      return dryRun ? "read" : "write"
    }

    case "systemctl": {
      const systemctlValueFlags = new Set([
        "-t", "--type", "-p", "--property", "-n", "--lines", "-o", "--output",
        "-H", "--host", "-M", "--machine", "--root", "--job-mode", "-i",
        "--signal", "-s", "--what", "--state", "--kill-whom", "--kill-value",
        "-T", "--preset-mode", "--image", "--image-policy", "--boot-loader-entry",
        "--boot-loader-menu",
      ])
      const { sub } = roSubcommand(args, systemctlValueFlags)
      if (!sub) return "read"
      const reads = new Set([
        "status", "is-active", "is-enabled", "is-failed", "is-system-running",
        "list-units", "list-unit-files", "list-timers", "list-dependencies",
        "list-jobs", "list-machines", "list-sockets", "list-automounts",
        "list-paths", "show", "cat", "help", "get-default", "whoami",
      ])
      return reads.has(sub) ? "read" : "write"
    }
    case "timedatectl": {
      const { sub } = roSubcommand(args)
      return sub === undefined || ["status", "show", "list-timezones", "timesync-status", "show-timesync", "help"].includes(sub) ? "read" : "write"
    }
    case "hostnamectl": {
      const { sub } = roSubcommand(args)
      return sub === undefined || ["status", "hostname", "icon-name", "chassis", "deployment", "location", "help"].includes(sub) ? "read" : "write"
    }
    case "ufw": {
      const { sub } = roSubcommand(args)
      return sub === "status" || sub === "help" || sub === "version" ? "read" : "write"
    }
    case "crontab": {
      // `crontab -l` (optionally `-u user`) lists; -e/-r/file operands write.
      const ok = args.every((a) => {
        const t = stripMatchingQuotes(a)
        return t === "-l" || t === "-u"
      })
      if (ok) return "read"
      const tokens = args.map(stripMatchingQuotes)
      if (tokens[0] === "-u" && tokens.length === 3 && tokens[2] === "-l") return "read"
      if (tokens[0] === "-u" && tokens.length === 2 && tokens[1] === "-l") return "read"
      return "write"
    }
    case "mount": {
      const ok = args.every((a) => {
        const t = stripMatchingQuotes(a).toLowerCase()
        return t === "-l" || t === "--list" || t === "-h" || t === "--help" || t === "-v" || t === "--version" || t === "-s" || t === "-f" || t === "-n" || t === "-i"
      })
      // Any non-flag operand or unlisted flag = a real mount → write.
      return ok && !args.some((a) => !stripMatchingQuotes(a).startsWith("-")) ? "read" : "write"
    }
    case "umount":
      return "write"
    case "fdisk": {
      const ok = args.length > 0 && args.every((a) => {
        const t = stripMatchingQuotes(a)
        return /^-(?:l|u|s|b|x|h|v|V|L|o)$/.test(t) || t === "--help" || t === "--version" || t === "--list"
      })
      return ok ? "read" : "write"
    }
    case "parted": {
      const nonFlag = args.map(stripMatchingQuotes).filter((t) => !t.startsWith("-"))
      const okFlags = args.every((a) => {
        const t = stripMatchingQuotes(a).toLowerCase()
        return ["-l", "--list", "-s", "--script", "-h", "--help", "-v", "--version", "-m", "--machine", "-j", "--json", "-f", "--fix", "-a", "--align"].includes(t)
      })
      if (!okFlags) return "write"
      if (nonFlag.length === 0) return "read"
      const command = nonFlag[nonFlag.length - 1]?.toLowerCase()
      return command === "print" || command === "help" ? "read" : "write"
    }
    case "ip": {
      const mutating = args.some((a) => /^(?:add|del|delete|set|change|replace|append|flush|restore|exec|netns|batch|monitor|save)$/i.test(stripMatchingQuotes(a)))
      return mutating ? "write" : "read"
    }
    case "ifconfig": {
      const operands = args.map(stripMatchingQuotes).filter((t) => !t.startsWith("-"))
      if (operands.length <= 1) return "read" // bare or `ifconfig eth0` lists
      const mutate = /^(?:up|down|add|del|delete|remove|create|destroy|plumb|unplumb|tunnel|dstaddr|netmask|broadcast|pointopoint|media|mediaopt|hw|mtu|metric|txqueuelen|arp|promisc|allmulti|multicast|dynamic|trailers|description|group|vlan|rename)$/i
      return operands.slice(1).some((o) => mutate.test(o)) || operands.length > 1 ? "write" : "read"
    }
    case "schtasks":
      return /\/(?:create|delete|change|run|end)\b/i.test(segment) ? "write" : "read"
    case "journalctl":
      return args.some((a) => /^--vacuum/.test(stripMatchingQuotes(a))) ? "write" : "read"
    case "sysctl": {
      const writing = args.some((a) => {
        const t = stripMatchingQuotes(a)
        return t === "-w" || t === "--write" || /=/.test(t)
      })
      return writing ? "write" : "read"
    }
    case "awk":
    case "gawk":
    case "mawk":
    case "yq": {
      if (roInplaceProcessor(args) === "write") return "write"
      // `-f`/`--file` reads an uninspected script file: its `system()`/`getline`
      // surface cannot be checked, so it stays unproven. Inline programs with
      // those primitives keep the normal path (their ASK signals still apply).
      if (args.some((a) => {
        const t = stripMatchingQuotes(a)
        return t === "-f" || /^-f\S/.test(t) || /^--file/.test(t)
      })) return "unproven"
      if (/(?:system\s*\(|\|\s*getline|getline\s*<\s*)/.test(args.join(" "))) return undefined
      return "read"
    }

    case "python":
    case "python2":
    case "python3":
    case "py": {
      // `python -m pip <read>` keeps pip's read surface; other -m modules
      // (venv, pytest, http.server, build, …) execute or write project code.
      const mIndex = args.findIndex((a) => stripMatchingQuotes(a) === "-m")
      if (mIndex >= 0) {
        const module = stripMatchingQuotes(args[mIndex + 1] ?? "").toLowerCase()
        if (module === "pip" || module === "pip3") {
          const sub = roSubcommand(args.slice(mIndex + 2)).sub
          if (!sub || PIP_READ_SUBS.has(sub)) return "read"
          if (PIP_WRITE_SUBS.has(sub)) return "write"
          return "unproven"
        }
        return "unproven"
      }
      // `python -c <code>` inline analysis mirrors the interop gate: the
      // payload is one argv element, so trailing fd redirects (dropped from
      // `args` by the invocation tokenizer) never reach it. Pure print/read
      // code resolves statically; every other form stays unproven.
      const cIndex = args.findIndex((a) => stripMatchingQuotes(a) === "-c")
      if (cIndex >= 0) {
        const code = stripMatchingQuotes(args[cIndex + 1] ?? "")
        if (!code.trim()) return "unproven"
        return pyInlineClass(code) === "read" ? "read" : "unproven"
      }
      const flagOnly = args.length > 0 && args.every((a) =>
        /^(--version|--help|-h|-V|--check-hash-based-pycs|--isolated|--init)$/i.test(stripMatchingQuotes(a)),
      )
      return flagOnly ? "read" : "unproven"
    }
    case "node":
    case "deno": {
      // Inline-eval payloads (`node -e`/`--eval`/`-p`/`--print`, `deno eval`)
      // get the same proof ladder as python -c: pure print/read expressions
      // are read-class, everything else stays unproven. `-v`/`--version`/`--help`
      // keep their static read.
      const inlineCode = jsInlineCode(leaf, args)
      if (inlineCode !== undefined) {
        if (!inlineCode.trim()) return "unproven"
        return jsInlineReadOnly(inlineCode) ? "read" : "unproven"
      }
      return roHelpVersionOnly(args) ? "read" : "unproven"
    }
    case "perl":
    case "ruby":
    case "php":
    case "lua":
    case "luajit":
    case "rscript":
    case "java":
      return roHelpVersionOnly(args) ? "read" : "unproven"
    case "dotnet": {
      if (roHelpVersionOnly(args)) return "read"
      const { sub, index } = roSubcommand(args)
      if (sub === "sln") {
        const nested = roSubcommand(args.slice(index + 1)).sub
        return nested === "list" ? "read" : "write"
      }
      if (sub === "run" || sub === "test" || sub === "watch" || sub === "vstest" || sub === "fsi" || sub === "exec") return "unproven"
      return sub ? "write" : "read" // bare dotnet prints CLI help
    }
    case "dd":
      return args.some((a) => /^\s*of\s*=/i.test(stripMatchingQuotes(a))) ? "write" : "read"
  }

  if (RO_WRITE_LEAVES.has(leaf)) return "write"
  if (RO_UNPROVEN_LEAVES.has(leaf)) return "unproven"
  if (/^(?:mkfs|fsck|mke2fs)[.+-]/i.test(leaf)) return "write"
  return undefined
}

// --- RO writable-scratch carve-out + kernel pass-through --------------------
//
// The kernel sandbox freezes every write outside the scratch hierarchy
// (default /tmp — the agent's dedicated directory). Two consequences for the
// RO static gate:
//
//  1. Scratch carve-out (ALL strictness levels, kernel present or not): a
//     mutation whose targets are ENTIRELY confined to roWritableRoots is a
//     scratch write, not an unauthorized write — ALLOW. Config denyWrite
//     entries override the carve-out per path.
//  2. Kernel pass-through (LOOSE only, roKernelEnforced): when the kernel
//     will actually wrap this call, write-shape/mutator/unproven denials
//     pass through as ALLOW — the kernel denies the real syscalls. A
//     non-write gate still runs first (floors, credentials, network, sudo)
//     because the kernel cannot see those. HARD never passes through.

/** Write vocabularies whose targets are NOT enumerable: code-level file APIs
 *  inside interpreter payloads (`open(x,'w')`, `writeFileSync`, `.write_text`)
 *  and PowerShell writers that take their path as an ordinary operand. A
 *  segment containing them can never claim "all targets under /tmp". */
const NONEXTRACTABLE_WRITE_RE =
  /\bopen\s*\([^)]*["'`]\s*[wax+]|\bopen\s*\([^)]*\bmode\s*=\s*["'`]\s*[wax+]|\.(?:write_text|write_bytes|writelines)\s*\(|(?:^|\bfs\s*\.\s*)(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync|mkdir|mkdirSync|rename|renameSync|truncate|truncateSync|rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync|mkdtemp|mkdtempSync|symlink|symlinkSync|link|linkSync|chmod|chmodSync|chown|chownSync|utimes|utimesSync)\s*\(|\bcreateWriteStream\s*\(|\b(?:set-content|add-content|out-file|new-item|copy-item|move-item|rename-item|set-item)\b/i

/** Mutators that write inside the project/checkout at the command's base
 *  (the cwd or the tree their operands point at). Cwd-scoped subcommand
 *  whitelists keep global-config/network/system surfaces out of the
 *  carve-out. */
function roCwdScopedMutator(invocation: ExecutableInvocation): boolean {
  const { leaf, args } = invocation
  if (!leaf) return false
  const bare = args.map(stripMatchingQuotes)
  const sub = roSubcommand(args, leaf === "git" ? GIT_VALUE_FLAGS : PM_VALUE_FLAGS).sub ?? ""
  switch (leaf) {
    case "git": {
      if (!RO_GIT_MUTATORS.has(sub)) return false
      return !["push", "fetch", "pull", "clone", "send-pack", "receive-pack", "upload-archive", "imap-send", "daemon", "instaweb", "p4", "svn", "bundle"].includes(sub)
    }
    case "npm":
    case "pnpm":
    case "yarn":
    case "bun":
      // Project-tree installs/removals only: config/access/cache/pkg/exec
      // surfaces write outside the tree or run code.
      return (
        NPM_WRITE_SUBS.has(sub) &&
        !["config", "cache", "pkg", "access", "hook", "org", "team", "profile", "dist-tag", "token", "owner", "star", "stars", "unstar", "publish", "unpublish", "deprecate", "login", "logout", "adduser", "link", "ln", "fund", "sbom"].includes(sub)
      )
    case "cargo": {
      if (["install", "publish", "login", "logout", "owner", "yank", "fetch", "add", "remove", "search"].includes(sub)) return false
      return !CARGO_READ_SUBS.has(sub)
    }
    case "go": {
      return ["build", "test", "run", "mod", "fmt", "vet", "generate", "clean", "work", "tool", "fix", "list"].includes(sub)
    }
    case "make":
    case "gmake":
    case "ninja":
    case "cmake":
    case "meson":
    case "mvn":
    case "mvnw":
    case "maven":
    case "gradle":
    case "gradlew":
      return !bare.some((token) => /^--install\b|^--open\b/i.test(token))
    case "gem":
    case "bundle":
    case "bundler":
    case "composer":
    case "poetry":
    case "pipenv":
    case "pdm":
    case "rye":
    case "hatch":
    case "conda":
    case "mamba":
    case "micromamba":
    case "luarocks":
    case "cpan":
    case "cpanm":
    case "mix":
    case "rebar3":
    case "opam":
    case "cabal":
    case "stack":
      return true
    default:
      return false
  }
}

/** Operand scan for the cwd-scoped carve-out: a flag/operand that redirects
 *  the mutation outside the tree (`--global`, `-g`, `--system`, absolute or
 *  `~`/`..` operands outside the roots) forfeits the exemption. Flag values
 *  that name directories (-C/--git-dir/--prefix) relocate the effective
 *  base — those are checked like operands and, when present, replace the
 *  bare-base check. */
const RO_GLOBAL_SCOPE_FLAGS = new Set([
  "-g", "--global", "--system", "--system-wide", "--user", "--save-global",
  "--globalconfig", "--systemconfig", "--work-tree", "--git-dir", "-C",
  "--prefix", "--target", "--target-dir", "--directory-prefix", "--cache",
  "--cache-dir", "--root", "--location=global",
])

/** Tri-state writability for one candidate mutation target:
 *  "ok" — canonically confined to a writable root and not denyWrite-frozen;
 *  "frozen" — confined but inside a configured sandbox.denyWrite entry;
 *  "outside" — not confined (or unparseable). `container` marks targets
 *  that RECEIVE files into a directory (`cp f /tmp/`, `tar xf -C /tmp/d`):
 *  those may equal a root itself; non-container targets must sit strictly
 *  inside a root. */
async function roPathWritable(
  candidate: string,
  base: string,
  roots: string[],
  denyWrite: string[],
  container = false,
): Promise<"ok" | "frozen" | "outside"> {
  const resolved = resolveTempPathCandidate(candidate, base)
  if (!resolved) return "outside"
  let isContainer = container || candidate.trim().endsWith("/")
  if (!isContainer) {
    try {
      isContainer = (await lstat(resolved.absolute)).isDirectory()
    } catch {
      /* nonexistent — treated as a leaf target */
    }
  }
  const inside =
    roots.some(
      (root) =>
        isStrictlyWithin(root, resolved.absolute) ||
        ((resolved.contentsOnly || isContainer) &&
          path.resolve(root).toLowerCase() === path.resolve(resolved.absolute).toLowerCase()),
    )
  if (!inside) return "outside"
  // Confinement must hold canonically too — a symlinked entry inside /tmp
  // pointing at /etc cannot launder an out-of-scratch write.
  const canonical = await canonicalProjectedPath(resolved.absolute)
  if (canonical && !roots.some((root) => isWithin(root, canonical))) return "outside"
  // Config denyWrite freezes override the carve-out — judged on the canonical
  // projection so a symlinked scratch entry cannot launder a frozen path.
  if (denyWrite.length > 0) {
    const probe = canonical ?? resolved.absolute
    if (denyWrite.some((denied) => isWithin(denied, probe))) return "frozen"
  }
  return "ok"
}

/** Every mutation target this segment can statically enumerate: redirect
 *  targets and write-vocabulary targets (tee/dd/mkdir/cp|mv/sed -i/…) via
 *  extractWriteTargets, archive extraction dirs (tar -C / unzip -d / bare),
 *  find -delete/-exec-rm roots, delete invocations (rm/rmdir/shred/…), mv
 *  source+target, and chmod/chown-family operands. Returns undefined when
 *  any target is unparseable (dynamic expansion) — fail closed. */
async function mutationTargetsOf(
  segment: string,
  roView: string,
  shell: string,
): Promise<Array<{ path: string; container: boolean }> | undefined> {
  if (hasDynamicShellExpansion(segment, shell)) return undefined
  const writes = extractWriteTargets(roView)
  if (writes.unparseable) return undefined
  const targets = writes.targets
    .filter((target) => target !== "")
    .map((target) => ({ path: target, container: false }))

  const tokens = simpleInvocationTokens(segment)
  const command = commandLeaf(tokens[0] ?? "")

  if (command === "tar") {
    // `tar f` writes the archive only when creating/updating; extraction
    // reads it and writes into -C/--directory or the base.
    const creating = tokens.slice(1).some((raw) => {
      const token = stripMatchingQuotes(raw)
      return /^--?(create|append|update|delete|concatenate|catenate)\b/i.test(token) ||
        (token.startsWith("-") && !token.startsWith("--") && /[crAu]/.test(token.slice(1))) ||
        (!token.startsWith("-") && /^[a-zA-Z]+$/.test(token) && /[crAu]/.test(token))
    })
    const dirs = [...segment.matchAll(/\s-C\s+("([^"]*)"|'([^']*)'|(\S+))|--directory(?:=|\s+)("([^"]*)"|'([^']*)'|(\S+))/gi)]
      .map((m) => m[2] ?? m[3] ?? m[4] ?? m[6] ?? m[7] ?? m[8])
      .filter((dir): dir is string => Boolean(dir))
    if (creating) {
      // -f archive path already collected by extractWriteTargets; nothing
      // else to enumerate.
    } else {
      targets.push(...(dirs.length > 0 ? dirs : ["."]).map((dir) => ({ path: dir, container: true })))
    }
  }
  if (command === "unzip" || command === "7z" || command === "7za" || command === "7zr") {
    const dirs = [...segment.matchAll(/(?:^|\s)-d\s*("([^"]*)"|'([^']*)'|(\S+))/gi)]
      .map((m) => m[2] ?? m[3] ?? m[4])
      .filter((dir): dir is string => Boolean(dir))
    targets.push(...(dirs.length > 0 ? dirs : ["."]).map((dir) => ({ path: dir, container: true })))
  }

  if (command === "find") {
    // `find <root> -delete` and `find <root> -exec rm …` delete under <root>.
    const deletes =
      /(?:^|\s)-delete(?:\s|$)/.test(segment) ||
      (() => {
        for (let i = 0; i < tokens.length; i += 1) {
          const token = stripMatchingQuotes(tokens[i] ?? "").toLowerCase()
          if (!FIND_EXEC_ACTIONS.has(token)) continue
          const consumer: string[] = []
          for (let j = i + 1; j < tokens.length; j += 1) {
            const c = stripMatchingQuotes(tokens[j] ?? "")
            if (c === "\\;" || c === ";" || c === "+") break
            consumer.push(tokens[j] ?? "")
          }
          const consumerLeaf = executableInvocation(consumer.join(" ")).leaf
          if (consumerLeaf && RO_DELETE_LEAVES.has(consumerLeaf)) return true
        }
        return false
      })()
    if (deletes) {
      const root = tokens.find((token, index) => index > 0 && !token.startsWith("-"))
      if (root) targets.push({ path: root, container: false })
    }
  }

  const deletion = parseDeleteInvocation(segment)
  if (deletion) {
    if (!deletion.parseable || deletion.targets.length === 0) return undefined
    targets.push(...deletion.targets.map((target) => ({ path: target, container: false })))
  }
  const move = parseMoveInvocation(segment)
  if (move) {
    targets.push({ path: move.source, container: false }, { path: move.target, container: true })
  }
  const copy = parseCopyInvocation(segment)
  if (copy) targets.push({ path: copy.target, container: true })

  if (["chmod", "chown", "chgrp", "chattr", "setfacl", "setfattr", "setcap", "attr", "install", "rename", "prename", "file-rename", "truncate", "touch", "mkdir", "ln", "mktemp", "mkfifo", "mknod"].includes(command ?? "")) {
    // First non-flag operand is the mode/spec; the rest are targets.
    const operands = tokens.slice(1).map(stripMatchingQuotes).filter((token) => !token.startsWith("-"))
    targets.push(...operands.slice(1).map((operand) => ({ path: operand, container: false })))
  }
  return targets
}

/** The /tmp carve-out for a write-class RO denial: every enumerated mutation
 *  target must sit under a writable root (canonically, denyWrite-honoring),
 *  and the segment must not carry non-enumerable write vocab or dynamic
 *  expansion. Cwd-scoped mutators (kind "write" only) instead require their
 *  effective base and every path operand to sit under a root. Interpreters,
 *  network clients and opaque executors never qualify — their real writes
 *  are not enumerable (same exclusion list the temp-confined path uses). */
async function roScratchCarveOut(
  segment: string,
  roView: string,
  base: string,
  input: InternalClassifyInput,
  kind: "write" | "unproven" | undefined,
): Promise<{ decision?: SegmentDecision; frozen?: boolean } | undefined> {
  const roots = input.roWritableRoots ?? ["/tmp"]
  const denyWrite = input.sandboxDenyWrite ?? []
  if (roots.length === 0) return undefined

  const invocation = executableInvocation(segment)
  const leaf = invocation.leaf
  const enumerableWrite =
    kind !== "unproven" &&
    (leaf === undefined || !TEMP_CONFINED_EXCLUDED_COMMAND.has(leaf)) &&
    !RO_UNPROVEN_LEAVES.has(leaf ?? "") &&
    !NONEXTRACTABLE_WRITE_RE.test(roView) &&
    !extractQuotedWrappers(segment).some((payload) => NONEXTRACTABLE_WRITE_RE.test(payload))
  if (enumerableWrite) {
    const targets = await mutationTargetsOf(segment, roView, input.shell)
    if (targets !== undefined && targets.length > 0) {
      let frozen = false
      for (const target of targets) {
        const status = await roPathWritable(target.path, base, roots, denyWrite, target.container)
        if (status === "frozen") frozen = true
        else if (status !== "ok") return undefined
      }
      if (frozen) {
        // Every target is confined, but a denyWrite entry freezes one of
        // them — the freeze overrides the carve-out in every mode.
        return { frozen: true }
      }
      return {
        decision: {
          verdict: "ALLOW",
          rules: ["operation.scratch-write"],
          reason: "Every mutation target is confined to the writable scratch root (/tmp)",
        },
      }
    }
  }

  if (kind !== "write" || !roCwdScopedMutator(invocation)) return undefined
  const carveFail = (status: "ok" | "frozen" | "outside") =>
    status === "frozen" ? ({ frozen: true } as const) : undefined
  // An unverified `cd` claim cannot carry the exemption: when the claimed
  // base fails canonical confinement the command may run in the real cwd.
  // canonicalProjectedPath handles not-yet-existing bases too.
  const baseOk =
    input.baseUnverified !== true ||
    (await (async () => {
      const canonical = await canonicalProjectedPath(base)
      const probe = canonical ?? base
      return roots.some((root) => isWithin(root, probe))
    })())
  if (!baseOk) return undefined

  // Directory-redirecting flag values replace the base; other path-shaped
  // operands must also stay inside the roots.
  const relocated: string[] = []
  const operandPaths: string[] = []
  const bare = invocation.args.map(stripMatchingQuotes)
  for (let i = 0; i < bare.length; i += 1) {
    const token = bare[i] ?? ""
    const eq = token.indexOf("=")
    const flagName = eq > 0 ? token.slice(0, eq) : token
    if (RO_GLOBAL_SCOPE_FLAGS.has(flagName.toLowerCase())) {
      const value = eq > 0 ? token.slice(eq + 1) : bare[i + 1]
      if (["-g", "--global", "--system", "--system-wide", "--user", "--save-global", "--globalconfig", "--systemconfig", "--location=global"].includes(flagName.toLowerCase())) {
        return undefined // global/user-level mutation target
      }
      if (value !== undefined) {
        relocated.push(value)
        if (eq < 0) i += 1
      }
      continue
    }
    if (token.startsWith("-")) continue
    const expanded = expandHome(token)
    if (/^(?:\/|~|\.\.?[\\/]|\\\\|[a-zA-Z]:[\\/])/.test(expanded)) operandPaths.push(expanded)
  }
  const effectiveBases = relocated.length > 0 ? relocated : [base]
  for (const dir of effectiveBases) {
    const status = await roPathWritable(dir, base, roots, denyWrite, true)
    if (status !== "ok") return carveFail(status)
  }
  for (const operand of operandPaths) {
    const status = await roPathWritable(operand, base, roots, denyWrite)
    if (status !== "ok") return carveFail(status)
  }
  return {
    decision: {
      verdict: "ALLOW",
      rules: ["operation.scratch-write"],
      reason: "The mutating command is confined to the writable scratch root (/tmp)",
    },
  }
}

/** Non-write findings the kernel cannot enforce: destructive floors, critical
 *  credential destruction, sensitive-path reads, network clients, and
 *  privilege launches. `segment`/`combined` are the already-masked surfaces;
 *  decoded/quoted payloads join the scan. A clean result returns undefined —
 *  the caller may then pass the segment through. */
async function roNonWriteGate(
  segment: string,
  base: string,
  input: InternalClassifyInput,
  strictness: Strictness,
): Promise<SegmentDecision | undefined> {
  const bypassed = input.bypassedCategories
  const ctx: PathContext = { cwd: base, worktree: input.worktree, strictness }
  // Rule surfaces use the proven-data view (fix D); sensitive-path findings
  // below keep the raw surfaces so masking can never hide a credential path.
  const ruleSurface = dataLiteralView(segment) ?? segment
  const ruleSurfaces = [
    ruleSurface,
    ...extractDecodedPayloads(ruleSurface, { executedOnly: true }),
    ...ruleScanWrappers(ruleSurface),
  ]
  const surfaces = [segment, ...extractDecodedPayloads(segment), ...extractQuotedWrappers(segment)]
  const combined = ruleSurfaces
    .flatMap((surface) => {
      const view = payloadRuleView(surface, input.shell)
      return [...view.segments, ...view.sinks]
    })
    .map((surface) => maskHeredocDataBodies(surface, input.shell))
    .join("\n\n")

  for (const rule of SECURITY_SIGNAL_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (!DEFINITE_DESTRUCTIVE_RULES.has(rule.id)) continue
    if (!rule.test(combined)) continue
    if (
      rule.id === "filesystem.forced-recursive-delete" &&
      (await forcedDeletesConfinedToTemp(surfaces, input))
    ) {
      continue // temp-confined forced deletes carry their own exemption
    }
    return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
  }
  if (!ruleBypassed("data.critical-delete", bypassed) && hasCriticalDataDestruction(combined, input.shell)) {
    return {
      verdict: "DENY",
      rules: ["data.critical-delete"],
      reason:
        strictness === "HARD"
          ? `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`
          : "Attempts to delete credential or key material",
    }
  }
  for (const surface of surfaces) {
    const finding = sensitivePathFinding(surface, ctx)
    if (finding && !ruleBypassed(finding.rule, bypassed)) {
      return {
        verdict: finding.kind === "deny" ? "DENY" : "ASK",
        rules: [finding.rule],
        reason: finding.reason,
      }
    }
  }
  if (!ruleBypassed("operation.context-required.network", bypassed) && NETWORK_CLIENT_WORD.test(combined)) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a network operation requiring review",
    }
  }
  // Privilege launchers and boundary mutators follow the privilege category;
  // process killers keep the host/process category. The launcher scan runs
  // only over executable surfaces (the segment, its decoded/quoted wrapper
  // payloads, executed heredoc bodies, substitution bodies) — never over
  // plain argument text.
  if (
    !ruleBypassed("operation.context-required.privilege", bypassed) &&
    privilegeExecutableSurfaces(segment).some((surface) => hasPrivilegeBoundaryAtCommandPosition(surface, input.shell))
  ) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a privilege operation requiring review",
    }
  }
  if (!ruleBypassed("operation.context-required.process", bypassed) && /\b(?:taskkill|pkill|killall|stop-process)\b/i.test(combined)) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a process operation requiring review",
    }
  }
  return undefined
}

function kernelEnforcedAllow(): SegmentDecision {
  return {
    verdict: "ALLOW",
    rules: ["operation.kernel-enforced"],
    reason: "Read-only is enforced by the kernel sandbox for this command",
  }
}

/** Whether an RO write/mutator/unproven denial can be lifted for this call:
 *  the scratch carve-out first (all modes), then the kernel pass-through
 *  (LOOSE + roKernelEnforced only). Returns the replacement decision, or
 *  undefined when the caller's static deny stands. */
async function roWriteGateBypass(
  segment: string,
  roView: string,
  base: string,
  input: InternalClassifyInput,
  strictness: Strictness,
  kind: "write" | "unproven" | undefined,
): Promise<SegmentDecision | undefined> {
  const carved = await roScratchCarveOut(segment, roView, base, input, kind)
  if (carved?.decision) return carved.decision
  if (carved?.frozen) {
    // A configured sandbox.denyWrite freeze overrides the scratch carve-out
    // in every mode — including kernel-enforced (the freeze is a declared
    // deny the kernel may not even see, e.g. mode auto/fail_open).
    return {
      verdict: "DENY",
      rules: ["filesystem.deny-write"],
      reason: "The write target is frozen by a configured sandbox.denyWrite entry",
    }
  }
  if (!input.roKernelEnforced || strictness === "HARD") return undefined
  return (await roNonWriteGate(segment, base, input, strictness)) ?? kernelEnforcedAllow()
}

/** Read-path scan for a proven-read invocation under RO: every non-flag
 *  operand (including flag values, which carry paths for flags like `git -C`
 *  or `ssh-keygen -f`) is classified as a read target so a sensitive operand
 *  — `zcat ~/.ssh/x.gz`, `dd if=/dev/sda`, `git -C ~ status` — cannot ride the
 *  static allow. Only ask/deny findings are returned; a fully clean scan is
 *  `undefined`. */
function readOnlyReadFinding(args: string[], ctx: PathContext): PathFinding | undefined {
  let finding: PathFinding | undefined
  let postDashDash = false
  for (const raw of args) {
    const token = stripMatchingQuotes(raw)
    if (!postDashDash) {
      if (token === "--") {
        postDashDash = true
        continue
      }
      if (token.startsWith("-")) continue
    }
    const next = classifyPathTarget(token, "read", ctx)
    if (next.kind === "deny") return next
    if (next.kind === "ask") finding = next
  }
  return finding
}

const READ_ONLY_AUTH_HINT =
  "ask the user to grant write access (/perm +w or /perm rw) and retry afterward"
const READ_ONLY_EXECUTION_DENY_REASON =
  "Read-only session: executing scripts, encoded payloads, or interop binaries is blocked pending user authorization — " +
  READ_ONLY_AUTH_HINT
const READ_ONLY_UNPROVEN_DENY_REASON =
  "Read-only session: the command cannot be proven free of filesystem side effects — blocked pending user authorization, " +
  READ_ONLY_AUTH_HINT

function readOnlyWriteDeny(): SegmentDecision {
  return {
    verdict: "DENY",
    rules: ["permission.write"],
    reason:
      "File writes and deletions are blocked in this read-only session — " + READ_ONLY_AUTH_HINT,
  }
}

function readOnlyExecutionDeny(reason = READ_ONLY_EXECUTION_DENY_REASON): SegmentDecision {
  return { verdict: "DENY", rules: ["permission.write"], reason }
}

/**
 * Execution channels a read-only session cannot statically prove read-only:
 * local script execution (execution.local-script), encoded payloads
 * (execution.encoded-shell), and dynamic execution wrappers
 * (execution.wrapper — eval/interpreter -c, $(...) expansion, decoded blobs).
 * `combined` is the segment's executable surfaces (raw + decoded + quoted
 * wrappers) joined with newlines, matching the late ASK detectors.
 */
function readOnlyExecutionChannel(segment: string, combined: string, shell: string): boolean {
  if (localScriptCandidates(segment, shell).length > 0) return true
  if (WRAPPER_PRIMITIVE.test(combined)) return true
  if (hasDynamicShellExpansion(combined, shell)) return true
  // A decoded blob is an execution channel only when the pipeline provably
  // feeds it to an interpreter; `| base64 -d > f` stores payload text.
  if (extractDecodedPayloads(segment, { executedOnly: true }).length > 0) return true
  // A heredoc whose consumer is code (shell/lang/remote/db) executes its body.
  const heredocs = parseHeredocs(segment)
  if (heredocs.some((h) => heredocConsumer(h) !== "data")) return true
  return false
}

async function classifySegment(
  segment: string,
  base: string,
  input: InternalClassifyInput,
  depth = 0,
): Promise<SegmentDecision> {
  const segInput: InternalClassifyInput = { ...input, script: segment, cwd: base }
  const strictness: Strictness = input.strictness ?? "LOOSE"
  const bypassed = input.bypassedCategories

  // Session permission ceiling (r/w MVP): no `w` denies write/delete-shaped
  // segments — the command-shape fallback that keeps read-only shell usable
  // under RO while blocking every write vector visible here. `x` is reserved
  // and intentionally not enforced (the evaluate hook no longer maps shell
  // to it); the kernel sandbox is the eventual hard write boundary.
  //
  // Under RO an executable-position interop spawn (.exe/.bat/.cmd/.ps1 or
  // wsl/wslpath/pwsh/powershell/cmd) is no longer blanket-denied: the payload
  // is classified by command semantics — proven reads allow, write shapes
  // deny as permission.write, and spawn/opaque payloads review under LOOSE
  // (the dynamic reviewer carries the RO advisory) while HARD keeps the
  // static execution deny. This check is unconditional — bypass categories
  // only relax rules, never permissions, so bypass:os/dynamic must not and
  // cannot relax it (any DENY wins).
  const permScope = input.permScope
  if (permScope) {
    if (!permScope.w) {
      // Write shapes are judged on a data-aware view: quoted string literals
      // are inert arguments to read-class consumers, so their contents are
      // masked before the raw write-vocabulary scans (a quoted "Set-Content"
      // in an echo/grep/printf argument is text, not a write). Quoted payloads
      // in EXECUTOR position (`bash -c`, `pwsh -Command`, `python3 -c`, ...)
      // are code, not data — extractQuotedWrappers re-surfaces them and they
      // are scanned raw so the write-shape denial still fires first.
      const roView = maskQuotedLiteralContents(maskHeredocDataBodies(segment, input.shell))
      const roStripped = stripHarmlessPrefixes(segment)
      // Interop payload semantics replace the blanket interop deny. It runs
      // before the mutation gate so `python.exe -c "print(42)"` — whose leaf
      // is otherwise an unproven interpreter — reaches the payload classifier
      // instead of an unconditional deny. Segments whose executable is not
      // interop fall through unchanged.
      const interopDecision = readOnlyInteropDecision(roStripped, roView, input, strictness)
      if (interopDecision) return interopDecision
      // Invocation-aware mutation gate: recognized mutating commands (package
      // installs, builds, cleans, git worktree/ref changes, archive/system
      // writers, delete invocations at executable position incl. `sudo rm`,
      // find -delete/-exec/xargs consumers) are unconditional RO denials —
      // before every ALLOW/ASK producer below and independent of bypass
      // categories. Unrecognized executors stay unproven-execution denials.
      // It runs before the generic write-shape scan so recognized read modes
      // (`unzip -l`, `gunzip -c`, `tar -t`) are not mis-denied by the
      // unconditional archive-extraction targets extractWriteTargets emits.
      // Proven read surfaces ("read") earn their static allow after the
      // write-shape denials below, once hygiene and the operand read-path
      // scan pass. (Interop executables never reach here — the payload
      // classifier above already adjudicated them.)
      const roMutation = readOnlyMutatingInvocation(roStripped)
      if (roMutation === "execute") {
        // Executor invocations (`rg --pre`, `git grep -O`, the sed `e`
        // family) run a child that can read or reach the network — the
        // kernel's write containment is not enough, so RO never authorizes
        // them. The floor/credential scan still runs first.
        const floors = await roNonWriteGate(segment, base, segInput, strictness)
        if (floors) return floors
        return readOnlyExecutionDeny()
      }
      if (roMutation === "write" || roMutation === "unproven") {
        // Scratch carve-out first (/tmp mutations exempt in every mode), then
        // the kernel pass-through (LOOSE + roKernelEnforced): the kernel
        // denies the write syscalls, so the static gate defers to it. All
        // other cases keep the unconditional permission.write deny.
        const bypass = await roWriteGateBypass(segment, roView, base, segInput, strictness, roMutation)
        if (bypass) return bypass
        return roMutation === "write"
          ? readOnlyWriteDeny()
          : readOnlyExecutionDeny(READ_ONLY_UNPROVEN_DENY_REASON)
      }
      const writeShaped =
        hasFileWritePrimitive(roView) ||
        // Redirect targets are real writes even on read-class commands
        // (`ls 2>f`); the full extractWriteTargets set additionally carries
        // synthetic targets a read-mode vocab emits (unzip -d, tar -f).
        extractRedirectTargets(roView).targets.length > 0 ||
        (roMutation !== "read" && extractWriteTargets(roView).targets.length > 0) ||
        extractQuotedWrappers(segment).some(
          (payload) =>
            hasFileWritePrimitive(payload) || extractWriteTargets(payload).targets.length > 0,
        )
      if (writeShaped || explicitRecycleBinOperation(segment, input.shell) !== undefined) {
        const bypass = await roWriteGateBypass(segment, roView, base, segInput, strictness, roMutation)
        if (bypass) return bypass
        return readOnlyWriteDeny()
      }
      // A proven read-only invocation (read surface of a tool whose write
      // forms are denied above: `git -C dir status`, `npm ls`, `unzip -l`,
      // `zcat`, `find` without write primaries, …) earns a static allow only
      // with the same hygiene the provably-safe path applies — no dynamic or
      // unquoted expansion, no sensitive env prefix — and a clean read-path
      // scan of every operand. Privileged launches (`sudo git status`) were
      // left on the normal path by the predicate and never reach this allow.
      const roBenignHolder: { v: string } = { v: "" }
      const roBenign =
        benignDynamicSurface(segment, roBenignHolder) &&
        !hasUnquotedExpansion(roBenignHolder.v, input.shell)
      // LOOSE tolerates glob operands on read surfaces (`wc -c *`, `cat *.ts`):
      // the shell expands them to local filenames a read command consumes.
      // HARD keeps the strict hygiene.
      const roAllowGlobs = strictness === "LOOSE"
      if (
        roMutation === "read" &&
        (roBenign ||
          (!hasDynamicShellExpansion(segment, input.shell) &&
            !hasUnquotedExpansion(maskHeredocDataBodies(segment, input.shell), input.shell, roAllowGlobs))) &&
        !hasSensitiveEnvPrefix(segment)
      ) {
        // Benign substitutions are masked for the path scans: the literal
        // text around them still drives sensitivity detection, while the
        // dynamic island (`$(pwd)`, `$(date)`) doesn't poison the parse.
        const scanSegment = roBenign ? roBenignHolder.v : segment
        const roPathCtx: PathContext = { cwd: base, worktree: input.worktree, strictness }
        const roFinding = analyzeSegmentPaths(scanSegment, roPathCtx)
        if (roFinding.kind === "pass") {
          const operandFinding = readOnlyReadFinding(executableInvocation(scanSegment).args, roPathCtx)
          if (operandFinding && !ruleBypassed(operandFinding.rule, bypassed)) {
            return {
              verdict: operandFinding.kind === "deny" ? "DENY" : "ASK",
              rules: [operandFinding.rule],
              reason: operandFinding.reason,
            }
          }
          return {
            verdict: "ALLOW",
            rules: ["operation.read-only"],
            reason: "The segment is a proven read-only invocation",
          }
        }
        if (!ruleBypassed(roFinding.rule, bypassed)) {
          return {
            verdict: roFinding.kind === "deny" ? "DENY" : "ASK",
            rules: [roFinding.rule],
            reason: roFinding.reason,
          }
        }
      }
    }
  }

  if (segment.trim().startsWith("#")) {
    return {
      verdict: "ALLOW",
      rules: ["operation.comment"],
      reason: "The segment is a shell comment",
    }
  }

  if (isPowerShellRecycleSetup(segment)) {
    return {
      verdict: "ALLOW",
      rules: ["filesystem.recycle-bin-setup"],
      reason: "Loads the operating-system recycle-bin API",
    }
  }

  if (hasForbiddenRecycleDestruction(segment)) {
    // Recycle-bin permanent deletion follows the filesystem bypass category.
    if (!ruleBypassed("filesystem.recycle-bin-permanent-delete", bypassed)) {
      return {
        verdict: "DENY",
        rules: ["filesystem.recycle-bin-permanent-delete"],
        reason: "Permanently deleting recycle-bin contents is blocked by filesystem policy because it bypasses recovery",
      }
    }
  }

  const recycle = explicitRecycleBinOperation(segment, input.shell)
  if (recycle && !ruleBypassed("filesystem.recycle-bin", bypassed)) {
    const recycleFinding = await recycleTargetsFinding(recycle.targets, base, segInput, strictness)
    if (recycleFinding && !recycleFinding.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      return recycleFinding
    }
    if (strictness === "HARD") {
      const tempRoots = await trustedUserLocalTempRoots(segInput)
      for (const target of recycle.targets) {
        const literal = literalPathToken(target)
        const protectedTarget = Boolean(
          literal && (backupPathIdentity(literal) || hasNamedTempPathSegment(literal)),
        )
        const inLocalTemp = tempRoots.length > 0 && await isTrustedTempPath(target, base, tempRoots)
        if ((protectedTarget || inLocalTemp) && !ruleBypassed("filesystem.protected-target-delete", bypassed)) {
          return {
            verdict: "DENY",
            rules: ["filesystem.protected-target-delete"],
            reason: `Removing a protected temporary or backup target is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
          }
        }
      }
      if (recycle.targets.some(isCriticalDeletionTarget) && !ruleBypassed("data.critical-delete", bypassed)) {
        return {
          verdict: "DENY",
          rules: ["data.critical-delete"],
          reason: `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      if (recycle.targets.some(isGeneralDataTarget) && !ruleBypassed("data.destructive-delete", bypassed)) {
        return {
          verdict: "DENY",
          rules: ["data.destructive-delete"],
          reason: `Attempts to delete a durable structured data file. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      return {
        verdict: "ALLOW",
        rules: ["filesystem.recycle-bin"],
        reason: "Moves items to the recoverable operating-system recycle bin",
      }
    }
    return {
      verdict: "ALLOW",
      rules: ["filesystem.recycle-bin"],
      reason: "Moves items to the recoverable operating-system recycle bin",
    }
  }


  const stripped = stripHarmlessPrefixes(segment)
  if (stripped && stripped !== segment.trim()) {
    return classifySegment(stripped, base, input, depth)
  }

  // Heredoc segments: the body's role is decided by the consumer (inert write,
  // local/remote code, database shell). Code-consumer bodies are classified
  // recursively; quoted inert bodies are masked out of the text scans below.
  const heredocDecision = await classifyHeredocSegment(segment, base, segInput, depth)
  if (heredocDecision) {
    return heredocDecision
  }

  if (strictness === "HARD") {
    // Deletion/backup policies gate their individual DENY verdicts with
    // ruleBypassed (filesystem vs secret categories differ per rule).
    const hardDecision = await classifyHardDeletionPolicy(segment, segInput)
    if (hardDecision && !hardDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      return { verdict: hardDecision.verdict, rules: hardDecision.rules, reason: hardDecision.reason }
    }
    const backupDecision = await classifyBackupPolicy(segment, segInput)
    if (backupDecision && !backupDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      if (backupDecision.verdict === "ALLOW" && backupDecision.rules.includes("filesystem.backup-delete")) {
        return {
          verdict: "DENY",
          rules: ["hard.backup-delete"],
          reason: `Permanent deletion of backup targets is blocked by filesystem policy. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      return { verdict: backupDecision.verdict, rules: backupDecision.rules, reason: backupDecision.reason }
    }
  } else {
    if (!segInput.cwdUnknown) {
      const namedTempDecision = await classifyNamedTempDeletionPolicy(segment, segInput)
      if (namedTempDecision && !namedTempDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
        return { verdict: namedTempDecision.verdict, rules: namedTempDecision.rules, reason: namedTempDecision.reason }
      }

      const userLocalTempDecision = await classifyUserLocalTempSegment(segment, segInput)
      if (
        userLocalTempDecision &&
        !userLocalTempDecision.rules.every((rule) => ruleBypassed(rule, bypassed))
      ) {
        return {
          verdict: userLocalTempDecision.verdict,
          rules: userLocalTempDecision.rules,
          reason: userLocalTempDecision.reason,
        }
      }
      const backupDecision = await classifyBackupPolicy(segment, segInput)
      if (backupDecision && !backupDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
        return { verdict: backupDecision.verdict, rules: backupDecision.rules, reason: backupDecision.reason }
      }
    }
  }

  // "All targets confined" exemption (fix B): every write/delete/extract
  // target of this segment is canonically inside a trusted temp root — the
  // write-family asks (outside-write, tar-extract, unverified base) no longer
  // break the safe path for work staged under /tmp after a `cd`.
  if (!segInput.cwdUnknown) {
    const confinedDecision = await classifyTempConfinedSegment(segment, base, segInput)
    if (confinedDecision && !confinedDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      return { verdict: confinedDecision.verdict, rules: confinedDecision.rules, reason: confinedDecision.reason }
    }
  }

  const wslPayload = segment.match(/^wsl(?:\.exe)?\s+--\s+([\s\S]+)$/i)
  if (wslPayload && (wslPayload[1] ?? "").trim()) {
    const payload = wslPayload[1] ?? ""
    const strippedPayload = stripOutputRedirects(payload) ?? payload
    if (
      isKnownSafeSegment(strippedPayload) &&
      !hasDynamicShellExpansion(payload, input.shell) &&
      !hasUnquotedExpansion(maskHeredocDataBodies(payload, input.shell), input.shell) &&
      !hasSensitiveEnvPrefix(payload) &&
      analyzeSegmentPaths(payload, { cwd: base, worktree: input.worktree, strictness }).kind === "pass"
    ) {
      return {
        verdict: "ALLOW",
        rules: ["operation.wsl-safe"],
        reason: "The WSL payload is a recognized safe operation",
      }
    }
  }

  // ---- M3 (P2) §4.9: dedicated safe surfaces -----------------------------
  const m3ctx: PathContext = { cwd: base, worktree: input.worktree, strictness }

  const tarOrUnzip = classifyTarExtractOrUnzip(segment, m3ctx, strictness, /^unzip\b/i.test(segment))
  if (tarOrUnzip && !tarOrUnzip.rules.every((rule) => ruleBypassed(rule, bypassed))) return tarOrUnzip

  if ((/^curl\b/i.test(segment) || /^wget\b/i.test(segment)) && strictness === "LOOSE" && !input.cwdUnknown) {
    if (isSafeDownloadTarget(segment, m3ctx)) {
      return {
        verdict: "ALLOW",
        rules: ["operation.download"],
        reason: "Downloads a file into the working tree from an HTTPS URL",
      }
    }
  } else if (/^python(?:3)?(?:\.exe)?\s+-m\s+http\.server\b/i.test(segment) && !input.cwdUnknown) {
    if (strictness === "LOOSE" && !hasDynamicShellExpansion(segment, input.shell)) {
      return { verdict: "ALLOW", rules: ["operation.dev-server"], reason: "Serves a local development HTTP server" }
    }
    return { verdict: "ASK", rules: ["operation.context-required"], reason: "Starting a local development server requires review" }
  } else if (/^ssh-keygen\b/i.test(segment) && strictness === "LOOSE" && !input.cwdUnknown) {
    if (!/\s-y\b|--print/.test(segment) && /\s-N\s+['""]['""]/.test(segment) && !hasDynamicShellExpansion(segment, input.shell)) {
      return { verdict: "ALLOW", rules: ["operation.keygen"], reason: "Generates a new SSH key pair locally" }
    }
  }

  const safeChmod = classifySafeChmod(segment, m3ctx, strictness)
  if (safeChmod) return safeChmod

  // `[ ... ]` / `test` literal test expressions (framing brackets are not globs here)
  const bracketMatch = segment.match(/^\[\s+([\s\S]*?)\s*\]\s*$/) ?? ( /^test\b/i.test(segment) ? [null, segment.replace(/^test\b/i, "").trim()] : null )
  if (bracketMatch && !input.cwdUnknown) {
    const inner = bracketMatch[1] ?? ""
    if (commandSubstitutionBodies(segment).length === 0 && !hasUnquotedExpansion(inner, input.shell)) {
      return { verdict: "ALLOW", rules: ["operation.test-expression"], reason: "Evaluates a literal shell test expression" }
    }
  }

  // Command substitution whose inner reads are entirely safe: `echo $(date)` etc.
  const substitutionBodies = commandSubstitutionBodies(segment)
  if (
    substitutionBodies.length > 0 &&
    !input.cwdUnknown &&
    isSafeSubstitutionSurface(segment, input.shell, m3ctx)
  ) {
    const maskedOuter = maskCommandSubstitutions(segment)
    const substitutionFinding = analyzeSegmentPaths(maskedOuter, m3ctx)
    if (substitutionFinding.kind === "pass") {
      return {
        verdict: "ALLOW",
        rules: ["operation.command-substitution"],
        reason: "Command substitution contains only recognized safe operations",
      }
    }
  }

  // Fix D: for proven eligible commands (bare grep-family, non-preprocessor
  // rg, git commit -m values), proven-inert quoted data spans are blanked in
  // the rule-scan surface and every derived surface is generated from that
  // masked view, so literal data can neither trip destructive rules nor be
  // re-raised as executable text by the payload extractors. Executor
  // eligibility was already decided on the raw segment above; path/write
  // checks keep the real arguments.
  const ruleSurface = dataLiteralView(segment) ?? segment
  const ansiSurfaces = decodeAnsiCContent(ruleSurface)
  const varSurface = substituteDeleteVars(ruleSurface)
  const quoteSurface = quoteStrippedDeleteSurface(ruleSurface)
  // Statically-known executor payloads (`sed 'e <cmd>'`, `rg --pre <cmd>`,
  // `git grep -O<cmd>`) join the scan surfaces so a destructive child command
  // is denied, not merely reviewed.
  const executorHazard = executorCapabilityHazard(segment)
  const surfaces = [
    ruleSurface,
    // Decoded payloads join the rule scan only when the pipeline provably
    // executes them (`| base64 -d | sh`). A decoded blob that is merely
    // stored (`| base64 -d > f`) is payload text — the dynamic reviewer
    // sees it through the encoded-payload ASK, not a floor DENY.
    ...extractDecodedPayloads(ruleSurface, { executedOnly: true }),
    // Language `-c`/`-e` payloads scan as their execution-sink view, not raw
    // program text: string literals inside them are data.
    ...ruleScanWrappers(ruleSurface),
    ...ansiSurfaces,
    ...(varSurface ? [varSurface] : []),
    ...(quoteSurface ? [quoteSurface] : []),
    ...(executorHazard?.kind === "executor" ? executorHazard.payloads : []),
  ]
  const combined = surfaces
    .flatMap((surface) => {
      const view = payloadRuleView(surface, input.shell)
      return [...view.segments, ...view.sinks]
    })
    .map((surface) => maskHeredocDataBodies(surface, input.shell))
    .join("\n\n")
  const reviewSignals = new Map<string, string>()
  // A quote-stripped variant of THIS same segment (`Remove-Item -LiteralPath
  // ".\dist" -Recurse -Force` unquotes to the identical delete invocation) is
  // not an evasion surface, so it must not suppress disposable-cleanup
  // recognition. Any other extra surface (decoded payload, wrapped payload,
  // ANSI, variable substitution) still denies the exemption.
  const quoteSurfaceOfThisSegment = quoteStrippedDeleteSurface(ruleSurface)
  const onlyInnocentSurfaces =
    surfaces.length === 1 ||
    (surfaces.length === 2 && quoteSurfaceOfThisSegment !== undefined && surfaces[1] === quoteSurfaceOfThisSegment)
  const explicitDisposableCleanup =
    (await isExplicitDisposableCleanup(segment, base, input.worktree)) && onlyInnocentSurfaces
  // Temp-confined forced deletes also exempt the definite floor signal — the
  // HARD-side equivalent of the `hard.forced-recursive-delete` path check.
  const forcedDeletesConfined =
    hasForcedRecursiveDelete(combined) && (await forcedDeletesConfinedToTemp(surfaces, segInput))

  const knownSafe = isKnownSafeSegment(stripOutputRedirects(segment) ?? segment)
  // Expansion detection runs on the rule surface: for an eligible command
  // the literal lexer already proved no expansion exists, so an inert `$'…'`
  // data literal cannot defeat the benign-part check (spec D.6).
  const hasExpansion = hasDynamicShellExpansion(ruleSurface, input.shell)
  // Benign dynamic parts ($(date), $PWD, …) are deterministic and local: they
  // don't disqualify a known-safe segment. Everything else dynamic keeps the
  // review path.
  const benignHolder: { v: string } = { v: "" }
  const benignDynamic =
    benignDynamicSurface(segment, benignHolder) &&
    !hasUnquotedExpansion(benignHolder.v, input.shell)
  const provablySafe =
    knownSafe &&
    (!hasExpansion || benignDynamic) &&
    (benignDynamic || !hasUnquotedExpansion(maskHeredocDataBodies(ruleSurface, input.shell), input.shell)) &&
    !hasSensitiveEnvPrefix(segment)

  // Kernel-trigger / core_pattern writs must not be masked by the
  // provably-safe early allow (e.g. `echo '|/bin/evil' > /proc/sys/kernel/core_pattern`).
  // Other DEFINITE rules keep running after EXIT-1 so that harmless echo/printf of
  // delete strings (`echo 'rm -rf /'`) are not misclassified as deletions.
  // Kernel primitives are floor rules: never bypassable.
  for (const ruleId of ["filesystem.kernel-trigger", "filesystem.kernel-core-pattern"]) {
    const rule = SECURITY_SIGNAL_RULES.find((entry) => entry.id === ruleId)
    if (rule && rule.test(combined)) {
      return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
    }
  }

  const expandedRead = await expandSafeReadGlobs(segment, segInput)
  if (expandedRead) return classifySegment(expandedRead, base, segInput)

  if (provablySafe) {
    const finding = analyzeSegmentPaths(benignDynamic ? benignHolder.v : segment, { cwd: base, worktree: input.worktree, strictness })
    if (finding.kind === "pass") {
      // Durable-data in-place overwrite must not ride the provably-safe early
      // allow (`sed -i` on .csv/.json/db/sqlite/xlsx/parquet).
      if (!ruleBypassed("data.destructive-overwrite", bypassed) && hasDestructiveOverwrite(segment)) {
        return {
          verdict: "ASK",
          rules: ["data.destructive-overwrite"],
          reason: "Attempts in-place destructive modification of durable structured data",
        }
      }
      return {
        verdict: "ALLOW",
        rules: ["operation.known-safe"],
        reason: "The segment is a recognized read-only or normal low-risk development action",
      }
    }
    if (!ruleBypassed(finding.rule, bypassed)) {
      return {
        verdict: finding.kind === "deny" ? "DENY" : "ASK",
        rules: [finding.rule],
        reason: finding.reason,
      }
    }
  }

  // Read-only execution channels: under RO, anything the classifier cannot
  // prove read-only is denied here rather than deferred to the dynamic
  // reviewer. This runs before every ASK producer below and ignores bypass
  // categories (permissions are orthogonal to bypass; any DENY wins). It sits
  // after the provably-safe early allow so known-safe reads (`ls`, `cat`,
  // `echo $(date)`) and pure-data heredocs stay allowed.
  //
  // Kernel pass-through: under LOOSE with roKernelEnforced the kernel denies
  // the write syscalls this channel could issue, so the channel passes
  // through once the non-write gate (floors/credentials/network/sudo inside
  // every surface incl. the payload) is clean. HARD and kernel-absent RO
  // keep the static deny.
  if (
    permScope &&
    !permScope.w &&
    readOnlyExecutionChannel(segment, combined, input.shell)
  ) {
    if (input.roKernelEnforced && strictness !== "HARD") {
      return (await roNonWriteGate(segment, base, segInput, strictness)) ?? kernelEnforcedAllow()
    }
    return readOnlyExecutionDeny()
  }

  for (const rule of SECURITY_SIGNAL_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(combined)) {
      if (DEFINITE_DESTRUCTIVE_RULES.has(rule.id)) {
        if (
          rule.id === "filesystem.forced-recursive-delete" &&
          (forcedDeletesConfined || (explicitDisposableCleanup && strictness !== "HARD"))
        ) {
          continue
        }
        return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
      }
      reviewSignals.set(rule.id, rule.reason)
    }
  }

  const compressionFinding = compressionDestructionFinding(segment, {
    cwd: base,
    worktree: input.worktree,
    strictness,
  })
  if (compressionFinding && !compressionFinding.rules.every((rule) => ruleBypassed(rule, bypassed))) {
    return { verdict: compressionFinding.verdict, rules: compressionFinding.rules, reason: compressionFinding.reason }
  }

  // Credential/key-material data rules belong to the secret category: arming
  // `secret` clears them; arming `filesystem` alone must not.
  if (!ruleBypassed("data.critical-delete", bypassed) && hasCriticalDataDestruction(combined, input.shell)) {
    return {
      verdict: "DENY",
      rules: ["data.critical-delete"],
      reason: strictness === "HARD"
        ? `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`
        : "Attempts to delete credential or key material",
    }
  }
  if (!ruleBypassed("data.destructive-delete", bypassed) && hasGeneralDataDestruction(combined)) {
    if (strictness === "HARD") {
      return {
        verdict: "DENY",
        rules: ["data.destructive-delete"],
        reason: `Attempts to permanently delete a durable structured data file. ${PERMANENT_DELETE_GUIDANCE}`,
      }
    }
    reviewSignals.set(
      "data.destructive-delete",
      "Attempts to delete user data or durable structured files and requires review",
    )
  }
  if (!ruleBypassed("data.destructive-overwrite", bypassed) && hasDestructiveOverwrite(combined)) {
    reviewSignals.set(
      "data.destructive-overwrite",
      "Attempts in-place destructive modification of durable structured data",
    )
  }
  const sensitivePath = sensitivePathFinding(segment, { cwd: base, worktree: input.worktree, strictness })
  if (sensitivePath && sensitivePath.kind !== "pass") {
    if (!ruleBypassed(sensitivePath.rule, bypassed)) {
      return {
        verdict: sensitivePath.kind === "deny" ? "DENY" : "ASK",
        rules: [sensitivePath.rule],
        reason: sensitivePath.reason,
      }
    }
  }

  const exfilRule = hasExfilOrDangerousPerms(segment, combined, {
    cwd: base,
    worktree: input.worktree,
    strictness,
  })
  if (exfilRule && !ruleBypassed(exfilRule, bypassed)) {
    const reason = exfilRule === "permissions.sensitive-mode"
      ? "Setting dangerous permissions on a credential or system file requires review"
      : "Sending credential or system data off-host requires review"
    if (strictness === "HARD") {
      return { verdict: "DENY", rules: [exfilRule], reason }
    }
    reviewSignals.set(exfilRule, reason)
  }

  for (const rule of HARD_DENY_LOOSE_ASK_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(combined)) {
      if (strictness === "HARD") {
        return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
      }
      reviewSignals.set(rule.id, rule.reason)
    }
  }

  if (explicitDisposableCleanup && strictness !== "HARD") {
    // Same guardrail as the named-temp path: when the base was claimed by a
    // `cd` that is not guaranteed to have run, only a canonically
    // temp-confined base may carry the exemption.
    if (input.baseUnverified === true && !(await baseInsideTempRoot(base, segInput))) {
      return {
        verdict: "ASK",
        rules: ["filesystem.temp-context-delete"],
        reason:
          "Deletion runs after a `cd` that is not guaranteed to have taken effect, and the claimed base is not a verified temp directory",
      }
    }
    return {
      verdict: "ALLOW",
      rules: ["cleanup.disposable"],
      reason: "Cleanup is narrowly scoped to a recognized disposable cache, dependency, build, or temporary target",
    }
  }
  if (reviewSignals.size > 0) {
    return {
      verdict: "ASK",
      rules: [...reviewSignals.keys()],
      reason: [...reviewSignals.values()][0] ?? "The command contains a security-sensitive operation requiring review",
    }
  }

  // Under a kernel-enforced RO session (LOOSE) the write/execution ASK
  // producers below are suppressed: their question — can this command
  // write/execute? — is answered by the kernel itself. Non-write producers
  // (context triggers, review signals, sensitive paths) ran above and keep
  // their verdicts.
  const roKernelPassthrough = Boolean(permScope && !permScope.w && input.roKernelEnforced && strictness !== "HARD")

  // Privilege launchers gate before the generic wrapper/indirection ask:
  // `sh -c 'doas id'` is a privilege question first — arming `privilege`
  // moves it on to the wrapper review instead of silently clearing it.
  // Launcher words count only at command position on executable surfaces.
  if (
    !ruleBypassed("operation.context-required.privilege", bypassed) &&
    privilegeExecutableSurfaces(segment).some((surface) => hasPrivilegeBoundaryAtCommandPosition(surface, input.shell))
  ) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a privilege operation requiring review",
    }
  }

  if (localScriptCandidates(segment, input.shell).length > 0 && !ruleBypassed("execution.local-script", bypassed)) {
    if (roKernelPassthrough) return kernelEnforcedAllow()
    return {
      verdict: "ASK",
      rules: ["execution.local-script"],
      reason: "The command executes a local script and requires contextual review",
    }
  }

  if (!ruleBypassed("execution.wrapper", bypassed) && WRAPPER_PRIMITIVE.test(combined)) {
    if (roKernelPassthrough) return kernelEnforcedAllow()
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command uses an interpreter, encoded payload, or dynamic execution wrapper",
    }
  }
  if (!ruleBypassed("execution.wrapper", bypassed) && hasDynamicShellExpansion(combined, input.shell)) {
    if (roKernelPassthrough) return kernelEnforcedAllow()
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command uses dynamic shell expansion and cannot be proven safe",
    }
  }
  if (!ruleBypassed("execution.wrapper", bypassed) && extractDecodedPayloads(segment).length > 0) {
    if (roKernelPassthrough) return kernelEnforcedAllow()
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command carries an encoded payload that requires review",
    }
  }

  if (!ruleBypassed("filesystem.scoped-delete", bypassed) && hasDeletePrimitive(combined)) {
    if (roKernelPassthrough) return kernelEnforcedAllow()
    return {
      verdict: "ASK",
      rules: ["filesystem.scoped-delete"],
      reason: "The command deletes files but is not an obvious broad or durable-data deletion",
    }
  }

  // Composite context-required check: each trigger family follows the category
  // of its primitive so an armed category actually clears its family. Network
  // clients are matched as command words only — a bare `\bssh\b` would also hit
  // paths like `~/.ssh/id_rsa` and wrongly defeat a secret bypass.
  const combinedWithoutFdMerges = combined
    .replace(INERT_OUTPUT_REDIRECT, "")
    .replace(/\d*>&\d+/g, "")
    .replace(/\d*>&-/g, "")
    .replace(/>&(?=\s*[\d-])/g, "")
  const killTrigger = !ruleBypassed("operation.context-required.process", bypassed) && /\b(?:kill|pkill|killall|taskkill|stop-process)\b/i.test(combined)
  const networkTrigger = !ruleBypassed("operation.context-required.network", bypassed) && NETWORK_CLIENT_WORD.test(combined)
  // The overwrite trigger is a write question — under kernel-enforced RO it
  // is suppressed (the kernel denies the redirect target's write); the
  // other trigger families are kernel-invisible and keep their review.
  const overwriteTrigger =
    !ruleBypassed("operation.context-required.overwrite", bypassed) && !roKernelPassthrough && /(?:^|[^>])>(?!>)/m.test(combinedWithoutFdMerges)
  if (killTrigger || networkTrigger || overwriteTrigger) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a process, network, or overwrite operation requiring review",
    }
  }

  // With any trigger-family category armed, the surviving fallback describes
  // itself as bypass-gated: the armed BYPASS RULE lets the dynamic reviewer
  // decide consistently instead of reading "unprovable" as high-risk.
  // Under a read-only session the unproven fallback is a write question:
  // kernel-enforced LOOSE passes it through (every non-write scan above has
  // already run clean at this point); HARD and kernel-absent RO keep the
  // static deny (permissions outrank bypass).
  if (permScope && !permScope.w) {
    if (roKernelPassthrough) return kernelEnforcedAllow()
    return readOnlyExecutionDeny(READ_ONLY_UNPROVEN_DENY_REASON)
  }
  if (
    bypassed &&
    STATIC_BYPASS_CATEGORIES.some((category) => bypassed.has(category))
  ) {
    return {
      verdict: "ASK",
      rules: ["bypass.static-allow"],
      reason: "Static checks are disabled for this command's categories by a user-armed bypass",
    }
  }
  return {
    verdict: "ASK",
    rules: ["operation.unknown"],
    reason: "The local classifier cannot prove the complete command safe",
  }
}

async function classifySegments(
  script: string,
  input: InternalClassifyInput,
  depth = 0,
): Promise<SegmentDecision> {
  if (depth > MAX_WRAPPER_DEPTH) {
    if (input.permScope && !input.permScope.w) {
      if (input.roKernelEnforced && (input.strictness ?? "LOOSE") !== "HARD") {
        return (await roNonWriteGate(script, path.resolve(input.cwd), input, input.strictness ?? "LOOSE")) ?? kernelEnforcedAllow()
      }
      return readOnlyExecutionDeny()
    }
    return { verdict: "ASK", rules: ["execution.wrapper"], reason: "Command wrappers exceed the review depth limit" }
  }

  // Cross-segment variable tracking: in `D=rm; $D -rf x` neither segment alone
  // carries the delete shape (the assignment and the usage split apart), so
  // classify the substituted surface as well and keep the worse verdict.
  const varSurface = depth === 0 ? substituteDeleteVars(script) : undefined
  const substituted =
    varSurface && varSurface !== script ? await classifySegments(varSurface, input, depth + 1) : undefined

  const parsed = splitCommandSegmentsDetailed(script, input.shell)
  // Opaque split (unclosed quote/escape, unsupported backtick, truncated
  // heredoc): the raw security scans still run — classify the whole script as
  // one surface — but a script that was never fully parsed may not authorize
  // itself through known-safe/read-only/path-exemption early allows. LOOSE
  // keeps the ASK floor; HARD and read-only sessions deny outright (with the
  // kernel-enforced passthrough still available under LOOSE).
  const unresolved = parsed === undefined
  const rawSegments = parsed?.segments ?? [{ text: script }]
  const results: SegmentDecision[] = []
  let stable: SegmentBase = {
    dir: path.resolve(input.cwd),
    unverified: input.baseUnverified === true,
  }
  let cond: SegmentBase = stable
  let sawDirectoryChange = false
  // Write→invoke correlation for this script level: literal file writes
  // (heredocs, `echo 'x' > f`) whose target is later executed or sourced.
  const writtenBodies = new Map<string, string>()

  for (const raw of rawSegments) {
    ;({ stable, cond } = advanceSegmentBase(raw, stable, cond, input.cwd))
    const segment = raw.text.trim()
    if (!segment) continue
    const cd = parseCdSegment(segment)
    if (cd) {
      sawDirectoryChange = true
      // A `cd` inside a pipeline or background job runs in a subshell and
      // cannot move the main shell's cwd.
      if (raw.incoming !== "|" && raw.incoming !== "&") {
        const resolvedDir = resolveCdBase(cd.dir, cond.dir)
        cond = { dir: resolvedDir, unverified: cond.unverified }
        if (raw.incoming === undefined || raw.incoming === ";" || raw.incoming === "newline") stable = cond
      }
      continue
    }
    const segInput: InternalClassifyInput = {
      ...input,
      cwdUnknown: cond.dir === undefined,
      baseUnverified: cond.unverified || input.baseUnverified === true,
    }
    const decision = await classifySegment(segment, cond.dir ?? input.cwd, segInput, depth)
    results.push(decision)

    // Record literal writes, then check whether this segment invokes a file a
    // previous segment wrote — if so its body is code and gets scanned.
    const writeBase = cond.dir ?? input.cwd
    for (const written of heredocWrittenBodies(segment, writeBase)) {
      writtenBodies.set(path.resolve(written.target), written.body)
    }
    const invoked = invokedScriptPath(segment)
    if (invoked !== undefined && cond.dir !== undefined) {
      const literal = literalPathToken(invoked)
      const absolute = literal
        ? resolveLexical(literal, writeBase, expandHome("~")).absolute
        : undefined
      const body = absolute ? writtenBodies.get(path.resolve(absolute)) : undefined
      if (body !== undefined) {
        const hit = definiteDestructiveHit(body, input.bypassedCategories)
        if (hit) {
          results.push({ verdict: "DENY", rules: [hit.id], reason: hit.reason })
        } else {
          const bodyDecision = await classifySegments(
            body,
            { ...input, cwd: writeBase, cwdUnknown: false },
            depth + 1,
          )
          if (bodyDecision.verdict === "DENY") results.push(bodyDecision)
          else if (
            hasLocalScriptReviewSignal(body) &&
            !ruleBypassed("execution.local-script-signal", input.bypassedCategories)
          ) {
            results.push({
              verdict: "ASK",
              rules: ["execution.local-script-signal"],
              reason: "A file written earlier in the command is executed and contains a review-requiring primitive",
            })
          }
        }
      }
    }
  }

  const direct =
    results.length === 0
      ? {
          verdict: "ALLOW" as SecurityVerdict,
          rules: [sawDirectoryChange ? "operation.directory-change" : "input.empty"],
          reason: sawDirectoryChange ? "The command only changes the working directory" : "The executable script is empty",
        }
      : combineSegmentDecisions(results)
  if (unresolved && direct.verdict !== "DENY") {
    const strictness: Strictness = input.strictness ?? "LOOSE"
    if (input.permScope && !input.permScope.w) {
      if (input.roKernelEnforced && strictness !== "HARD") {
        const gate = await roNonWriteGate(script, path.resolve(input.cwd), input, strictness)
        const opaque = gate ?? kernelEnforcedAllow()
        return substituted ? combineSegmentDecisions([opaque, substituted]) : opaque
      }
      const opaque = readOnlyExecutionDeny()
      return substituted ? combineSegmentDecisions([opaque, substituted]) : opaque
    }
    const opaque: SegmentDecision =
      strictness === "HARD"
        ? {
            verdict: "DENY",
            rules: ["input.opaque"],
            reason: "The command could not be fully parsed, and strict policy denies unparseable commands",
          }
        : {
            verdict: "ASK",
            rules: ["input.opaque"],
            reason: "The command could not be fully parsed for local classification",
          }
    return substituted ? combineSegmentDecisions([opaque, substituted]) : opaque
  }
  return substituted ? combineSegmentDecisions([direct, substituted]) : direct
}

const DOWNLOAD_OR_BUILD_PATTERN = new RegExp(
  [
    // Network download / transfer
    String.raw`\b(?:curl|wget|wget2|aria2c|yt-dlp|gdown|scp|rsync|invoke-webrequest|iwr|irm)\b`,
    String.raw`\bgit\s+(?:clone|fetch|pull|submodule\s+update)\b`,
    String.raw`\bgh\s+repo\s+clone\b`,
    String.raw`\b(?:hg|svn)\s+(?:clone|checkout|update)\b`,
    // Package manager install / dependency fetch / download-and-run
    String.raw`\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|ci)\b`,
    String.raw`\b(?:npx|bunx|pnpm\s+dlx)\b`,
    String.raw`\b(?:pip(?:3)?|pipx|uv)\s+install\b`,
    String.raw`\b(?:cargo\s+(?:fetch|update|add)|go\s+(?:mod\s+download|get)|dotnet\s+(?:restore|add|tool\s+install))\b`,
    String.raw`\b(?:apt(?:-get)?\s+install|apt-get\s+(?:update|dist-upgrade)|brew\s+(?:install|upgrade|bundle)|winget\s+install|scoop\s+install|choco\s+install|dnf\s+install|yum\s+install|pacman\s+(?:-S|--sync))\b`,
    // Build / packaging
    String.raw`\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:build|release)\b`,
    String.raw`\b(?:mvnw?|maven|gradle|gradlew)\s+(?:clean\s+)?(?:build|package|install|compile|verify|test|assemble|bundle|jar|compileJava|deploy)\b`,
    String.raw`\b(?:make|cmake\s+--build|meson\s+compile|ninja|cargo\s+build|go\s+build|dotnet\s+build|tsc|vite\s+build|webpack|rollup|esbuild|next\s+build|nuxt\s+build|svelte-kit\s+build)\b`,
  ].join("|"),
  "i",
)

export function isDownloadOrBuildCommand(script: string) {
  const value = stripLeadingDirectoryChanges(script.trim())
  return DOWNLOAD_OR_BUILD_PATTERN.test(value)
}

function isPowerShellShellName(shell: string) {
  const name = path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase()
  return name === "pwsh" || name === "powershell"
}

const DETACHED_START_PREFIX =
  /^(?:Start-Process\b|Start-Job\b|start\b|cmd(?:\.exe)?\s+(?:\/\/c|\/c)\s+start\b)/i

/**
 * `start` / `cmd /c start` / `Start-Process` launch detached processes that
 * inherit the bash tool's stdout/stderr pipe, so OpenCode waits for the pipe
 * to reach EOF and the command hangs until the launched program exits. This
 * rewrites the leading detached-start segment to redirect its handles away
 * from the pipe, letting the tool return immediately while the launched
 * program keeps running in the background.
 */
export function isolateDetachedStartCommand(command: string, shell: string) {
  const value = command.trim()
  const match = value.match(new RegExp(`^${DETACHED_START_PREFIX.source}([^;&|\\n]*)`, "i"))
  if (!match) return command
  const args = match[1] ?? ""
  if (/[<>]/.test(args)) return command
  const redirect = isPowerShellShellName(shell) ? "> $null 2>&1" : ">/dev/null 2>&1"
  const rest = value.slice(match[0].length)
  const separator = rest.match(/^\s*(&&|\|\||;|\||\r?\n)/)
  if (!separator) return `${value} ${redirect}`
  const sep = separator[1]
  const tail = rest.slice(separator[0].length).trim()
  const prefix = value.slice(0, match[0].length).trimEnd()
  return `${prefix} ${redirect} ${sep} ${tail}`
}

export async function classifyShellCommand(input: ClassifyShellCommandInput): Promise<StaticSecurityDecision> {
  const source = normalized(input.script).trim()
  if (!source) {
    return { verdict: "DENY", rules: ["input.empty"], reason: "The executable script is empty", fingerprints: [] }
  }
  if (source.length > MAX_COMMAND_CHARS || source.includes("\0")) {
    return {
      verdict: "ASK",
      rules: ["input.opaque"],
      reason: "The command is too large or contains opaque bytes for reliable local classification",
      fingerprints: [],
    }
  }
  // Comment-neutralized scan view (A/E1): comment text is blanked to spaces
  // so it can neither smuggle a quoted tail past the splitter nor manufacture
  // rule/path findings (`ls # rm -rf /`). When the script cannot be fully
  // lexed the raw source stays in place — conservative fallback — and the
  // opaque clamp inside classifySegments forbids early allows anyway.
  const scanView = commentNeutralizedView(source, input.shell) ?? source
  // Fix D+E2 full-script rule view: proven data-heredoc bodies are removed
  // and proven-inert quoted data spans of eligible commands blanked, while
  // connectors, pipelines, substitutions, redirects, and executor bodies stay
  // visible. Unparseable or ineligible input keeps the raw scan text.
  const ruleView = dataLiteralScriptView(source, input.shell) ?? scanView
  // Floor-scan view: same position-preserving scan text, but with heredoc
  // bodies that cannot be PROVEN to execute (data consumers, unknown
  // consumers that don't pipe onward to code) removed. A payload stored in a
  // file (`cat > x.sh <<'EOF' … EOF`) is payload text, not a command — the
  // ambiguous remainder routes to ASK via execution.ambiguous-heredoc.
  // Executed-code sinks inside language `-c` payloads join as extra surfaces.
  const payloadView = payloadRuleView(scanView, input.shell)
  const floorsView =
    maskHeredocNonExecBodies(payloadView.text, input.shell) +
    (payloadView.sinks.length > 0 ? "\n" + payloadView.sinks.join("\n") : "")
  const executableSurfaces = [
    ruleView,
    ...extractDecodedPayloads(ruleView, { executedOnly: true }),
    ...ruleScanWrappers(ruleView),
  ]
  const bypassed = input.bypassedCategories
  // Pipe-separated segments are classified individually, so remote-pipe
  // (`curl ... | bash`) must be judged on the full script. HARD mode denies
  // download-and-execute outright; LOOSE defers it to the dynamic reviewer
  // (which applies the official-installer rule).
  const remotePipeRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "execution.remote-pipe")
  if (
    (input.strictness ?? "LOOSE") === "HARD" &&
    remotePipeRule &&
    !ruleBypassed("execution.remote-pipe", bypassed) &&
    remotePipeRule.test(floorsView)
  ) {
    return {
      verdict: "DENY",
      rules: ["execution.remote-pipe"],
      reason: remotePipeRule.reason,
      fingerprints: [],
    }
  }
  // Reverse shells / xargs deletion may span `|`/`;` segments, so judge them
  // on the full script (both modes: these are DEFINITE-destructive). Reverse
  // shells are floor rules and never bypassable.
  const reverseShellRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "network.reverse-shell")
  const xargsRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "execution.xargs-destructive")
  for (const rule of [reverseShellRule, xargsRule]) {
    if (!rule || ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(floorsView)) {
      return { verdict: "DENY", rules: [rule.id], reason: rule.reason, fingerprints: [] }
    }
  }
  // Floor rules that can span `|`/`&` segment splits: fork bombs (the `&`
  // inside the function body splits the pattern) and kernel-trigger /
  // kernel-core-pattern writes via `tee`/`cp`-style pipes. `splitCommandSegments`
  // runs before the per-segment SECURITY_SIGNAL_RULES loop, so the per-segment
  // check alone never sees the full shape; these are floor rules (never
  // bypassable) and DEFINITE-destructive, so DENY on the full script up front.
  // `source` only (not decoded payloads): a decoded payload that is merely
  // printed (`echo <b64> | base64 -d`) never executes; genuinely executed
  // wrappers/remote-pipes are handled by the wrapper, remote-pipe, and
  // literal-shell checks below and by classifySegments recursion.
  const forkBombRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "execution.fork-bomb")
  const kernelTriggerRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "filesystem.kernel-trigger")
  const kernelCorePatternRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "filesystem.kernel-core-pattern")
  for (const rule of [forkBombRule, kernelTriggerRule, kernelCorePatternRule]) {
    if (!rule || ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(floorsView)) {
      return { verdict: "DENY", rules: [rule.id], reason: rule.reason, fingerprints: [] }
    }
  }
  // Literal piped into a shell interpreter: `printf 'rm -rf /' | sh`.
  const literalShell = /(?:echo|printf)\s+["'][^"']{0,200}?(?:\brm\b[^\n;|"'&]*-[rf]|\bshred\b|\brm\s+-rf\b)[^"']*["']\s*\|\s*(?:sh|bash|zsh|dash)\b/i.test(
    floorsView,
  )
  if (literalShell) {
    return {
      verdict: "DENY",
      rules: ["execution.literal-shell"],
      reason: "Pipes a destructive literal command into a shell interpreter",
      fingerprints: [],
    }
  }
  // Cross-call base (fix E): the shell tool's `workdir` argument is the
  // directory the command will actually execute in — a claim from the tool
  // input, not the verified session directory. It becomes the tracked base
  // (resolved against the session cwd when relative) and marks it unverified:
  // path checks resolve against it, but temp-confined exemptions only apply
  // once the base canonically lands inside a trusted temp root.
  const resolvedWorkdir =
    input.runtimeWorkdir !== undefined && input.runtimeWorkdir.trim() !== ""
      ? path.isAbsolute(input.runtimeWorkdir)
          ? path.normalize(input.runtimeWorkdir)
          : path.resolve(input.cwd, input.runtimeWorkdir)
      : undefined
  const effectiveInput: InternalClassifyInput =
    resolvedWorkdir !== undefined && resolvedWorkdir !== path.resolve(input.cwd)
      ? { ...input, cwd: resolvedWorkdir, baseUnverified: true }
      : input

  const localScriptSurfaces: string[] = []
  const fingerprints: ScriptFingerprint[] = []
  const localScripts: LocalScriptReviewContext[] = []
  const uninspectedLocalScripts: string[] = []
  const targetDirectories: TargetDirectoryReviewContext[] = []
  const uninspectedTargetDirectories: string[] = []
  const referenced = referencedPathCandidates(scanView, input.shell)
  const deletionTargets = deletionTargetCandidates(scanView, input.shell, effectiveInput.cwd)
  let cloudScriptChars = 0

  for (const candidate of localScriptCandidates(scanView, input.shell)) {
    const inspected = await fingerprintLocalScript(candidate, effectiveInput.cwd, input.worktree)
    if (!inspected) {
      uninspectedLocalScripts.push(candidate)
      continue
    }
    fingerprints.push(inspected.fingerprint)
    localScriptSurfaces.push(normalized(inspected.content))
    if (cloudScriptChars + inspected.content.length <= MAX_CLOUD_LOCAL_SCRIPT_CHARS) {
      localScripts.push({
        path: inspected.reviewPath,
        content: inspected.content,
        sha256: inspected.fingerprint.sha256,
      })
      cloudScriptChars += inspected.content.length
    } else {
      // Single file exceeds cloud budget: send head+tail window with truncation marker
      const content = inspected.content
      const headSize = 64000
      const tailSize = 64000
      if (content.length > headSize + tailSize) {
        const head = content.slice(0, headSize)
        const tail = content.slice(content.length - tailSize)
        const middleOmitted = content.length - headSize - tailSize
        localScripts.push({
          path: inspected.reviewPath,
          content: head + `\n[TRUNCATED: middle ${middleOmitted} bytes omitted of ${content.length} total]\n` + tail,
          sha256: inspected.fingerprint.sha256,
        })
      } else {
        localScripts.push({
          path: inspected.reviewPath,
          content: content,
          sha256: inspected.fingerprint.sha256,
        })
      }
      uninspectedLocalScripts.push(candidate)
    }
  }

  for (const candidate of deletionTargets.items) {
    const inspected = await inspectTargetDirectory(candidate.target, candidate.cwd, input.worktree)
    if (inspected.context) targetDirectories.push(inspected.context)
    if (inspected.uninspected) uninspectedTargetDirectories.push(inspected.uninspected)
  }

  const reviewContext: StaticReviewContext = {
    localScripts,
    uninspectedLocalScripts,
    targetDirectories,
    uninspectedTargetDirectories,
    referencedPaths: referenced.paths,
    referencedPathsTruncated: referenced.truncated,
  }
  const decisionState = { fingerprints, reviewContext }
  const executableCombined = executableSurfaces.join("\n\n")
  const localScriptCombined = localScriptSurfaces.join("\n\n")

  const segmentDecision = await classifySegments(scanView, effectiveInput)

  if (segmentDecision.verdict === "DENY") {
    return { verdict: "DENY", rules: segmentDecision.rules, reason: segmentDecision.reason, ...decisionState }
  }
  // An unparseable top-level script may not ride the disposable-cleanup
  // early allow (it bypasses the ASK floor entirely).
  const topLevelOpaque = segmentDecision.rules.includes("input.opaque")

  if (deletionTargets.truncated && !ruleBypassed("filesystem.deletion-targets-truncated", bypassed)) {
    return {
      verdict: "ASK",
      rules: [...new Set([...segmentDecision.rules, "filesystem.deletion-targets-truncated"])],
      reason: "The command has more deletion targets than can be inspected safely",
      ...decisionState,
    }
  }

  if (
    !topLevelOpaque &&
    await isExplicitDisposableCleanup(scanView, effectiveInput.cwd, input.worktree) &&
    executableSurfaces.length === 1 &&
    localScriptSurfaces.length === 0 &&
    (input.strictness ?? "LOOSE") !== "HARD"
  ) {
    return {
      verdict: "ALLOW",
      rules: ["cleanup.disposable"],
      reason: "Cleanup is narrowly scoped to a recognized disposable cache, dependency, build, or temporary target",
      ...decisionState,
    }
  }

  const extraSignals = new Map<string, string>()
  for (const rule of SECURITY_SIGNAL_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (rule.id === "execution.remote-pipe" && rule.test(executableCombined)) {
      extraSignals.set(rule.id, rule.reason)
    }
  }
  if (localScriptCombined) {
    for (const rule of SECURITY_SIGNAL_RULES) {
      if (ruleBypassed(rule.id, bypassed)) continue
      if (rule.test(localScriptCombined)) extraSignals.set(rule.id, rule.reason)
    }
    // Exfiltration primitives inside an inspected script must surface as review
    // signals too; without this, `bash script.sh` with a curl -T/scp upload is
    // ALLOWed on the strength of the script's otherwise-clean content.
    const scriptExfil = hasExfilOrDangerousPerms(localScriptCombined, localScriptCombined, {
      cwd: input.cwd,
      worktree: input.worktree,
      strictness: input.strictness ?? "LOOSE",
    })
    if (scriptExfil && !ruleBypassed(scriptExfil, bypassed)) {
      extraSignals.set(
        scriptExfil,
        scriptExfil === "permissions.sensitive-mode"
          ? "The local script sets dangerous permissions on a credential or system file and requires review"
          : "The local script sends credential or system data off-host and requires review",
      )
    }
    if (!ruleBypassed("data.critical-delete", bypassed) && hasCriticalDataDestruction(localScriptCombined, input.shell)) {
      extraSignals.set("data.critical-delete", "Local script may delete credential or key material and requires review")
    }
    if (!ruleBypassed("data.destructive-delete", bypassed) && hasGeneralDataDestruction(localScriptCombined)) {
      extraSignals.set("data.destructive-delete", "Local script may delete durable data and requires semantic review")
    }
    if (!ruleBypassed("data.destructive-overwrite", bypassed) && hasDestructiveOverwrite(localScriptCombined)) {
      extraSignals.set("data.destructive-overwrite", "Local script may overwrite durable data and requires semantic review")
    }
    if (hasLocalScriptReviewSignal(localScriptCombined) && !ruleBypassed("execution.local-script-signal", bypassed)) {
      extraSignals.set("execution.local-script-signal", "Local script contains a review-requiring primitive")
    }
  }

  if (
    segmentDecision.verdict === "ASK" &&
    segmentDecision.rules.length === 1 &&
    segmentDecision.rules[0] === "execution.local-script" &&
    localScriptSurfaces.length > 0 &&
    uninspectedLocalScripts.length === 0 &&
    extraSignals.size === 0
  ) {
    return {
      verdict: "ALLOW",
      rules: ["execution.local-script-inspected"],
      reason: "The local script was fully read and fingerprinted and contains no review-requiring behavior",
      ...decisionState,
    }
  }

  const rules = [...segmentDecision.rules]
  for (const [id, reason] of extraSignals) {
    if (!rules.includes(id)) rules.push(id)
  }
  if (segmentDecision.verdict === "ALLOW" && extraSignals.size > 0) {
    return {
      verdict: "ASK",
      rules,
      reason: [...extraSignals.values()][0],
      ...decisionState,
    }
  }

  return { verdict: segmentDecision.verdict, rules, reason: segmentDecision.reason, ...decisionState }
}

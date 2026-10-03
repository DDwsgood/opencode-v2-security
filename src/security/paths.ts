// Path safety layer: lexical (no filesystem) resolution of file arguments and
// sensitivity classification against a static registry. Mirrors the design of
// Claude Code's pathValidation.ts: a command is only provably safe when every
// read/write argument is known, literal, and inside an allowed area.
import { AsyncLocalStorage } from "node:async_hooks"
import path from "node:path"

/** Set for the duration of one classification: LOOSE read-write ("rw"),
 *  LOOSE read-only ("ro"), or HARD ("off"). Lexer and vocabulary relaxations
 *  that only exist to raise the LOOSE static-allow rate check it, so HARD
 *  (and any helper called outside a classification) keeps the stricter
 *  original behavior. */
export const looseRelaxationScope = new AsyncLocalStorage<"rw" | "ro" | "off">()

export function looseRelaxationsActive(): boolean {
  const scope = looseRelaxationScope.getStore()
  return scope === "rw" || scope === "ro"
}

/** Relaxations whose only backstop is the RW review path, not the RO
 *  write ceiling. */
export function looseReadWriteActive(): boolean {
  return looseRelaxationScope.getStore() === "rw"
}

export type Strictness = "LOOSE" | "HARD"
export type PathContext = {
  cwd: string
  worktree: string
  strictness: Strictness
}

export type PathFinding =
  | { kind: "pass" }
  | { kind: "ask"; rule: string; reason: string }
  | { kind: "deny"; rule: string; reason: string }

// --- registry ---------------------------------------------------------------

type SensitivityFlags = { critical: boolean; credential: boolean; systemWrite: boolean }

const CRITICAL_EXACT = [
  "/etc/shadow",
  "/etc/gshadow",
  "/etc/master.passwd",
  "/dev/mem",
  "/dev/port",
  "/dev/kmsg",
  "/proc/sysrq-trigger",
]

const CRITICAL_RE = [
  /^\/proc\/(?:\d+|self|thread-self)\/mem(?:$|[./])/,
  /^\/proc\/sys\//,
  /^\/dev\/(?:sd|nvme|vd|hd|xvd|mmcblk|dasd)[a-z0-9-]*$/,
]

const CREDENTIAL_HOME_DIRS = [".ssh", ".gnupg", ".aws", ".kube", ".azure", ".config/gcloud", ".config/azure-cli"]

const CREDENTIAL_HOME_FILES = [
  ".netrc",
  ".git-credentials",
  ".npmrc",
  ".pypirc",
  ".bash_history",
  ".zsh_history",
  ".docker/config.json",
]

const CREDENTIAL_ABS_RE = [
  /^\/proc\/(?:\d+|self|thread-self)\/environ/,
  /^\/etc\/sudoers(?:$|[./])/,
]

const CREDENTIAL_NAME_RE = [
  /^id_(?:rsa|dsa|ecdsa|ed25519|ed448)$/,
  /\.(?:pem|key|p12|pfx|ppk|jks|keystore|kdbx|gpg|age)$/,
  /^\.env(?:$|[.])/i,
  /\.env$/i,
]

const SYSTEM_WRITE_EXACT = [
  "/etc/passwd",
  "/etc/group",
  "/etc/shadow",
  "/etc/gshadow",
  "/etc/ld.so.preload",
  "/etc/hosts",
  "/etc/hosts.equiv",
  "/etc/resolv.conf",
  "/etc/fstab",
  "/etc/nsswitch.conf",
  "/etc/environment",
  "/etc/sudoers",
  "/etc/ld.so.cache",
  "/etc/crontab",
  "/etc/issue",
  "/etc/motd",
]

const SYSTEM_WRITE_PREFIX = [
  "/etc/ssh/",
  "/etc/pam.d/",
  "/etc/cron",
  "/etc/systemd/",
  "/var/spool/cron/",
  "/boot/",
  "/etc/modprobe.d/",
  "/etc/profile.d/",
  "/etc/tmpfiles.d/",
  "/bin/",
  "/sbin/",
  "/usr/bin/",
  "/usr/sbin/",
  "/usr/local/bin/",
  "/usr/local/sbin/",
  "/var/log/",
  "/etc/profile",
  "/etc/bash.bashrc",
]

const SYSTEM_WRITE_HOME_FILES = [
  ".bashrc",
  ".bash_profile",
  ".bash_login",
  ".profile",
  ".shrc",
  ".zshrc",
  ".zprofile",
  ".zlogin",
  ".rhosts",
]

// Suffix anchors applied to relative path arguments that escape the worktree,
// so that `../../etc/shadow` is caught even though its resolved form depends
// on the working directory.
const SENSITIVE_SUFFIXES: [string, SensitivityFlags][] = [
  ["/etc/shadow", { critical: true, credential: false, systemWrite: true }],
  ["/etc/gshadow", { critical: true, credential: false, systemWrite: true }],
  ["/etc/master.passwd", { critical: true, credential: false, systemWrite: false }],
  ["/etc/passwd", { critical: false, credential: false, systemWrite: true }],
  ["/etc/sudoers", { critical: false, credential: true, systemWrite: true }],
  ["/etc/sudoers.d/", { critical: false, credential: true, systemWrite: true }],
  ["/proc/sys/", { critical: true, credential: false, systemWrite: false }],
  ["/proc/sysrq-trigger", { critical: true, credential: false, systemWrite: false }],
  [".ssh/", { critical: false, credential: true, systemWrite: false }],
  [".gnupg/", { critical: false, credential: true, systemWrite: false }],
  [".aws/", { critical: false, credential: true, systemWrite: false }],
  [".kube/", { critical: false, credential: true, systemWrite: false }],
]

// --- environment ------------------------------------------------------------

function getHome(): string {
  return process.env.USERPROFILE ?? process.env.HOME ?? ""
}

function stripQuotes(value: string): string {
  const trimmed = value.trim()
  if (trimmed.length >= 2) {
    const first = trimmed[0]
    const last = trimmed[trimmed.length - 1]
    if ((first === '"' || first === "'") && first === last) return trimmed.slice(1, -1)
  }
  return trimmed
}

function homeBaseName(home: string): string {
  return home.replaceAll("\\", "/").replace(/\/+$/, "").split("/").pop() ?? ""
}

// --- lexical resolution -----------------------------------------------------

export type ResolvedPath = {
  /** Normalized (slashes) raw argument with `~` expanded where possible. */
  raw: string
  /** Absolute path after lexical `.`/`..` reduction; undefined when the argument cannot be anchored (e.g. `~other`). */
  absolute: string | undefined
  /** The raw argument was absolute. */
  isAbsolute: boolean
  /** The argument references another user's home (`~other` or `/home/<other>`). */
  foreignHome: boolean
}

export function resolveLexical(rawInput: string, cwd: string, home: string): ResolvedPath {
  const raw = stripQuotes(rawInput).replaceAll("\\", "/")
  const result: ResolvedPath = { raw, absolute: undefined, isAbsolute: raw.startsWith("/"), foreignHome: false }
  if (!raw) return result

  let value = raw
  if (value === "~") {
    value = home
  } else if (value.startsWith("~/")) {
    value = home + value.slice(1)
  } else if (/^~[^/]+/.test(value)) {
    const other = value.slice(1).split("/")[0]
    const selfBase = homeBaseName(home).toLowerCase()
    result.foreignHome = selfBase !== "" && other.toLowerCase() !== selfBase
    if (result.foreignHome) return result
    value = home + value.slice(1 + other.length)
  }

  const isAbsolute = value.startsWith("/")
  const parts = value.split("/").filter((part) => part.length > 0 && part !== ".")
  if (isAbsolute) {
    const reduced: string[] = []
    for (const part of parts) {
      if (part === "..") {
        if (reduced.length > 0) reduced.pop()
      } else {
        reduced.push(part)
      }
    }
    result.absolute = "/" + reduced.join("/")
  } else {
    const base = home
      ? cwd
          .replaceAll("\\", "/")
          .split("/")
          .filter((part) => part.length > 0 && part !== ".")
      : []
    const combined = [...(base ?? []), ...parts]
    const reduced: string[] = []
    let escaped = 0
    for (const part of combined) {
      if (part === "..") {
        if (reduced.length > 0) reduced.pop()
        else escaped += 1
      } else {
        reduced.push(part)
      }
    }
    result.absolute = "/" + reduced.join("/")
    result.isAbsolute = false
  }

  const selfBase = homeBaseName(home).toLowerCase()
  if (selfBase && result.absolute !== undefined) {
    const foreignMatch = result.absolute.match(/^\/(?:home|Users)\/([^/]+)\//i)
    if (foreignMatch && foreignMatch[1].toLowerCase() !== selfBase) result.foreignHome = true
  }
  return result
}

export function isWithinLexical(base: string, target: string): boolean {
  const b = base.replaceAll("\\", "/").replace(/\/+$/, "") || "/"
  const t = target.replaceAll("\\", "/")
  if (b === "/") return true
  return t === b || t.startsWith(b + "/")
}

// --- sensitivity ------------------------------------------------------------

/** Credential-name fragments that can appear inside interpreter code or
 *  other argument text where the shell-token path extractor never sees them
 *  (`node -e "…readFileSync('/home/u/.ssh/id_rsa')…"`). Built from the same
 *  vocabulary as the registry above (home credential dirs, credential file
 *  names, credential suffixes); matching text keeps a read-side surface in
 *  review instead of statically allowing it. */
const EMBEDDED_CREDENTIAL_RE = new RegExp(
  [
    String.raw`(?:^|[/\s"'=(,;:&|])\.ssh(?:/|["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.gnupg(?:/|["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.aws(?:/|["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.kube(?:/|["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.azure(?:/|["'\s,;)&|]|$)`,
    String.raw`\.config/gcloud`,
    String.raw`\.config/azure-cli`,
    String.raw`(?:^|[/\s"'=(,;:&|])id_(?:rsa|dsa|ecdsa|ed25519|ed448)(?:["'\s,;)&|./]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.netrc(?:["'\s,;)&|]|$)`,
    String.raw`\.git-credentials`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.npmrc(?:["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.pypirc(?:["'\s,;)&|]|$)`,
    String.raw`\.bash_history`,
    String.raw`\.zsh_history`,
    String.raw`\.docker/config\.json`,
    String.raw`/proc/(?:\d+|self|thread-self)/environ`,
    String.raw`(?:^|[/\s"'=(,;:&|])sudoers(?:[./]|["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])[\w.-]+\.(?:pem|ppk|p12|pfx|jks|kdbx|age)(?:["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])[\w.-]+\.(?:crt|key)(?:["'\s,;)&|]|$)`,
    String.raw`(?:^|[/\s"'=(,;:&|])\.env(?:\.[\w.-]+)?(?:["'\s,;)&|]|$)`,
    String.raw`[\w.-]\.env(?:["'\s,;)&|]|$)`,
  ].join("|"),
  "i",
)

/** A read-side finding for argument text that names a credential store
 *  without forming a classifiable path token. Returns undefined when the
 *  text carries no credential hint. */
export function embeddedCredentialFinding(text: string): PathFinding | undefined {
  if (!EMBEDDED_CREDENTIAL_RE.test(text)) return undefined
  return {
    kind: "ask",
    rule: "credentials.sensitive-access",
    reason: "Reading a credential or sensitive system file requires review",
  }
}

function matchRegistry(absolute: string, home: string, flags: SensitivityFlags): void {
  const norm = absolute
    .replaceAll("\\", "/")
    .toLowerCase()
    .replace(/\/{2,}/g, "/")
    .replace(/\/+$/, "")

  if (CRITICAL_EXACT.includes(norm)) flags.critical = true
  for (const re of CRITICAL_RE) if (re.test(norm)) flags.critical = true
  for (const re of CREDENTIAL_ABS_RE) if (re.test(norm)) flags.credential = true
  if (SYSTEM_WRITE_EXACT.includes(norm)) flags.systemWrite = true
  for (const prefix of SYSTEM_WRITE_PREFIX) {
    const cleaned = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix
    if (norm === cleaned || norm.startsWith(cleaned + "/")) flags.systemWrite = true
  }

  if (home) {
    const h = home.replaceAll("\\", "/").toLowerCase().replace(/\/+$/, "")
    if (h) {
      for (const dir of CREDENTIAL_HOME_DIRS) {
        if (norm === `${h}/${dir}` || norm.startsWith(`${h}/${dir}/`)) flags.credential = true
      }
      for (const file of CREDENTIAL_HOME_FILES) if (norm === `${h}/${file}`) flags.credential = true
      for (const file of SYSTEM_WRITE_HOME_FILES) if (norm === `${h}/${file}`) flags.systemWrite = true
    }
  }

  const baseName = norm.split("/").pop() ?? ""
  if (baseName) {
    for (const re of CREDENTIAL_NAME_RE) if (re.test(baseName)) flags.credential = true
  }
}

function matchSuffix(raw: string, flags: SensitivityFlags): void {
  const value = raw.replaceAll("\\", "/").toLowerCase()
  for (const [suffix, entry] of SENSITIVE_SUFFIXES) {
    if (value.endsWith(suffix)) {
      if (entry.critical) flags.critical = true
      if (entry.credential) flags.credential = true
      if (entry.systemWrite) flags.systemWrite = true
    }
  }
}

function isBroadScanRoot(absolute: string | undefined): boolean {
  if (!absolute) return false
  return absolute === "/" || /^\/mnt\/[a-z]$/i.test(absolute)
}

const REASON_SENSITIVE_READ_ASK = "Reading a credential or sensitive system file requires review"
const REASON_SENSITIVE_READ_DENY = "Attempts to read credential or sensitive system data"
const REASON_SENSITIVE_WRITE_ASK = "Writing to a credential or system file requires review"
const REASON_SENSITIVE_WRITE_DENY = "Attempts to overwrite credential or system files"
const REASON_SENSITIVE_DELETE = "Attempts to delete credential or system data"
const REASON_OUTSIDE_WRITE = "Writing outside the working tree requires review"
const REASON_BROAD_SCAN = "Scanning a filesystem root requires review"
const REASON_FOREIGN_HOME = "Accessing another user's home directory requires review"
const REASON_UNPARSEABLE = "The path contains dynamic expansion and cannot be proven safe"

/**
 * Worktree-relative path fragments whose contents are executed by trusted
 * tools, so writing into them plants code that later fires inside a
 * known-safe command (a planted .git/hooks/pre-commit runs on the
 * whitelisted `git commit`).
 */
const WORKTREE_EXEC_TRIGGERS = ["/.git/hooks/"]

export function classifyPathTarget(raw: string, mode: "read" | "write" | "delete", ctx: PathContext): PathFinding {
  const home = getHome()
  const resolved = resolveLexical(raw, ctx.cwd, home)
  if (!resolved.raw) return { kind: "pass" }
  if (/[`$]/.test(resolved.raw)) {
    return { kind: "ask", rule: "execution.unparseable-path", reason: REASON_UNPARSEABLE }
  }
  if (mode === "write" && /[*?[{]/.test(resolved.raw)) {
    return { kind: "ask", rule: "execution.unparseable-path", reason: REASON_UNPARSEABLE }
  }

  const flags: SensitivityFlags = { critical: false, credential: false, systemWrite: false }
  const inside = resolved.absolute !== undefined && isWithinLexical(ctx.worktree, resolved.absolute)
  if (resolved.absolute !== undefined) matchRegistry(resolved.absolute, home, flags)
  if (!inside && !resolved.isAbsolute) {
    matchSuffix(resolved.raw, flags)
  }

  const sensitiveRead = flags.critical || flags.credential
  const sensitiveWrite = flags.critical || flags.credential || flags.systemWrite

  // /proc/sys is the kernel-parameter interface: a write-direction access is
  // a kernel.sysctl-write question (privilege category), not a secret one.
  // Reads keep their sensitive-path classification.
  if (mode !== "read" && resolved.absolute !== undefined && /^\/proc\/sys(?:\/|$)/i.test(resolved.absolute.replaceAll("\\", "/"))) {
    return ctx.strictness === "HARD"
      ? { kind: "deny", rule: "kernel.sysctl-write", reason: "Modifying kernel parameters is blocked by privilege policy" }
      : { kind: "ask", rule: "kernel.sysctl-write", reason: "Modifying kernel parameters requires review" }
  }

  if (mode === "read" && sensitiveRead) {
    return ctx.strictness === "HARD"
      ? { kind: "deny", rule: "data.critical-read", reason: REASON_SENSITIVE_READ_DENY }
      : { kind: "ask", rule: "credentials.sensitive-access", reason: REASON_SENSITIVE_READ_ASK }
  }
  if (mode === "write" && sensitiveWrite) {
    return ctx.strictness === "HARD"
      ? {
          kind: "deny",
          rule: flags.critical || flags.credential ? "data.critical-write" : "system.file-override",
          reason: REASON_SENSITIVE_WRITE_DENY,
        }
      : {
          kind: "ask",
          rule: flags.critical || flags.credential ? "credentials.sensitive-access" : "system.sensitive-write",
          reason: REASON_SENSITIVE_WRITE_ASK,
        }
  }
  if (mode === "delete" && sensitiveWrite) {
    return ctx.strictness === "HARD"
      ? { kind: "deny", rule: "data.critical-delete", reason: REASON_SENSITIVE_DELETE }
      : { kind: "ask", rule: "data.critical-delete", reason: REASON_SENSITIVE_DELETE }
  }
  if (mode === "read" && resolved.foreignHome) {
    return { kind: "ask", rule: "credentials.foreign-home", reason: REASON_FOREIGN_HOME }
  }
  if (mode !== "read" && resolved.absolute !== undefined) {
    const norm = resolved.absolute.replaceAll("\\", "/").toLowerCase()
    if (WORKTREE_EXEC_TRIGGERS.some((trigger) => norm.includes(trigger) || norm.endsWith(trigger.replace(/\/$/, "")))) {
      return ctx.strictness === "HARD"
        ? { kind: "deny", rule: "persistence.git-hooks", reason: "Writing git hooks is blocked by host policy because it plants code that fires on trusted git commands" }
        : { kind: "ask", rule: "persistence.git-hooks", reason: "Writing git hooks plants code that fires on trusted git commands and requires review" }
    }
  }
  if (mode === "read" && isBroadScanRoot(resolved.absolute)) {
    return { kind: "ask", rule: "filesystem.broad-scan", reason: REASON_BROAD_SCAN }
  }
  if (mode === "write" && !inside) {
    return { kind: "ask", rule: "filesystem.outside-write", reason: REASON_OUTSIDE_WRITE }
  }
  return { kind: "pass" }
}

// --- redirect scanning ------------------------------------------------------

type RedirectSpan = { start: number; end: number; target: string; unparseable: boolean }

const EXEMPT_REDIRECT_TARGETS = /^(?:\/dev\/(?:null|stdout|stderr|tty)|\$null|NUL)$/i

function scanRedirects(segment: string): RedirectSpan[] {
  const spans: RedirectSpan[] = []
  let i = 0
  const n = segment.length
  while (i < n) {
    const ch = segment[i]
    if (ch === "'" || ch === '"') {
      const quote = ch
      let k = i + 1
      while (k < n && segment[k] !== quote) {
        if (quote === '"' && segment[k] === "\\" && k + 1 < n) k += 2
        else k += 1
      }
      i = k + 1
      continue
    }
    if (ch === "&" || ch === ">") {
      let start = i
      while (start > 0 && /\d/.test(segment[start - 1])) start -= 1
      let opEnd: number | undefined
      if (segment[i] === "&" && segment[i + 1] === ">") opEnd = i + 2
      else if (segment[i] === ">") opEnd = i + (segment[i + 1] === ">" ? 2 : 1)
      if (opEnd === undefined) {
        i += 1
        continue
      }
      let j = opEnd
      while (j < n && segment[j] === " ") j += 1
      if (j >= n) {
        i = n
        break
      }
      const first = segment[j]
      let target: string
      if (first === '"' || first === "'") {
        let k = j + 1
        let buffer = ""
        while (k < n && segment[k] !== first) {
          if (first === '"' && segment[k] === "\\" && k + 1 < n) {
            buffer += segment[k + 1]
            k += 2
          } else {
            buffer += segment[k]
            k += 1
          }
        }
        if (k >= n) {
          i = n
          break
        }
        target = buffer
        j = k + 1
      } else {
        let k = j
        // `>&1`/`>&-`: the leading & is part of an fd-dup target, not a
        // separator — consuming it prevents an empty span target.
        if (segment[k] === "&") k += 1
        while (k < n && !/[\s()<>;|&]/.test(segment[k])) k += 1
        target = segment.slice(j, k)
        j = k
      }
      // fd duplication/close targets (&1, 1, &- , -) are not file writes.
      if (!/^&?[\d-]+$/.test(target) && !EXEMPT_REDIRECT_TARGETS.test(target)) {
        spans.push({ start, end: j, target, unparseable: /[`$*?[{]/.test(target) })
      }
      i = j
      continue
    }
    i += 1
  }
  return spans
}

/**
 * Removes every output redirect from the segment. Returns undefined when a
 * redirect target contains dynamic expansion (the segment is not provably safe).
 */
export function stripOutputRedirects(segment: string): string | undefined {
  const spans = scanRedirects(segment)
  if (spans.some((span) => span.unparseable)) return undefined
  if (spans.length === 0) return segment
  let result = ""
  let previous = 0
  for (const span of spans) {
    result += segment.slice(previous, span.start) + " "
    previous = span.end
  }
  result += segment.slice(previous)
  return result
}

// --- guards -----------------------------------------------------------------

const SENSITIVE_ENV_PREFIX_EXACT = new Set([
  "PATH",
  "PYTHONPATH",
  "NODE_OPTIONS",
  "NODE_EXTRA_CA_CERTS",
  "IFS",
  "HISTFILE",
  "HISTSIZE",
  "HISTCONTROL",
  "BASH_ENV",
  "ENV",
  "GCONV_PATH",
  "PERL5LIB",
  "PERL5OPT",
  "RUBYLIB",
  "RUBYOPT",
  "PYTHONSTARTUP",
  "JAVA_TOOL_OPTIONS",
])

const SENSITIVE_ENV_PREFIX_PREFIXES = ["LD_", "DYLD_"]

/** Detects `VAR=value` prefixes that can redirect execution or hide activity. */
export function hasSensitiveEnvPrefix(segment: string): boolean {
  const match = segment.match(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*/)
  if (!match) return false
  const names = match[0].match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []
  for (const name of names) {
    const upper = name.toUpperCase()
    if (SENSITIVE_ENV_PREFIX_EXACT.has(upper)) return true
    for (const prefix of SENSITIVE_ENV_PREFIX_PREFIXES) if (upper.startsWith(prefix)) return true
  }
  return false
}

/** A POSIX `$` expands only before a name, digit, `{`, `(`, `[`, a special
 *  parameter, or a quote (`$'…'`/`$"…"`); elsewhere (`grep "foo$"`,
 *  `json_extract(d,'$.x')`) it is a literal character. */
function expandsAt(text: string, index: number): boolean {
  return !looseRelaxationsActive() || /[A-Za-z0-9_{(\[@*#?$!\-'"]/.test(text[index + 1] ?? "")
}

/**
 * CC `containsUnquotedExpansion` equivalent: unquoted `$`, backticks, globs,
 * and brace expansions make a segment unprovable. Single quotes are inert in
 * both shell families; double quotes protect globs but not variables.
 */
export function hasUnquotedExpansion(text: string, shell: string, allowGlobs = false): boolean {
  const name = path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase()
  const powershell = name === "pwsh" || name === "powershell"
  let inSingle = false
  let inDouble = false
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i]
    if (powershell) {
      if (inSingle) {
        if (ch === "'") inSingle = false
        continue
      }
      if (inDouble) {
        if (ch === '"') inDouble = false
        else if (ch === "`") i += 1
        else if (ch === "$" && text[i + 1] !== "$") return true
        continue
      }
      if (ch === "'") {
        inSingle = true
        continue
      }
      if (ch === '"') {
        inDouble = true
        continue
      }
      if (ch === "`") {
        i += 1
        continue
      }
      if (ch === "$" && text[i + 1] !== "$") return true
      continue
    }
    if (inSingle) {
      if (ch === "'") inSingle = false
      continue
    }
    if (inDouble) {
      if (ch === '"') inDouble = false
      else if (ch === "\\") i += 1
      else if (ch === "$" && expandsAt(text, i)) return true
      continue
    }
    if (ch === "'") {
      inSingle = true
      continue
    }
    if (ch === '"') {
      inDouble = true
      continue
    }
    if (ch === "\\") {
      i += 1
      continue
    }
    if ((ch === "$" && expandsAt(text, i)) || ch === "`") return true
    // Glob characters are locally expanded filenames consumed by the command —
    // callers that opt in (LOOSE read surfaces) tolerate them; the shell's own
    // globbing can only name existing local files.
    if (!allowGlobs && (ch === "*" || ch === "?" || ch === "[" || ch === "{")) return true
  }
  return false
}

// --- argument extraction ----------------------------------------------------

function tokenize(value: string): string[] {
  return value.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
}

/** Non-backtracking replacement for the ReDoS-prone regex /(?:\s+\d*>&\d+)+\s*$/. */
export function stripTrailingFdMerges(text: string): string {
  let wsEnd = text.length
  while (wsEnd > 0 && /[\s]/.test(text[wsEnd - 1])) wsEnd -= 1
  let matchEnd = wsEnd
  let found = false
  for (;;) {
    let j = matchEnd
    while (j > 0 && /\d/.test(text[j - 1])) j -= 1
    if (j === matchEnd) break
    if (j < 2 || text[j - 1] !== "&" || text[j - 2] !== ">") break
    let k = j - 2
    while (k > 0 && /\d/.test(text[k - 1])) k -= 1
    if (k === j - 2) break
    let wsStart = k
    while (wsStart > 0 && /[\s]/.test(text[wsStart - 1])) wsStart -= 1
    if (wsStart === k) break
    matchEnd = wsStart
    found = true
  }
  return found ? text.slice(0, matchEnd) : text
}

/** Command leaf of a segment, ignoring env prefixes and the PowerShell `&` call form. */
export function segmentCommandLeaf(segment: string): string {
  let value = stripTrailingFdMerges(segment)
    .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/, "")
    .trim()
  const callMatch = value.match(/^&\s+(?:"([^"]+)"|'([^']+)'|(\S+))/)
  if (callMatch) value = callMatch[1] ?? callMatch[2] ?? callMatch[3] ?? ""
  else value = value.match(/^(\S+)/)?.[1] ?? ""
  return stripQuotes(value)
    .replaceAll("\\", "/")
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase() ?? ""
}

function commandTokens(segment: string): string[] {
  const stripped = stripOutputRedirects(segment)
  if (stripped === undefined) return []
  let value = stripped.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/, "").trim()
  const callMatch = value.match(/^&\s+(?:"[^"]+"|'[^']+'|\S+)\s+/)
  if (callMatch) value = value.slice(callMatch[0].length)
  return tokenize(value)
}

type PositionalOptions = {
  skipFirst?: boolean
  /** Flags that consume the following token as their value. */
  valueFlags?: string[]
  /** Flags whose value is itself a read path (e.g. `grep -f`, `awk -f`). */
  readValueFlags?: string[]
  /** Flags whose value is a write path (e.g. `sort -o`, `base64 -o`). */
  writeValueFlags?: string[]
}

function positionalArgs(tokens: string[], options: PositionalOptions = {}): {
  positionals: string[]
  readValues: string[]
  writeValues: string[]
} {
  const positionals: string[] = []
  const readValues: string[] = []
  const writeValues: string[] = []
  const valueFlags = new Set((options.valueFlags ?? []).map((flag) => flag.toLowerCase()))
  const readValueFlags = new Set((options.readValueFlags ?? []).map((flag) => flag.toLowerCase()))
  const writeValueFlags = new Set((options.writeValueFlags ?? []).map((flag) => flag.toLowerCase()))
  let optionsEnded = false
  let firstSkipped = false

  for (let i = 1; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (!optionsEnded && token === "--") {
      optionsEnded = true
      continue
    }
    if (!optionsEnded && token.startsWith("-") && token !== "-") {
      const flag = token.toLowerCase()
      const inlineValue = flag.includes("=")
      const bare = inlineValue ? flag.slice(0, flag.indexOf("=")) : flag
      if (valueFlags.has(bare) && !inlineValue) {
        const value = tokens[i + 1]
        if (value !== undefined) {
          i += 1
          if (readValueFlags.has(bare)) readValues.push(value)
          else if (writeValueFlags.has(bare)) writeValues.push(value)
          continue
        }
      }
      continue
    }
    if (options.skipFirst && !firstSkipped) {
      firstSkipped = true
      continue
    }
    positionals.push(token)
  }
  return { positionals, readValues, writeValues }
}

const READ_VALUE_FLAGS: Record<string, PositionalOptions> = {
  grep: {
    skipFirst: true,
    valueFlags: [
      "-e", "-f", "-m", "--max-count", "-a", "--after-context", "-b", "--before-context",
      "-c", "--context", "--include", "--exclude", "--exclude-dir", "--binary-files",
      "--color", "--devices", "--directories", "--label", "--threads", "--buffer-size", "--regexp",
    ],
    readValueFlags: ["-f"],
  },
  rg: { skipFirst: true, valueFlags: ["-e", "-g", "--glob", "-j", "--threads", "-m", "--max-count"] },
  "select-string": {
    skipFirst: true,
    valueFlags: ["-Path", "-LiteralPath", "-Include", "-Exclude", "-Context"],
  },
  awk: { skipFirst: true, valueFlags: ["-v", "-f"], readValueFlags: ["-f"] },
  jq: { skipFirst: true, valueFlags: ["-f"], readValueFlags: ["-f"] },
  yq: { skipFirst: true, valueFlags: ["-f"], readValueFlags: ["-f"] },
  head: { valueFlags: ["-n", "--lines", "-c", "--bytes"] },
  tail: { valueFlags: ["-n", "--lines", "-c", "--bytes"] },
  uniq: { valueFlags: ["-f", "-s"] },
  cut: { valueFlags: ["-b", "-c", "-d", "-f", "--output-delimiter"] },
  tr: { valueFlags: ["-t"] },
  nl: { valueFlags: ["-b", "-n", "-w", "-v"] },
  paste: { valueFlags: ["-d", "-s"] },
  column: { valueFlags: ["-s", "-o", "-N"] },
  sort: {
    valueFlags: ["-k", "-o", "-T", "-S", "--key", "--output", "--temporary-directory", "--buffer-size"],
    writeValueFlags: ["-o", "--output"],
  },
  diff: {
    valueFlags: ["-F", "-I", "-L", "-x", "-X", "--exclude-from", "--from-file", "--label", "-T", "-S"],
    readValueFlags: ["--from-file"],
  },
  file: { valueFlags: ["-e", "-m", "-C", "--certfile", "-f"], readValueFlags: ["-C", "--certfile", "-f"] },
  stat: { valueFlags: ["-c", "--format", "--printf"] },
  ls: { valueFlags: ["-T"] },
  du: { valueFlags: ["-d", "--max-depth", "--exclude", "-B", "--block-size"] },
  base64: { valueFlags: ["-w", "--wrap", "-o"], writeValueFlags: ["-o"] },
  shuf: { valueFlags: ["-o", "-n", "-i", "-r", "-e", "--output", "--head-count", "--repeat", "--echo"], writeValueFlags: ["-o", "--output"] },
  od: { valueFlags: ["-A", "-t", "-j", "-N", "-s", "-w"] },
  xxd: { valueFlags: ["-l", "-o", "-s", "-c", "-g"] },
  strings: { valueFlags: ["-n", "-t"] },
}

const SIMPLE_READ_COMMANDS = new Set([
  "cat", "type", "more", "less", "get-content", "head", "tail", "wc", "sort", "uniq",
  "diff", "file", "stat", "strings", "xxd", "od", "hexdump", "nl", "base64", "md5sum",
  "sha256sum", "sha1sum", "ls", "dir", "get-childitem", "du", "cut", "tr", "tac",
  "paste", "column", "comm", "join", "fold", "pr", "gzip", "bzip2", "xz", "split",
  "expand", "shuf", "fmt",
])

const FIND_PATTERN_VALUE_FLAGS = new Set([
  "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-wholename", "-iwholename",
  "-user", "-group", "-perm", "-size", "-maxdepth", "-mindepth", "-links", "-inum",
])

const GIT_ADD_SKIP_FLAGS = new Set(["-A", "-a", "-u", "-f", "-i", "-p", "-n", "-v", "-e", "--"])

function extractInputRedirectTargets(segment: string): string[] {
  const targets: string[] = []
  let i = 0
  const n = segment.length
  while (i < n) {
    const ch = segment[i]
    if (ch === "'" || ch === '"') {
      const quote = ch
      let k = i + 1
      while (k < n && segment[k] !== quote) {
        if (quote === '"' && segment[k] === "\\" && k + 1 < n) k += 2
        else k += 1
      }
      i = k + 1
      continue
    }
    if (ch === "<") {
      // skip heredoc (<<), herestring (<<<), process substitution (<())
      if (segment[i + 1] === "<" || segment[i + 1] === "(") {
        i += 1
        continue
      }
      let start = i
      while (start > 0 && /\d/.test(segment[start - 1])) start -= 1
      let j = i + 1
      while (j < n && /[ \t]/.test(segment[j])) j += 1
      if (j >= n) {
        i = n
        break
      }
      let k = j
      while (k < n && !/[\s()<>;|&]/.test(segment[k])) k += 1
      const target = segment.slice(j, k)
      if (target && !/^&?\d+$/.test(target)) targets.push(target)
      i = k
      continue
    }
    i += 1
  }
  return targets
}

export function extractReadPaths(segment: string): string[] {
  const command = segmentCommandLeaf(segment)
  const tokens = commandTokens(segment)
  if (tokens.length < 2) return []
  const reads: string[] = []

  if (command === "find") {
    for (let i = 1; i < tokens.length; i += 1) {
      const token = tokens[i]
      if (token === "--") break
      if (token.startsWith("-")) {
        const lower = token.toLowerCase()
        if (FIND_PATTERN_VALUE_FLAGS.has(lower) || /^-(?:newer[a-z]{0,2}|anewer|cnewer|mnewer|samefile)$/.test(lower)) {
          if (tokens[i + 1] !== undefined) {
            if (/^-(?:newer[a-z]{0,2}|anewer|cnewer|mnewer|samefile)$/.test(lower)) reads.push(tokens[i + 1])
            i += 1
          }
        }
        continue
      }
      reads.push(token)
      break
    }
    return reads
  }

  if (command === "git" && stripQuotes(tokens[1]).toLowerCase() === "add") {
    for (let i = 2; i < tokens.length; i += 1) {
      const token = tokens[i]
      if (GIT_ADD_SKIP_FLAGS.has(token) || token.startsWith("-")) continue
      reads.push(token)
    }
    return reads
  }

  if (command === "openssl") {
    // `openssl pkey/rsa/ec … -in <file>` reads a private key and must be
    // path-validated. The public-certificate subcommands (x509/req/verify/crl)
    // read public certs/CSRs and are left to the normal flow.
    const subcommand = (tokens[1] ?? "").toLowerCase()
    const publicOnly = new Set(["x509", "req", "verify", "crl", "crl2pkcs7", "ocsp"])
    if (!publicOnly.has(subcommand)) {
      for (let i = 1; i < tokens.length; i += 1) {
        const lower = tokens[i].toLowerCase()
        if (lower === "-in" || lower === "-cert" || lower === "-key" || lower === "-cafile" || lower === "-cakey" || lower === "-revoke") {
          if (tokens[i + 1] !== undefined) {
            reads.push(tokens[i + 1])
            i += 1
          }
        }
      }
    }
    return reads
  }

  if (command === "tar") {
    return extractTarPaths(segment, tokens).reads
  }

  if (command === "zip") {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-x", "--exclude"] })
    return positionals.slice(1)
  }

  if (command === "dd") {
    for (let i = 1; i < tokens.length; i += 1) {
      const token = tokens[i]
      if (token.toLowerCase().startsWith("if=")) reads.push(stripQuotes(token.slice(3)))
      else if (token.toLowerCase() === "--if") {
        if (tokens[i + 1] !== undefined) reads.push(stripQuotes(tokens[i + 1]))
        i += 1
      }
    }
    return reads
  }

  if (command === "sed") {
    const writes = extractWriteTargets(segment)
    if (writes.targets.length > 0) return []
    const spec: PositionalOptions = {
      skipFirst: true,
      valueFlags: ["-e", "-f"],
      readValueFlags: ["-f"],
    }
    const { positionals, readValues } = positionalArgs(tokens, spec)
    return [...readValues, ...positionals]
  }

  if (READ_VALUE_FLAGS[command] !== undefined || SIMPLE_READ_COMMANDS.has(command)) {
    const { positionals, readValues } = positionalArgs(tokens, READ_VALUE_FLAGS[command] ?? {})
    return [...readValues, ...positionals]
  }

  return []
}

function extractTarPaths(_segment: string, tokens: string[]): { reads: string[]; writes: string[] } {
  const reads: string[] = []
  const writes: string[] = []
  let afterDashDash = false
  for (let i = 1; i < tokens.length; i += 1) {
    const token = tokens[i]
    if (afterDashDash) {
      reads.push(token)
      continue
    }
    if (token === "--") {
      afterDashDash = true
      continue
    }
    if (token.startsWith("--")) {
      const eq = token.indexOf("=")
      if (eq > 0) {
        const name = token.slice(2, eq).toLowerCase()
        const value = stripQuotes(token.slice(eq + 1))
        if (name === "file") writes.push(value)
        else if (name === "directory") reads.push(`__dir__${value}`)
        continue
      }
      continue
    }
    if (token.startsWith("-") && token !== "-") {
      const letters = token.slice(1)
      for (let k = 0; k < letters.length; k += 1) {
        const letter = letters[k].toLowerCase()
        if (letter === "f") {
          const value = tokens[i + 1]
          if (value !== undefined) {
            writes.push(stripQuotes(value))
            i += 1
          }
          break
        }
        if (letter === "C") {
          const value = tokens[i + 1]
          if (value !== undefined) {
            reads.push(`__dir__${stripQuotes(value)}`)
            i += 1
          }
          break
        }
      }
      continue
    }
    reads.push(token)
  }
  return { reads, writes }
}

/** Redirect-shaped write targets only (`>f`, `2>>f`, `&>f`) — the subset of
 *  extractWriteTargets that is always a real write, even for commands whose
 *  read-mode vocab emits synthetic targets (unzip extraction dir, tar -f). */
export function extractRedirectTargets(segment: string): { targets: string[]; unparseable: boolean } {
  const targets: string[] = []
  let unparseable = false
  for (const span of scanRedirects(segment)) {
    targets.push(span.target)
    if (span.unparseable) unparseable = true
  }
  return { targets, unparseable }
}

export function extractWriteTargets(segment: string): { targets: string[]; unparseable: boolean } {
  const { targets, unparseable } = extractRedirectTargets(segment)

  const command = segmentCommandLeaf(segment)
  const tokens = commandTokens(segment)
  if (tokens.length < 2) return { targets, unparseable }

  if (command === "tee") {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-p", "--pid"] })
    targets.push(...positionals)
  } else if (command === "dd") {
    for (let i = 1; i < tokens.length; i += 1) {
      const token = tokens[i]
      const lower = token.toLowerCase()
      if (lower.startsWith("of=")) targets.push(stripQuotes(token.slice(3)))
      else if (lower === "--of") {
        if (tokens[i + 1] !== undefined) targets.push(stripQuotes(tokens[i + 1]))
        i += 1
      }
    }
  } else if (command === "truncate" || command === "touch") {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-s", "--size"] })
    targets.push(...positionals)
  } else if (command === "ln") {
    const { positionals } = positionalArgs(tokens, { valueFlags: [] })
    if (positionals.length > 0) targets.push(positionals[positionals.length - 1])
  } else if (["cp", "copy", "copy-item", "mv", "move", "move-item", "rename-item", "ren", "install"].includes(command)) {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-t", "--target-directory"] })
    if (positionals.length >= 2) targets.push(positionals[positionals.length - 1])
    else if (positionals.length === 1 && /(^|\s)-t(\s|$)/i.test(segment)) targets.push(positionals[0])
  } else if (command === "sed") {
    const inPlace = tokens.slice(1).some((token) => {
      const lower = token.toLowerCase()
      return lower === "-i" || /^-i[\w.-]*$/.test(lower) || lower === "--in-place"
    })
    if (inPlace) {
      const { positionals, readValues } = positionalArgs(tokens, {
        skipFirst: true,
        valueFlags: ["-e", "-f"],
        readValueFlags: ["-f"],
      })
      targets.push(...positionals)
      void readValues
    }
  } else if (command === "mkdir" || command === "md") {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-m", "--mode", "-Z", "--context", "--security-context"] })
    targets.push(...positionals)
  } else if (command === "rmdir" || command === "rd" || command === "remove-item") {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["--ignore-fail-on-non-empty", "-path", "-literalpath"] })
    targets.push(...positionals)
  }

  // `sort -o`, `base64 -o` style output flags on read commands
  const spec = READ_VALUE_FLAGS[command]
  if (spec?.writeValueFlags) {
    const { writeValues } = positionalArgs(tokens, spec)
    targets.push(...writeValues)
  }

  if (command === "tar") {
    targets.push(...extractTarPaths(segment, tokens).writes)
  }
  if (command === "zip") {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-x", "--exclude"] })
    if (positionals.length > 0) targets.push(positionals[0])
  }

  // python -m venv <dir> creates a directory
  if ((command === "python" || command === "python3" || command === "py") && /-m\s+venv\b/i.test(segment)) {
    const { positionals } = positionalArgs(tokens, {
      valueFlags: ["-m", "-p", "--prompt", "--upgrade-deps"],
    })
    for (const p of positionals) {
      if (/^(?:venv|virtualenv)$/i.test(p)) continue
      targets.push(p)
      break
    }
  }

  // openssl -out / -keyout writes files
  if (command === "openssl") {
    for (let index = 1; index < tokens.length; index += 1) {
      const token = tokens[index]
      const lower = token.toLowerCase()
      if (lower === "-out" || lower === "-keyout") {
        if (tokens[index + 1] !== undefined) targets.push(stripQuotes(tokens[index + 1]))
        index += 1
      } else if (/^-out(?:=|:)/i.test(token)) {
        targets.push(stripQuotes(token.slice(token.indexOf("=") + 1)))
      }
    }
  }

  // curl / wget downloads write files (-o/-O/--output/-P)
  if (command === "curl" || command === "curl.exe" || command === "wget" || command === "wget2") {
    const isWget = command === "wget" || command === "wget2"
    for (let index = 1; index < tokens.length; index += 1) {
      const token = tokens[index]
      if (token === "-o" || token === "--output" || (isWget && token === "-O")) {
        if (tokens[index + 1] !== undefined) targets.push(stripQuotes(tokens[index + 1]))
        index += 1
      } else if (token === "-O" || token === "--remote-name" || token === "--remote-name-all") {
        // curl -O: writes remote basename into the current directory
        targets.push(".")
      } else if (/^--output=(.+)$/i.test(token)) {
        targets.push(stripQuotes(token.slice(token.indexOf("=") + 1)))
      } else if (token === "-P" || token === "--directory-prefix") {
        if (tokens[index + 1] !== undefined) targets.push(stripQuotes(tokens[index + 1]))
        index += 1
      } else if (/^-[pP][^\s]+$/.test(token) && token.length > 2) {
        targets.push(stripQuotes(token.slice(2)))
      } else if (isWget && /^--clobber(-on-exist)?$/.test(token)) {
        continue
      }
    }
  }

  // unzip -d <dir> writes into <dir> (default: current dir)
  if (command === "unzip" || command === "7z" || command === "7za" || command === "7zr") {
    let dir = "."
    for (let index = 1; index < tokens.length; index += 1) {
      const token = tokens[index]
      const lower = token.toLowerCase()
      if (lower === "-d" || lower === "--directory") {
        if (tokens[index + 1] !== undefined) dir = stripQuotes(tokens[index + 1])
        index += 1
      } else if (/^-d\S/.test(token)) {
        dir = stripQuotes(token.slice(2))
      }
    }
    targets.push(dir)
  }

  // gunzip / gzip -d writes the decompressed file next to its source
  if (command === "gunzip" || (command === "gzip" && /(?:^|\s)-(?:d|dc|cd|z?d)(?:$|\s)/i.test(segment))) {
    const { positionals } = positionalArgs(tokens, { valueFlags: ["-c", "--stdout", "-S", "--suffix"] })
    for (const p of positionals) targets.push(stripQuotes(p).replace(/\.gz$/i, ""))
  }

  return { targets, unparseable }
}

/**
 * Sensitivity-only check (no area/verdict logic), for callers that apply their
 * own area rules (e.g. the backup-copy gate).
 */
export function checkPathSensitivity(raw: string, ctx: PathContext): { parseable: boolean; sensitive: boolean } {
  const home = getHome()
  const resolved = resolveLexical(raw, ctx.cwd, home)
  if (!resolved.raw || /[`$]/.test(resolved.raw) || /[*?[{]/.test(resolved.raw)) {
    return { parseable: false, sensitive: false }
  }
  if (resolved.foreignHome) return { parseable: true, sensitive: true }
  const flags: SensitivityFlags = { critical: false, credential: false, systemWrite: false }
  if (resolved.absolute !== undefined) matchRegistry(resolved.absolute, home, flags)
  if (resolved.absolute === undefined || !isWithinLexical(ctx.worktree, resolved.absolute)) {
    if (!resolved.isAbsolute) matchSuffix(resolved.raw, flags)
  }
  return { parseable: true, sensitive: flags.critical || flags.credential || flags.systemWrite }
}

// --- segment analysis -------------------------------------------------------

function escalate(current: PathFinding, next: PathFinding): PathFinding {
  if (next.kind === "deny") return next
  if (current.kind === "pass" && next.kind === "ask") return next
  return current
}

/**
 * Analyzes every read/write argument of a segment. `pass` means every path is
 * literal and inside the working tree (or an exempt sink).
 */
export function analyzeSegmentPaths(segment: string, ctx: PathContext): PathFinding {
  let finding: PathFinding = { kind: "pass" }
  const command = segmentCommandLeaf(segment)

  if (command === "tar") {
    const tokens = commandTokens(segment)
    const { reads, writes } = extractTarPaths(segment, tokens)
    let base: string | undefined
    let unverifiedBase = false
    for (const read of reads) {
      if (read.startsWith("__dir__")) {
        const dir = read.slice(7)
        const resolved = resolveLexical(dir, ctx.cwd, getHome())
        if (!resolved.absolute || !isWithinLexical(ctx.worktree, resolved.absolute)) unverifiedBase = true
        else base = resolved.absolute
        continue
      }
      const anchor = base ?? ctx.cwd
      const resolved = resolveLexical(read, anchor, getHome())
      if (!resolved.absolute) {
        finding = escalate(finding, { kind: "ask", rule: "execution.unparseable-path", reason: REASON_UNPARSEABLE })
        continue
      }
      const inside = isWithinLexical(ctx.worktree, resolved.absolute)
      const flags: SensitivityFlags = { critical: false, credential: false, systemWrite: false }
      matchRegistry(resolved.absolute, getHome(), flags)
      if (!inside && !resolved.isAbsolute) matchSuffix(resolved.raw, flags)
      if (flags.critical || flags.credential) {
        finding = escalate(
          finding,
          ctx.strictness === "HARD"
            ? { kind: "deny", rule: "data.critical-read", reason: REASON_SENSITIVE_READ_DENY }
            : { kind: "ask", rule: "credentials.sensitive-access", reason: REASON_SENSITIVE_READ_ASK },
        )
      }
    }
    if (unverifiedBase) {
      finding = escalate(finding, { kind: "ask", rule: "filesystem.unverified-base", reason: "The archive base directory is outside the working tree and requires review" })
    }
    for (const write of writes) finding = escalate(finding, classifyPathTarget(write, "write", ctx))
    return finding
  }

  for (const raw of extractReadPaths(segment)) finding = escalate(finding, classifyPathTarget(raw, "read", ctx))
  // `< file` input redirects are reads too and must be path-validated
  for (const raw of extractInputRedirectTargets(segment)) finding = escalate(finding, classifyPathTarget(raw, "read", ctx))

  const writes = extractWriteTargets(segment)
  if (writes.unparseable && writes.targets.length > 0) {
    finding = escalate(finding, { kind: "ask", rule: "execution.unparseable-path", reason: REASON_UNPARSEABLE })
  }
  for (const raw of writes.targets) finding = escalate(finding, classifyPathTarget(raw, "write", ctx))

  return finding
}

/**
 * Read/write sensitivity check for segments that are not provably safe.
 * Returns a finding only for sensitive (credential / system / critical)
 * targets in either direction, so HARD mode surfaces DENY for credential
 * reads (e.g. `cat ~/.ssh/id_rsa`) even when the segment is not on the
 * known-safe command list. Non-sensitive outside writes are left to the
 * existing flow, which already asks for them.
 */
export function sensitivePathFinding(segment: string, ctx: PathContext): PathFinding | undefined {
  const finding = analyzeSegmentPaths(segment, ctx)
  if (finding.kind === "deny") return finding
  if (
    finding.kind === "ask" &&
    (finding.rule === "credentials.sensitive-access" ||
      finding.rule === "system.sensitive-write" ||
      finding.rule === "kernel.sysctl-write" ||
      finding.rule === "credentials.foreign-home" ||
      finding.rule === "execution.unparseable-path")
  ) {
    return finding
  }
  return undefined
}

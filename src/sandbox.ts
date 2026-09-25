// P4 M3 — plugin-side OS sandbox integration (Linux).
//
// The kernel floor lives in `bin/opencode-sandbox` (native/linux-sandbox):
// stage1 picks a sandbox path per the §3.4 decision table and execs bwrap,
// stage2 installs NNP + seccomp + (RO) the Landlock ruleset. This module is
// everything the host process must do around that binary, and is pure logic
// except where noted so it is unit-testable without kernel privileges:
//
//   profileForPerm        perm → ro|rw|full profile (mode + enabled folded in)
//   insertSandboxMarker   prepend a `: opencode-sandbox <nonce>` no-op line so
//   extractSandboxMarker  create.before (which has NO sessionID in the 19271
//                         API) can recover the exact profile chosen at
//                         execute.before time — see plan §1.3
//   applySandboxCreateBefore  marker → wrap decision for create.before; the
//                         marker is the SOLE authority — marker-less spawns
//                         (user `!cmd`, host-internal) are never sandboxed
//   wrapShellForSandbox   rewrite ev.shell to the helper + set OPENCODE_* env
//   probeLinuxSandbox     run `helper --probe`, parse the §3.4 route
//   assertSandboxAvailable  onUnavailable gate (fail_close|degrade)
//   sandboxDenyCommand    exit-126 rewrite for the infallible create.before
//
// The helper builds the bwrap argv itself; the plugin selects behavior only
// through OPENCODE_SANDBOX_* env vars (contract: native/linux-sandbox/README).

import { execFile } from "node:child_process"
import { randomBytes } from "node:crypto"
import { existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { Perm } from "./permissions"
import { splitSimpleSegments } from "./security/classifier"

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

/** Default helper location inside the installed package. */
export const DEFAULT_SANDBOX_HELPER = path.join(PACKAGE_ROOT, "bin", "opencode-sandbox")

export type SandboxProfile = "ro" | "rw" | "full"

/** The §3.4 sandbox route reported by `opencode-sandbox --probe`
 * ("full" = bwrap floor + Landlock, not the FULL profile). */
export type SandboxPath = "full" | "bwrap-only" | "landlock-only" | "unavailable"

/** The subset of ResolvedSandbox (src/config.ts) the spawn/probe logic needs;
 * structurally compatible so config.ts types satisfy it without an import
 * cycle. */
export type SandboxSelection = {
  enabled: boolean
  mode: "auto" | "ro" | "rw" | "full"
  bwrapPath: string
  helperPath: string
  scratch: string
  roNetwork: "off" | "on"
  /** "on" (default) = RW keeps network; "off" applies the RO network deny to
   * the RW profile. */
  rwNetwork: "on" | "off"
  /** Extra write-freeze (denyWrite) / read-shadow (denyRead) path lists,
   * colon-joined into the helper env. A path in both lists is legal: the
   * helper applies read-shadow first, then write-freeze. */
  denyWrite: readonly string[]
  denyRead: readonly string[]
  /** Permit sudo/setuid escalation (default false). Honest semantics: bwrap
   * sets NNP unconditionally, so "1" + MODE=rw makes the helper run the
   * payload host-direct (no namespace, NNP, or seccomp floor). RO is
   * unaffected (always fully isolated, sudo always refused). */
  allowSudo: boolean
  /** Raw bwrap argv pass-through: each entry is one argv element appended
   * after all helper-generated args, immediately before the `--` payload
   * separator, on ro/rw and the bwrap-only fallback path. */
  extraArgs: readonly string[]
  maskWslInterop: boolean
  maskPrivilegedSockets: readonly string[]
  roAfUnixBlock: boolean
  onUnavailable: "fail_close" | "degrade"
}

export type SandboxProbeResult = {
  /** Whether the helper probe ran and reported a usable route. */
  available: boolean
  path?: SandboxPath
  bwrap?: string
  userns?: boolean
  landlockAbi?: number
  /** Human-readable unavailability reason; never contains secrets. */
  reason?: string
}

// --- profile selection -----------------------------------------------------

/** Effective profile for one shell call. `mode` wins over the perm-derived
 * profile; `enabled:false` or `mode:"full"` always yields "full" (no wrap). */
export function profileForPerm(perm: Perm, sandbox: Pick<SandboxSelection, "enabled" | "mode">): SandboxProfile {
  if (!sandbox.enabled || sandbox.mode === "full") return "full"
  if (sandbox.mode === "ro" || sandbox.mode === "rw") return sandbox.mode
  return perm.w ? "rw" : "ro"
}

// --- privilege-launcher detection -------------------------------------------

/** Commands that need OS-level privilege to actually work. The OS sandbox sets
 * NO_NEW_PRIVS unconditionally and drops capabilities, so under a wrap these
 * fail at runtime (sudo: "Operation not permitted"). The plugin uses this to
 * route privilege-authorized calls host-direct instead (the `privilege` bypass
 * category). Detection is POSITION-BASED, not a whole-text word match: a
 * privilege word in a string/argument/comment position (`grep sudo README.md`,
 * `echo "sudo x"`, `# sudo id`, `printf 'chmod 4755'`) must NOT trigger the
 * routing — over-detection strips the OS sandbox from harmless calls. The
 * script is split into segments (`;`/`&&`/`||`/`|`/newline, comments
 * stripped), each segment's command word is found by skipping leading
 * `VAR=val` assignments, shell keywords and prefix wrappers, and only the
 * command-word position is matched against the families below. Quoted
 * payloads that are themselves executed (`sh -c '…'`, `eval …`, command
 * substitutions) are checked recursively. A script the segment splitter
 * cannot parse (unterminated quotes/heredoc, backticks) falls back to the
 * conservative whole-text match: the old over-inclusive behavior is safer
 * there than a false negative, and privilege is armed anyway. */
const PRIVILEGE_COMMAND_WORDS = new Set([
  // Privilege launchers.
  "sudo",
  "sudoedit",
  "doas",
  "pkexec",
  "runas",
  "su",
  "runuser",
  "setpriv",
  "capsh",
  // Ownership / capability boundary mutators.
  "chown",
  "chgrp",
  "setcap",
  "setfacl",
  // Account / identity boundary mutators.
  "useradd",
  "usermod",
  "userdel",
  "passwd",
  "chpasswd",
  "visudo",
  // Mount / namespace / loop-device / chroot boundary crossing.
  "mount",
  "umount",
  "unshare",
  "nsenter",
  "chroot",
  "losetup",
  // Kernel / firewall / MAC boundary crossing; also fail silently (EPERM)
  // under the sandbox's NNP.
  "modprobe",
  "insmod",
  "rmmod",
  "kexec",
  "iptables",
  "nft",
  "ufw",
  "setenforce",
])

/** POSIX shells whose `-c`/`-lc`-style option argument is a recursively
 * executable payload — the payload is the real execution, so it is scanned
 * with the same position-based rules. */
const SHELL_PAYLOAD_WORDS = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash"])

/** Shell keywords that merely position the real command behind them
 * (`if sudo id`, `while chown …`, `do mount …`). Skipping them keeps the
 * command word in command position. */
const SHELL_KEYWORD_WORDS = new Set(["if", "then", "elif", "else", "while", "until", "do"])

/** Prefix wrappers: the real command word follows the wrapper and its
 * options (`env -u X sudo id`, `nice -n 5 mount …`, `xargs chmod 4755`). */
const WRAPPER_WORDS = new Set([
  "env",
  "command",
  "nohup",
  "time",
  "nice",
  "ionice",
  "stdbuf",
  "timeout",
  "setsid",
  "xargs",
  "exec",
  "builtin",
  "busybox",
  "watch",
])

/** Wrapper options that consume a separate value token (`nice -n 5`). */
const WRAPPER_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  env: new Set(["-u", "--unset", "-S", "--split-string", "-C", "--chdir", "-P", "--path"]),
  nice: new Set(["-n", "--adjustment"]),
  ionice: new Set(["-c", "-n"]),
  timeout: new Set(["-k", "--kill-after", "-s", "--signal"]),
  time: new Set(["-o", "--output", "-f", "--format"]),
  stdbuf: new Set(["-i", "-o", "-e"]),
  xargs: new Set([
    "-I",
    "--replace",
    "-L",
    "--max-lines",
    "-n",
    "--max-args",
    "-P",
    "--max-procs",
    "-s",
    "--max-chars",
    "-a",
    "--arg-file",
    "-d",
    "--delimiter",
    "-E",
    "--eof",
  ]),
  watch: new Set(["-n", "--interval"]),
}

/** Recursion cap for nested payloads (`sh -c 'sh -c …'`, subshells, eval). */
const MAX_PRIVILEGE_SCAN_DEPTH = 6

/** Escape character of the classifier shell dialect (mirrors
 * shellEscapeCharacter in classifier.ts, which is not exported). */
function escapeCharacterFor(shell: string): "\\" | "`" | "^" {
  const name = path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase()
  if (name === "pwsh" || name === "powershell") return "`"
  if (name === "cmd") return "^"
  return "\\"
}

function stripMatchingQuotes(token: string): string {
  if (
    token.length >= 2 &&
    ((token[0] === '"' && token.at(-1) === '"') || (token[0] === "'" && token.at(-1) === "'"))
  ) {
    return token.slice(1, -1)
  }
  return token
}

/** Lowercased executable leaf of a command token: `/usr/bin/sudo`,
 * `./sudo` and `sudo.exe` all resolve to `sudo`. */
function commandWordOf(token: string): string {
  return (
    stripMatchingQuotes(token)
      .replaceAll("\\", "/")
      .split("/")
      .at(-1)
      ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
      .toLowerCase() ?? ""
  )
}

/** `VAR=val` word (assignment positions never execute anything). */
function isAssignmentWord(token: string): boolean {
  const value = stripMatchingQuotes(token)
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(value) && !value.startsWith("-")
}

/** Strip a trailing `#` comment (word-start `#` outside quotes only, so
 * `echo '# sudo'` and `foo#bar` keep their text). */
function stripSegmentComment(text: string): string {
  let quote: "'" | '"' | undefined
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (quote) {
      if (character === quote) quote = undefined
      continue
    }
    if (character === "'" || character === '"') {
      quote = character
      continue
    }
    if (character === "#" && (index === 0 || /[\s;&|(]/.test(text[index - 1] ?? ""))) {
      return text.slice(0, index)
    }
  }
  return text
}

/** Quote/escape-aware tokenizer for one segment. Quoted spans stay whole
 * (`"sudo x"` is one inert token) and `>`/`>>`/`<>` redirects (with optional
 * leading fd digits) split into operator tokens so redirect targets are
 * inspectable positionally. */
function tokenizeSegment(text: string, escape: "\\" | "`" | "^"): string[] {
  const tokens: string[] = []
  let current = ""
  let quote: "'" | '"' | undefined
  const flush = () => {
    if (current !== "") {
      tokens.push(current)
      current = ""
    }
  }
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]
    if (quote === "'") {
      current += character
      if (character === "'") quote = undefined
      continue
    }
    if (quote === '"') {
      current += character
      // Inside double quotes the escape still protects the next character
      // (at minimum the closing quote itself).
      if (character === escape && index + 1 < text.length) {
        current += text[index + 1]
        index += 1
      } else if (character === '"') {
        quote = undefined
      }
      continue
    }
    if (character === escape && index + 1 < text.length) {
      current += character
      current += text[index + 1]
      index += 1
      continue
    }
    if (character === "'" || character === '"') {
      quote = character
      current += character
      continue
    }
    if (/\s/.test(character)) {
      flush()
      continue
    }
    if (character === ">" || (character === "<" && text[index + 1] !== "<")) {
      let operator = /^\d+$/.test(current) ? current : ""
      current = ""
      operator += character
      if (text[index + 1] === character) {
        operator += text[index + 1]
        index += 1
      }
      if (text[index + 1] === ">" && operator.endsWith("<")) {
        operator += ">"
        index += 1
      }
      if (text[index + 1] === "&") {
        operator += "&"
        index += 1
        while (/\d/.test(text[index + 1] ?? "")) {
          operator += text[index + 1]
          index += 1
        }
      }
      tokens.push(operator)
      continue
    }
    current += character
  }
  flush()
  return tokens
}

/** Index of the closing paren matching the one at `open`, quote/escape-aware;
 * undefined when unterminated. */
function findMatchingParen(text: string, open: number): number | undefined {
  let depth = 0
  let quote: "'" | '"' | undefined
  for (let index = open; index < text.length; index += 1) {
    const character = text[index]
    if (quote) {
      if (character === "\\" && quote === '"') index += 1
      else if (character === quote) quote = undefined
      continue
    }
    if (character === "'" || character === '"') {
      quote = character
      continue
    }
    if (character === "\\") {
      index += 1
      continue
    }
    if (character === "(") depth += 1
    else if (character === ")") {
      depth -= 1
      if (depth === 0) return index
    }
  }
  return undefined
}

type SubstitutionScan = { sanitized: string; payloads: string[] }

/** Closing index of the command substitution opening at `index` — `$(`,
 * `>(`/`<(`, or a backtick (in `\`-escape shells) — or undefined when the
 * span is unterminated. Callers check the opening shape first. */
function substitutionClose(text: string, index: number): number | undefined {
  if (text[index] === "`") {
    for (let scan = index + 1; scan < text.length; scan += 1) {
      if (text[scan] === "\\") scan += 1
      else if (text[scan] === "`") return scan
    }
    return undefined
  }
  return findMatchingParen(text, index + 1)
}

/** Heredoc currently being scanned: its delimiter word plus whether the
 * delimiter was quoted (`<<'D'`, `<<"D"`, `<<\D`). A quoted delimiter makes
 * the body literal — no parameter or command expansion happens inside it —
 * while an unquoted one keeps `$(…)`/backtick expansion alive in the body. */
type HeredocScan = { delim: string; quoted: boolean }

/** Extract command substitutions — `$(…)`, `>(…)`/`<(…)`, and (for `\`-escape
 * shells) backticks — replacing each span with the inert placeholder `"_"`
 * and collecting the payloads, which are real execution and get the same
 * scan recursively. Quote-aware: single-quoted spans are literal; inside
 * double quotes only `$(…)`/backticks execute. Heredoc-aware: a
 * quoted-delimiter heredoc body is literal text, so nothing inside it is
 * extracted; an unquoted-delimiter body still expands `$(…)`/backticks,
 * and heredoc bodies have no quoting semantics, so quote characters
 * inside a body never open quote state. Returns undefined when a
 * substitution span or a heredoc body is unterminated (caller falls back
 * to the conservative match — same rule the segment splitter applies). */
function extractCommandSubstitutions(text: string, escape: "\\" | "`" | "^"): SubstitutionScan | undefined {
  const payloads: string[] = []
  let sanitized = ""
  let quote: "'" | '"' | undefined
  let index = 0
  // Heredoc body being scanned (set once the body's opening newline is
  // consumed), the heredoc whose body starts at the next newline, and the
  // body line accumulated for the delimiter-line check.
  let heredoc: HeredocScan | undefined
  let pendingHeredoc: HeredocScan | undefined
  let bodyLine = ""

  // Take the substitution opening at `index` (shape already checked by the
  // caller): pushes the payload, drops the placeholder, and returns false
  // when the span is unterminated.
  const takeSubstitution = (): boolean => {
    const close = substitutionClose(text, index)
    if (close === undefined) return false
    payloads.push(text.slice(text[index] === "`" ? index + 1 : index + 2, close))
    sanitized += '"_"'
    if (heredoc !== undefined) bodyLine += '"_"'
    index = close + 1
    return true
  }

  while (index < text.length) {
    const character = text[index]

    // --- heredoc body: line-scoped, no quoting semantics ---------------
    if (heredoc !== undefined) {
      if (character === "\n") {
        sanitized += character
        if (bodyLine.trim() === heredoc.delim) heredoc = undefined
        bodyLine = ""
        index += 1
        continue
      }
      // Quoted delimiter: the body is literal — copy it verbatim. `\r` is
      // line-ending debris, never an escape or an operator.
      if (heredoc.quoted || character === "\r") {
        sanitized += character
        bodyLine += character
        index += 1
        continue
      }
      // Unquoted delimiter: `$(…)`/backticks still execute in the body;
      // every other character (quotes, `<<`, `#`) is literal data.
      if (character === escape && index + 1 < text.length) {
        sanitized += character + text[index + 1]
        bodyLine += character + text[index + 1]
        index += 2
        continue
      }
      if ((character === "$" && text[index + 1] === "(") || (character === "`" && escape === "\\")) {
        if (!takeSubstitution()) return undefined
        continue
      }
      sanitized += character
      bodyLine += character
      index += 1
      continue
    }

    if (quote === "'") {
      sanitized += character
      if (character === "'") quote = undefined
      index += 1
      continue
    }
    if (quote === '"') {
      if (character === escape && index + 1 < text.length) {
        sanitized += character + text[index + 1]
        index += 2
        continue
      }
      if (character === '"') quote = undefined
      // Inside double quotes $(…)/backticks still execute.
      if ((character === "$" && text[index + 1] === "(") || (character === "`" && escape === "\\")) {
        if (!takeSubstitution()) return undefined
        continue
      }
      sanitized += character
      index += 1
      continue
    }
    if (character === escape && index + 1 < text.length) {
      sanitized += character + text[index + 1]
      index += 2
      continue
    }
    if (character === "'" || character === '"') {
      quote = character
      sanitized += character
      index += 1
      continue
    }
    // Heredoc operator: parse the delimiter (mirroring the classifier's
    // splitCommandSegments, including `<<-` and `<< 'D'` spacing forms) and
    // remember whether it was quoted; the body starts at the next newline.
    // Tokens on the operator's own line stay live (`cat <<'D' $(date)`
    // still expands `$(date)`).
    if (character === "<" && text[index + 1] === "<") {
      let lookAhead = index + 2
      if (text[lookAhead] === "-") lookAhead += 1
      while (lookAhead < text.length && (text[lookAhead] === " " || text[lookAhead] === "\t")) lookAhead += 1
      let delim = ""
      let delimEnd = lookAhead
      let quoted = false
      if (text[lookAhead] === "'" || text[lookAhead] === '"') {
        const delimQuote = text[lookAhead]
        delimEnd = lookAhead + 1
        while (delimEnd < text.length && text[delimEnd] !== delimQuote) {
          delim += text[delimEnd]
          delimEnd += 1
        }
        delimEnd += 1
        quoted = true
      } else {
        // A backslash-escaped delimiter (`<<\EOF`) is the quoted form.
        if (text[delimEnd] === "\\") {
          delimEnd += 1
          quoted = true
        }
        while (delimEnd < text.length && /\w/.test(text[delimEnd])) {
          delim += text[delimEnd]
          delimEnd += 1
        }
      }
      if (delim !== "") {
        sanitized += text.slice(index, delimEnd)
        index = delimEnd
        pendingHeredoc = { delim, quoted }
        continue
      }
    }
    if (character === "\n" && pendingHeredoc !== undefined) {
      heredoc = pendingHeredoc
      pendingHeredoc = undefined
      bodyLine = ""
      sanitized += character
      index += 1
      continue
    }
    if ((character === "$" || character === ">" || character === "<") && text[index + 1] === "(") {
      if (!takeSubstitution()) return undefined
      continue
    }
    if (character === "`" && escape === "\\") {
      if (!takeSubstitution()) return undefined
      continue
    }
    sanitized += character
    index += 1
  }
  // Unterminated heredoc (body never closed, or the operator never even
  // reached its body newline) cannot be parsed positionally: fall back to
  // the conservative whole-text match, exactly like the segment splitter.
  // The delimiter line may end the script without a trailing newline.
  if (pendingHeredoc !== undefined) return undefined
  if (heredoc !== undefined && bodyLine.trim() !== heredoc.delim) return undefined
  return { sanitized, payloads }
}

/** Index of the segment's command word: leading `VAR=val` assignments, shell
 * keywords and prefix wrappers (with their options) are skipped. `command -v`
 * only looks a name up and never executes it, so it reports "no command".
 * `executablePayloads` collects option/operand values that are themselves
 * executed as scripts and therefore must be scanned recursively:
 * `env -S/--split-string <string>` runs the option value, and `watch` runs
 * its remaining operands as one command string (`sh -c`). */
function findCommandWordIndex(tokens: string[], executablePayloads?: string[]): number | undefined {
  let index = 0
  for (;;) {
    while (index < tokens.length && isAssignmentWord(tokens[index] ?? "")) index += 1
    if (index >= tokens.length) return undefined
    const word = commandWordOf(tokens[index] ?? "")
    if (SHELL_KEYWORD_WORDS.has(word)) {
      index += 1
      continue
    }
    if (!WRAPPER_WORDS.has(word)) return index
    const valueFlags = WRAPPER_VALUE_FLAGS[word] ?? new Set<string>()
    index += 1
    if (word === "command" && /^-[vV]$/.test(stripMatchingQuotes(tokens[index] ?? ""))) {
      return undefined
    }
    while (index < tokens.length) {
      const token = tokens[index] ?? ""
      if (token === "--") {
        index += 1
        break
      }
      if (token.startsWith("-") && token !== "-") {
        if (
          executablePayloads !== undefined &&
          word === "env" &&
          (stripMatchingQuotes(token) === "-S" || stripMatchingQuotes(token) === "--split-string") &&
          index + 1 < tokens.length
        ) {
          executablePayloads.push(stripMatchingQuotes(tokens[index + 1] ?? ""))
        }
        index += valueFlags.has(token) ? 2 : 1
        continue
      }
      break
    }
    if (word === "env") {
      while (index < tokens.length && isAssignmentWord(tokens[index] ?? "")) index += 1
    } else if (word === "timeout") {
      // `timeout <duration> cmd …`: one bare operand precedes the command.
      if (index < tokens.length) index += 1
    } else if (word === "watch") {
      // watch concatenates its operands and executes them via `sh -c` —
      // they are not a command word in this segment's command position.
      const operand = tokens.slice(index).map(stripMatchingQuotes).join(" ").trim()
      if (operand !== "") executablePayloads?.push(operand)
    }
  }
}

function isProcSysPath(value: string): boolean {
  return value === "/proc/sys" || value.startsWith("/proc/sys/")
}

/** `> /proc/sys/…` kernel-parameter writes, regardless of the command word. */
function redirectsIntoProcSys(tokens: string[]): boolean {
  for (let index = 0; index + 1 < tokens.length; index += 1) {
    if (/^\d*(?:>>|<>|>)$/.test(tokens[index] ?? "") && isProcSysPath(stripMatchingQuotes(tokens[index + 1] ?? ""))) {
      return true
    }
  }
  return false
}

/** chmod sets the setuid/setgid bit: symbolic `+s` (also inside mode lists
 * like `u+rwx,g+s`) or a 4-digit octal mode with leading 2/4/6. `1777`
 * (sticky) and plain 3-digit modes do not. */
function chmodSetsPrivilegeBit(args: string[]): boolean {
  return args.some((token) => {
    const value = stripMatchingQuotes(token)
    return /^[246][0-7]{3}$/.test(value) || /\+s\b/.test(value)
  })
}

/** `sysctl` kernel-parameter writes: `-w`/`--write key=val`, positional
 * `key=val`, and the file-loading forms `-p`/`--load`/`--system` (applying
 * settings is a write, same as `-w`). Plain reads (`sysctl -a`,
 * `sysctl kernel.x`) are not. */
function sysctlWrites(args: string[]): boolean {
  return args.some((token) => {
    const value = stripMatchingQuotes(token)
    return (
      value === "-w" ||
      value === "--write" ||
      value === "-p" ||
      value === "--system" ||
      value.startsWith("--load") ||
      value.includes("=")
    )
  })
}

/** Privileged-container arguments: `--privileged`/`--privileged=true` (an
 * explicit `--privileged=false` disables it and must NOT match), the host
 * PID namespace in both spellings (`--pid=host`, `--pid host`), and
 * docker-socket mounts (mirrors the static infrastructure rule). */
function containerArgsNeedPrivilege(args: string[]): boolean {
  for (let index = 0; index < args.length; index += 1) {
    const value = stripMatchingQuotes(args[index] ?? "")
    if (value === "--privileged" || value === "--privileged=true") return true
    if (value === "--pid=host") return true
    if (value === "--pid" && stripMatchingQuotes(args[index + 1] ?? "") === "host") return true
    if (value.includes("docker.sock")) return true
  }
  return false
}

/** Command-position check for one already-tokenized segment. */
function tokensNeedOsPrivilege(tokens: string[], shell: string, depth: number): boolean {
  if (redirectsIntoProcSys(tokens)) return true
  // Wrapper option/operand values that are themselves executed as scripts
  // (`env -S 'sudo id'`, `watch 'sudo id'`) get the recursive scan first:
  // they run even when no further command word follows the wrapper.
  const executablePayloads: string[] = []
  const commandIndex = findCommandWordIndex(tokens, executablePayloads)
  for (const payload of executablePayloads) {
    if (payload.trim() !== "" && commandNeedsOsPrivilege(payload, shell, depth + 1)) return true
  }
  if (commandIndex === undefined) return false
  const word = commandWordOf(tokens[commandIndex] ?? "")
  const args = tokens.slice(commandIndex + 1)

  // A command-position token ending in `)` is a `case` branch pattern
  // (`PATTERN) COMMANDS`): the splitter cut the script at every `;`, so
  // branches after the first `;;` arrive as their own segments that START
  // with the pattern token — the tokens after it are in command position.
  // (A leading balanced `( … )` subshell was already resolved in
  // segmentNeedsOsPrivilege; a function definition head `foo() { … }`
  // only DEFINES the body, and the recursion below correctly leaves
  // `{ sudo … }` untriggered because `{` is not a command word.)
  if (stripMatchingQuotes(tokens[commandIndex] ?? "").endsWith(")")) {
    const rest = tokens.slice(commandIndex + 1)
    return rest.length > 0 && tokensNeedOsPrivilege(rest, shell, depth + 1)
  }

  if (PRIVILEGE_COMMAND_WORDS.has(word)) return true
  if (word === "chmod") return chmodSetsPrivilegeBit(args)
  if (word === "sysctl") return sysctlWrites(args)
  if (word === "case") {
    // `case WORD in PATTERN) COMMANDS ;; …` — every `)`-terminated pattern
    // token puts the tokens between it and the next pattern token (or the
    // end of the segment) in command position.
    const inIndex = args.findIndex((token) => stripMatchingQuotes(token) === "in")
    const body = inIndex >= 0 ? args.slice(inIndex + 1) : []
    for (let index = 0; index < body.length; index += 1) {
      if (!stripMatchingQuotes(body[index] ?? "").endsWith(")")) continue
      let end = index + 1
      while (end < body.length && !stripMatchingQuotes(body[end] ?? "").endsWith(")")) end += 1
      const slice = body.slice(index + 1, end)
      if (slice.length > 0 && tokensNeedOsPrivilege(slice, shell, depth + 1)) return true
    }
    return false
  }
  if (word === "eval") {
    // eval concatenates its arguments and runs them as a script.
    const payload = args.map(stripMatchingQuotes).join(" ").trim()
    return payload !== "" && commandNeedsOsPrivilege(payload, shell, depth + 1)
  }
  if (SHELL_PAYLOAD_WORDS.has(word)) {
    // `sh -c '…'` (also `-lc`, `-ic`, …): the option argument is the real
    // execution. Later tokens become $0/$1, not commands.
    const flagIndex = args.findIndex((token) => /^-[A-Za-z]*c[A-Za-z]*$/.test(stripMatchingQuotes(token)))
    if (flagIndex >= 0 && flagIndex + 1 < args.length) {
      const payload = stripMatchingQuotes(args[flagIndex + 1] ?? "").trim()
      if (payload !== "" && commandNeedsOsPrivilege(payload, shell, depth + 1)) return true
    }
    return false
  }
  if (word === "docker" || word === "podman" || word === "nerdctl") {
    return containerArgsNeedPrivilege(args)
  }
  if (word === "find") {
    // `find … -exec cmd …` executes the payload command positionally.
    for (let index = 0; index < args.length; index += 1) {
      const flag = stripMatchingQuotes(args[index] ?? "")
      if (flag !== "-exec" && flag !== "-execdir" && flag !== "-ok" && flag !== "-okdir") continue
      let end = args.findIndex((token, at) => at > index && (token === ";" || token === "\\;" || token === "+"))
      if (end === -1) end = args.length
      const slice = args.slice(index + 1, end)
      if (slice.length > 0 && tokensNeedOsPrivilege(slice, shell, depth + 1)) return true
    }
    return false
  }
  if (word === "dd") {
    return args.some((token) => {
      const value = stripMatchingQuotes(token).toLowerCase()
      return value.startsWith("of=") && isProcSysPath(value.slice(3))
    })
  }
  if (word === "tee" || word === "truncate") {
    return args.some((token) => isProcSysPath(stripMatchingQuotes(token)))
  }
  if (word === "cp" || word === "mv" || word === "install" || word === "rsync") {
    // Trailing destination argument (same shape the classifier's
    // kernel-floor write test uses).
    const operands = args.map(stripMatchingQuotes).filter((token) => !token.startsWith("-") && token !== "")
    const destination = operands.at(-1)
    return destination !== undefined && isProcSysPath(destination)
  }
  return false
}

/** Delimiter words of the heredoc operators (`<<EOF`, `<<'EOF'`, `<<-EOF`) on
 * one command line, in order; quote/escape-aware so `echo '<<EOF'` is inert. */
function heredocOperandDelimiters(head: string, escape: "\\" | "`" | "^"): string[] {
  const delimiters: string[] = []
  let quote: "'" | '"' | undefined
  for (let index = 0; index < head.length; index += 1) {
    const character = head[index]
    if (quote) {
      if (quote === '"' && character === escape && index + 1 < head.length) index += 1
      else if (character === quote) quote = undefined
      continue
    }
    if (character === escape && index + 1 < head.length) {
      index += 1
      continue
    }
    if (character === "'" || character === '"') {
      quote = character
      continue
    }
    if (character !== "<" || head[index + 1] !== "<") continue
    let cursor = index + 2
    if (head[cursor] === "-") cursor += 1
    while (head[cursor] === " " || head[cursor] === "\t") cursor += 1
    let delim = ""
    if (head[cursor] === "'" || head[cursor] === '"') {
      const delimQuote = head[cursor]
      cursor += 1
      while (cursor < head.length && head[cursor] !== delimQuote) {
        delim += head[cursor]
        cursor += 1
      }
      cursor += 1
    } else {
      if (head[cursor] === escape) cursor += 1
      while (cursor < head.length && /\w/.test(head[cursor] ?? "")) {
        delim += head[cursor]
        cursor += 1
      }
    }
    if (delim !== "") {
      delimiters.push(delim)
      index = cursor - 1
    }
  }
  return delimiters
}

/** A heredoc body is a script when its consumer is a shell (`bash <<'EOF' …
 * EOF`, `env bash <<EOF … EOF`): the shell runs the body from stdin, so the
 * body gets the same position-based scan, quoted or unquoted delimiter alike.
 * Bodies consumed by anything else (`cat`, `python3`, `tee …`) are inert data
 * and stay undetected — same as a heredoc that is never executed. */
function shellHeredocBodyNeedsOsPrivilege(
  segment: string,
  shell: string,
  escape: "\\" | "`" | "^",
  depth: number,
): boolean {
  const newline = segment.indexOf("\n")
  if (newline < 0) return false
  const head = segment.slice(0, newline)
  const delimiters = heredocOperandDelimiters(head, escape)
  if (delimiters.length === 0) return false
  const tokens = tokenizeSegment(head, escape)
  const commandIndex = findCommandWordIndex(tokens)
  if (commandIndex === undefined || !SHELL_PAYLOAD_WORDS.has(commandWordOf(tokens[commandIndex] ?? ""))) return false
  // Bodies follow the command line in operator order; each ends at its own
  // delimiter line (`<<-` allows leading tabs, hence the trim).
  const bodies: string[] = []
  let body: string[] = []
  let at = 0
  for (const line of segment.slice(newline + 1).split("\n")) {
    if (at >= delimiters.length) break
    if (line.trim() === delimiters[at]) {
      bodies.push(body.join("\n"))
      body = []
      at += 1
      continue
    }
    body.push(line)
  }
  return bodies.some((payload) => payload.trim() !== "" && commandNeedsOsPrivilege(payload, shell, depth + 1))
}

/** One split segment: strip comments, resolve leading `!`/`{`/`(` compound
 * punctuation (a leading balanced `(` group is its own executable subshell),
 * then check the command position. */
function segmentNeedsOsPrivilege(segment: string, shell: string, escape: "\\" | "`" | "^", depth: number): boolean {
  let code = stripSegmentComment(segment).trim()
  if (code === "") return false
  for (;;) {
    if (code.startsWith("!")) {
      code = code.slice(1).trim()
      continue
    }
    if (code.startsWith("{") && /^\s/.test(code.slice(1))) {
      code = code.slice(1).trim()
      continue
    }
    if (code.startsWith("(")) {
      const close = findMatchingParen(code, 0)
      if (close !== undefined) {
        const interior = code.slice(1, close).trim()
        const tail = code.slice(close + 1).trim()
        if (interior !== "" && commandNeedsOsPrivilege(interior, shell, depth + 1)) return true
        if (tail === "") return false
        code = tail
      } else {
        code = code.slice(1).trim()
      }
      continue
    }
    break
  }
  if (code === "") return false
  const tokens = tokenizeSegment(code, escape)
  if (tokens.length === 0) return false
  if (tokensNeedOsPrivilege(tokens, shell, depth)) return true
  // A heredoc body fed to a shell consumer is a script that shell runs from
  // stdin (`bash <<EOF … EOF`), so it is scanned like any other executable
  // payload; bodies for `cat`/`python3`/`tee` stay data.
  return shellHeredocBodyNeedsOsPrivilege(code, shell, escape, depth)
}

/** Conservative whole-text match, used only when the script cannot be parsed
 * (unterminated quotes/heredoc, stray backticks): keeps the pre-rework
 * over-inclusive behavior plus the new families. Such scripts are broken or
 * substitution-heavy, and privilege is armed anyway, so a false negative
 * (silent sandbox failure) is the worse failure mode there. */
function conservativePrivilegeMatch(script: string): boolean {
  return (
    PRIVILEGE_LAUNCHER_FALLBACK_RE.test(script) ||
    CHMOD_SETUID_RE.test(script) ||
    /--privileged\b|--pid=host\b|docker\.sock/i.test(script) ||
    /(?:>|>>|of=)\s*\/proc\/sys\//i.test(script)
  )
}

const PRIVILEGE_LAUNCHER_FALLBACK_RE =
  /\b(?:sudo(?:edit)?|doas|pkexec|runas|su|runuser|setpriv|capsh|chown|chgrp|setcap|setfacl|useradd|usermod|userdel|passwd|chpasswd|visudo|mount|umount|unshare|nsenter|chroot|losetup|modprobe|insmod|rmmod|kexec|iptables|nft|ufw|setenforce|sysctl)\b/i
const CHMOD_SETUID_RE = /\bchmod\b[^\n;|&]*(?:\+s\b|u\+s\b|g\+s\b|\b[246][0-7]{3}\b)/i

/** True when the script executes anything that needs OS-level privilege:
 * a privilege launcher, an ownership/capability/mount/namespace mutator, a
 * kernel-module loader, a `sysctl` write, a `/proc/sys` write, or a
 * privileged container — in COMMAND position (see the block comment above).
 * `shell` selects the tokenizer dialect and defaults to `/bin/bash`. */
export function commandNeedsOsPrivilege(script: string, shell: string = "/bin/bash", depth = 0): boolean {
  if (depth >= MAX_PRIVILEGE_SCAN_DEPTH || script === "") return conservativePrivilegeMatch(script)
  const escape = escapeCharacterFor(shell)
  const extracted = extractCommandSubstitutions(script, escape)
  if (extracted === undefined) return conservativePrivilegeMatch(script)
  for (const payload of extracted.payloads) {
    if (payload.trim() !== "" && commandNeedsOsPrivilege(payload, shell, depth + 1)) return true
  }
  const segments = splitSimpleSegments(extracted.sanitized, shell)
  if (segments === undefined) return conservativePrivilegeMatch(script)
  for (const segment of segments) {
    if (segmentNeedsOsPrivilege(segment, shell, escape, depth)) return true
  }
  return false
}

// --- nonce markers ---------------------------------------------------------

// `: opencode-sandbox <hex>` is a POSIX no-op (the `:` builtin) so even if the
// marker ever reached a real shell it is inert; it is consumed and stripped
// by create.before before that can happen.
const MARKER_PREFIX = ": opencode-sandbox "
const MARKER_LINE = /^: opencode-sandbox ([0-9a-f]{32})\r?\n?/
const MARKER_TTL_MS = 60_000
const MAX_MARKERS = 1024

export type SandboxMarkers = Map<string, { profile: SandboxProfile; expiresAt: number; hostDirect?: boolean }>

export function createSandboxMarkers(): SandboxMarkers {
  return new Map()
}

function pruneMarkers(markers: SandboxMarkers, now: number) {
  for (const [nonce, entry] of markers) {
    if (entry.expiresAt <= now) markers.delete(nonce)
  }
  while (markers.size >= MAX_MARKERS) {
    const oldest = markers.keys().next().value
    if (oldest === undefined) break
    markers.delete(oldest)
  }
}

/** Prepend the nonce marker line to a command. The nonce is generated after
 * the model produced the tool call and never enters the transcript, so it is
 * unforgeable; a miss at create.before means the spawn runs bare (pre-P4
 * behavior — the classifier still gated the command at execute.before).
 * `hostDirect` marks the per-call host-direct routing (the `privilege`
 * bypass category): create.before then wraps through the helper with
 * ALLOW_SUDO=1 even when sandbox.allowSudo is false. */
export function insertSandboxMarker(
  markers: SandboxMarkers,
  command: string,
  profile: SandboxProfile,
  nonce: string = randomBytes(16).toString("hex"),
  now: number = Date.now(),
  hostDirect?: boolean,
): string {
  pruneMarkers(markers, now)
  markers.set(nonce, { profile, expiresAt: now + MARKER_TTL_MS, hostDirect })
  return `${MARKER_PREFIX}${nonce}\n${command}`
}

/** Strip a leading marker line if present (first line only, at most once).
 * Returns the command unchanged when there is no marker. */
export function stripSandboxMarker(command: string): string {
  const match = MARKER_LINE.exec(command)
  return match ? command.slice(match[0].length) : command
}

/**
 * Consume the marker at create.before time. On a hit the marker line is
 * stripped and the stored profile returned. On a miss — unknown nonce,
 * expired entry, or no marker at all — the command is returned untouched so
 * the spawn runs bare (an expired entry is also deleted, and the no-op
 * marker line stays in place, inert for a real shell).
 */
export function extractSandboxMarker(
  markers: SandboxMarkers,
  command: string,
  now: number = Date.now(),
): { command: string; profile?: SandboxProfile; hostDirect?: boolean } {
  const match = MARKER_LINE.exec(command)
  if (!match) return { command }
  const entry = markers.get(match[1])
  if (!entry) return { command }
  markers.delete(match[1])
  if (entry.expiresAt <= now) return { command }
  return { command: command.slice(match[0].length), profile: entry.profile, hostDirect: entry.hostDirect }
}

// --- spawn wrapping --------------------------------------------------------

export type SandboxSpawnSpec = {
  /** Path the helper will re-exec as --stage2 inside bwrap. */
  helperPath: string
  env: Record<string, string>
}

/** Compute the env contract the helper reads (README "Environment contract").
 * `exists` decides whether a privileged socket still earns a mask slot —
 * injectable for tests (the helper re-checks at spawn time, so filtering here
 * only keeps the env var short). RO-only toggles are emitted only for "ro". */
export function buildSandboxSpawn(
  profile: SandboxProfile,
  sandbox: SandboxSelection,
  exists: (path: string) => boolean = existsSync,
  hostDirect?: boolean,
): SandboxSpawnSpec {
  const mode = profile === "ro" ? "ro" : "rw"
  const env: Record<string, string> = {
    OPENCODE_SANDBOX_MODE: mode,
    OPENCODE_SANDBOX_SCRATCH: sandbox.scratch,
    OPENCODE_SANDBOX_BWRAP: sandbox.bwrapPath,
    OPENCODE_SANDBOX_HELPER: sandbox.helperPath,
    OPENCODE_SANDBOX_MASK_SOCKETS: sandbox.maskPrivilegedSockets.filter((socket) => exists(socket)).join(":"),
    // denyRead shadows reads, denyWrite freezes writes; the same path may be
    // in both (the helper applies read-shadow first, then write-freeze).
    OPENCODE_SANDBOX_DENY_WRITE: sandbox.denyWrite.join(":"),
    OPENCODE_SANDBOX_DENY_READ: sandbox.denyRead.join(":"),
    OPENCODE_SANDBOX_RW_NETWORK: sandbox.rwNetwork === "on" ? "1" : "0",
    // "1" + MODE=rw tells the helper to skip bwrap and run the payload
    // host-direct (no namespace, NNP, or seccomp floor) — the only way sudo
    // can actually work, since bwrap sets NNP unconditionally. RO ignores it.
    // `hostDirect` is the per-call variant of the same route, armed by the
    // `privilege` bypass category for one privilege-needing call.
    OPENCODE_SANDBOX_ALLOW_SUDO: sandbox.allowSudo || hostDirect === true ? "1" : "0",
    // Raw bwrap argv pass-through: one argv element per line, appended after
    // all helper-generated args immediately before the `--` payload separator
    // (later mounts shadow earlier ones). NOTE: --setenv/--unsetenv entries
    // reach stage2's environment and can override env-read controls such as
    // OPENCODE_SANDBOX_SCRATCH, weakening the RO Landlock write-freeze —
    // trusted-config authority, same trust level as mode:"full".
    OPENCODE_SANDBOX_EXTRA_ARGS: sandbox.extraArgs.join("\n"),
  }
  if (mode === "ro") {
    env.OPENCODE_SANDBOX_RO_NETWORK = sandbox.roNetwork
    env.OPENCODE_SANDBOX_MASK_WSL_INTEROP = sandbox.maskWslInterop ? "1" : "0"
    env.OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK = sandbox.roAfUnixBlock ? "1" : "0"
  }
  return { helperPath: sandbox.helperPath, env }
}

/** Rewrite a create.before event (or any {shell, env} pair) so the spawn runs
 * under the helper. `ev.shell` is preserved via OPENCODE_REAL_BASH — the
 * helper execs it as the final stage. No-op for the "full" profile. */
export function wrapShellForSandbox(
  ev: { shell: string; env: Record<string, string | undefined> },
  profile: SandboxProfile,
  sandbox: SandboxSelection,
  exists?: (path: string) => boolean,
  hostDirect?: boolean,
): void {
  if (profile === "full") return
  const spec = buildSandboxSpawn(profile, sandbox, exists, hostDirect)
  ev.env.OPENCODE_REAL_BASH = ev.shell
  for (const [key, value] of Object.entries(spec.env)) ev.env[key] = value
  ev.shell = spec.helperPath
}

/** Linux create.before body, extracted so the authority rule is unit-testable.
 * The nonce marker is the SOLE source of truth for wrapping: user-initiated
 * shells (`!cmd`, host-internal spawns) never ran execute.before, carry no
 * marker, and are trusted authority — they are returned byte-identical,
 * unsandboxed, exactly as they were never classified.
 *
 * An expired or unknown marker also runs bare: that is pre-P4 behavior — the
 * command was still gated by the classifier at execute.before; only the
 * kernel wrap is skipped. The safe direction is unchanged (classifier
 * denials still apply, an unknown marker can never cause a wrap).
 *
 * Marker present → the marker line is stripped and the profile wrapped;
 * "full" (sandbox-bypass category / kill switch carrier) returns untouched.
 * The fail_close exit-126 rewrite applies ONLY to marker-present spawns
 * whose probe reports unavailable — belt-and-suspenders, since runBefore
 * already gates tool shells; marker-less spawns are never denied here.
 *
 * `marked` is the extractSandboxMarker result (extraction happens in
 * index.ts on every platform so an explicit "full" marker also skips the
 * Windows supervisor wrap). Returns the resolved profile. */
export function applySandboxCreateBefore(
  ev: { command: string; shell: string; env: Record<string, string | undefined> },
  marked: { command: string; profile?: SandboxProfile; hostDirect?: boolean },
  sandbox: SandboxSelection,
  probe: SandboxProbeResult | undefined,
): SandboxProfile | undefined {
  if (!marked.profile) return undefined
  ev.command = marked.command
  if (marked.profile === "full") return "full"
  if (marked.profile === "rw" && (sandbox.allowSudo || marked.hostDirect === true)) {
    // Host-direct route (config allowSudo, or the `privilege` bypass
    // category routing this one call out of the sandbox): no bwrap/Landlock.
    // Still go through the helper (it owns the routing) — a missing/broken
    // helper must surface as an execution failure, not a silent bare-shell
    // fallback.
    wrapShellForSandbox(ev, marked.profile, sandbox, undefined, marked.hostDirect)
    return marked.profile
  }
  if (!probe?.available) {
    if (probe !== undefined && !probe.available && sandbox.onUnavailable === "fail_close") {
      ev.command = sandboxDenyCommand(
        sandboxUnavailableMessage(probe.reason ?? "probe did not run"),
      )
    }
    // degrade (or no probe at all): leave the spawn untouched.
    return marked.profile
  }
  wrapShellForSandbox(ev, marked.profile, sandbox)
  return marked.profile
}

// --- startup probe -----------------------------------------------------------

/** Parse `opencode-sandbox --probe` output (key: value lines). Exported for
 * the §3.4 decision-table unit tests. */
export function parseSandboxProbe(stdout: string): Omit<SandboxProbeResult, "available"> {
  const fields: Record<string, string> = {}
  for (const line of stdout.split("\n")) {
    const sep = line.indexOf(":")
    if (sep > 0) fields[line.slice(0, sep).trim()] = line.slice(sep + 1).trim()
  }
  const bwrap = fields.bwrap && fields.bwrap !== "not found" ? fields.bwrap : undefined
  const abi = Number.parseInt(fields.landlock_abi ?? "", 10)
  const landlockAbi = Number.isFinite(abi) ? abi : undefined
  const path = fields.sandbox_path as SandboxPath | undefined
  const validPath =
    path === "full" || path === "bwrap-only" || path === "landlock-only" || path === "unavailable"
      ? path
      : undefined
  const userns = fields.userns?.startsWith("yes")
  const reason =
    validPath && validPath !== "unavailable"
      ? undefined
      : `bwrap: ${bwrap ?? "not found"}, Landlock: ${landlockAbi && landlockAbi > 0 ? `ABI ${landlockAbi}` : "unavailable"}`
  return { path: validPath, bwrap, userns, landlockAbi, reason }
}

const PROBE_TIMEOUT_MS = 10_000

function defaultProbeRun(helperPath: string, env: Record<string, string>): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      helperPath,
      ["--probe"],
      { timeout: PROBE_TIMEOUT_MS, env: { ...process.env, ...env } },
      (error, stdout) => {
        if (error) reject(error)
        else resolve(stdout)
      },
    )
  })
}

/** Run the helper's `--probe` and classify the result per §3.4. Any spawn or
 * parse failure reports unavailable with a sanitized reason. `run` is
 * injectable so tests can feed synthetic probe output. */
export async function probeLinuxSandbox(
  sandbox: Pick<SandboxSelection, "helperPath" | "bwrapPath">,
  run: (helperPath: string, env: Record<string, string>) => Promise<string> = defaultProbeRun,
): Promise<SandboxProbeResult> {
  try {
    const stdout = await run(sandbox.helperPath, { OPENCODE_SANDBOX_BWRAP: sandbox.bwrapPath })
    const parsed = parseSandboxProbe(stdout)
    const available = parsed.path !== undefined && parsed.path !== "unavailable"
    return { available, ...parsed }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error)
    return { available: false, reason: `helper probe failed: ${detail.slice(0, 200)}` }
  }
}

// --- availability gate / fail modes -----------------------------------------

/** §4.3 deny message. Reason contains no secrets (probe fields only). The
 * remedy is user-side: the agent must not install bubblewrap or relax the
 * sandbox configuration itself, so the message names the user explicitly. */
export function sandboxUnavailableMessage(reason: string): string {
  return (
    `OS sandbox unavailable (${reason}). Refusing shell execution. ` +
    `Report this to the user: only the user may install bubblewrap or set sandbox.onUnavailable:'degrade' ` +
    `to accept classifier-only risk; do not work around it with other commands.`
  )
}

/** Gate called from runBefore for non-full profiles. Returns "ok" when the
 * sandbox can be built, "degraded" when onUnavailable opted into running
 * classifier-only; throws (with the §4.3 message) under fail_close.
 *
 * `rw + allowSudo` resolves to the helper's host-direct route, which never
 * invokes bwrap or Landlock — an unavailable probe does not make it
 * unrunnable, so the gate reports "ok". The kernel isolation the probe
 * measures is intentionally absent on that route (allowSudo is the explicit
 * opt-out); the classifier still gates the command. RO stays fail-close
 * regardless of allowSudo. */
export function assertSandboxAvailable(
  profile: SandboxProfile,
  probe: SandboxProbeResult | undefined,
  onUnavailable: "fail_close" | "degrade",
  allowSudo = false,
): "ok" | "degraded" {
  if (profile === "full") return "ok"
  if (profile === "rw" && allowSudo) return "ok"
  if (probe?.available) return "ok"
  if (onUnavailable === "degrade") return "degraded"
  throw new Error(sandboxUnavailableMessage(probe?.reason ?? "probe did not run"))
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

/** create.before cannot reject (failure channel `never`), so the fail_close
 * deny is expressed as a command that prints the §4.3 message and exits 126
 * (POSIX "cannot execute") in the real shell. */
export function sandboxDenyCommand(message: string): string {
  return `printf '%s\\n' ${shellQuote(message)} >&2; exit 126`
}

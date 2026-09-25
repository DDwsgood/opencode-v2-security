// Static detection of safe-but-wasteful commands via real AST (shell-scan).
// Covers unbounded filesystem scans, never-exiting streams, dev-servers, long sleeps, infinite loops.
// Rewritten per reason调研: introduces shell-scan AST, expanded expensive roots, wrapper/timeout unwrapping,
// multiple roots for find, dev-server detection, and independent switch handling.
import path from "node:path"
import { scan } from "./shell-scan"

export type SlowCommandFinding = {
  kind: "unbounded-scan" | "never-exits" | "long-sleep" | "dev-server" | "infinite-loop"
  reason: string
  rule?: string
}

// Short English hints
const OPTIMIZE_HINT =
  "High-cost scan without maxdepth or explicit timeout; narrow scope or set explicit timeout"

const NEVER_EXITS_HINT = "Command never exits, use explicit timeout or background:true"
const SLEEP_HINT = "Sleep too long, use shorter wait or readiness check with explicit timeout"
const DEV_SERVER_HINT = "Dev server runs persistently, use background:true or explicit timeout"
const LOOP_HINT = "Infinite loop without exit, add condition or use timeout/background"

const HOME_CACHE_DIRS = new Set([
  ".cache",
  ".npm",
  ".cargo",
  ".rustup",
  ".nvm",
  ".local",
  ".m2",
  ".gradle",
  ".nuget",
  ".vscode-server",
  ".cursor-server",
  ".pyenv",
  ".ollama",
  ".conda",
  ".pixi",
  ".yarn",
  ".pnpm-store",
])

// System/mount trees where only the root itself is expensive. A specific
// subdirectory (e.g. /usr/share/doc or /proc/self) is bounded and must not be
// flagged as an unbounded scan.
const EXPENSIVE_SYSTEM_ROOTS = new Set([
  "/",
  "/mnt",
  "/media",
  "/proc",
  "/sys",
  "/dev",
  "/usr",
  "/var",
  "/opt",
  "/srv",
  "/boot",
  "/root",
  "/etc",
  "/run",
  "/home",
  "/users",
])

// Commands that can cause unbounded scans
const SCAN_COMMANDS = new Set(["find", "du", "grep", "rg", "ls", "diff", "fd", "tar", "cp", "rsync"])

const WRAPPER_SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh"])
const TIMEOUT_COMMANDS = new Set(["timeout", "gtimeout"])

function normalizeSlashes(value: string): string {
  const clean = value.replaceAll("\\", "/").replace(/\/+$/, "")
  return clean === "" && value.includes("/") ? "/" : clean
}

function expandTilde(value: string): string {
  const home = process.env.USERPROFILE ?? process.env.HOME ?? ""
  if (!home) return value
  if (value === "~") return home
  if (value.startsWith("~/")) return path.join(home, value.slice(2))
  return value
}

function isExpensiveRoot(rawRoot: string, cwd: string, worktree: string): boolean {
  const value = rawRoot.trim().replace(/^["']|["']$/g, "")
  if (!value || value.startsWith("-")) return false
  // Expand $HOME / ${HOME} (and their path suffixes) to the real home directory so
  // `find $HOME` is treated identically to `find ~`. Other $-variables are left
  // unresolved — we cannot statically know their value, and blocking them would
  // be a false positive (e.g. `find $BUILD_DIR` where $BUILD_DIR is a project path).
  const home = process.env.HOME ?? process.env.USERPROFILE ?? ""
  let resolved = value
  if (home) {
    if (value === "$HOME") resolved = home
    else if (value.startsWith("$HOME/")) resolved = path.join(home, value.slice(5))
    else if (value === "${HOME}") resolved = home
    else if (value.startsWith("${HOME}/")) resolved = path.join(home, value.slice(7))
  }
  if (resolved === value && value.startsWith("$")) return false
  if (/^https?:/i.test(resolved)) return false

  let absolute: string
  if (resolved === "~" || resolved.startsWith("~/")) {
    absolute = normalizeSlashes(expandTilde(resolved))
  } else if (path.isAbsolute(resolved)) {
    absolute = normalizeSlashes(resolved)
  } else {
    absolute = normalizeSlashes(path.resolve(cwd, resolved))
  }
  if (!absolute.startsWith("/")) return false

  const worktreeNorm = normalizeSlashes(path.resolve(worktree)).toLowerCase()
  const lower = absolute.toLowerCase()
  if (lower === worktreeNorm || lower.startsWith(worktreeNorm + "/")) return false

  // /tmp and /var/tmp: only the roots themselves are expensive; subdirectories
  // (e.g. /tmp/opencode, /var/tmp/build) are routine work areas and must not be flagged.
  if (lower === "/tmp" || lower === "/var/tmp") return true
  if (lower.startsWith("/tmp/") || lower.startsWith("/var/tmp/")) return false

  // Root and system/mount trees: only the roots themselves are expensive.
  if (EXPENSIVE_SYSTEM_ROOTS.has(lower)) return true
  if (/^\/(?:home|users)\/[^/]+\/?$/.test(lower)) return true
  const homeMatch = lower.match(/^\/(?:home|users)\/[^/]+\/(.+)$/)
  if (homeMatch) {
    const rest = homeMatch[1] ?? ""
    const next = rest.split("/")[0] ?? ""
    // Only the known cache-like hidden directories themselves are expensive
    // (e.g. ~/.cache, ~/.local, ~/.npm). Specific subdirectories such as
    // ~/.cache/opencode or ~/.local/share/opencode are bounded and must not be
    // flagged.
    if (next.startsWith(".")) {
      if (HOME_CACHE_DIRS.has(next) && rest === next) return true
      return false
    }
  }
  return false
}

// --- flag helpers operating on words[] (already quote-resolved) ---

function hasFlag(words: string[], predicate: (flag: string, raw: string) => boolean): boolean {
  for (let i = 1; i < words.length; i++) {
    const raw = words[i] ?? ""
    const lower = raw.toLowerCase()
    if (predicate(lower, raw)) return true
  }
  return false
}

function flagValue(words: string[], names: string[]): string | undefined {
  for (let i = 1; i < words.length; i++) {
    const raw = words[i] ?? ""
    const lower = raw.toLowerCase()
    if (names.includes(lower)) return words[i + 1]
    for (const name of names) {
      if (name.startsWith("--") && lower.startsWith(name + "=")) return raw.slice(name.length + 1)
    }
    // Handle combined: --max-depth=3 already handled; -maxdepth 3 is separate
  }
  return undefined
}

function depthAtMost(words: string[], limit: number): boolean {
  const raw = flagValue(words, ["-maxdepth", "--max-depth", "--maxdepth"])
  if (raw === undefined) return false
  const depth = Number.parseInt(raw, 10)
  return Number.isFinite(depth) && depth >= 0 && depth <= limit
}

function hasRecursiveFlag(words: string[]): boolean {
  return hasFlag(words, (f, raw) => f === "-r" || f === "-r-" || f === "--recursive" || /^-[a-z]*r[a-z]*$/.test(f))
}

function hasLsRecursive(words: string[]): boolean {
  return hasFlag(words, (_f, raw) => raw === "-R" || raw === "--recursive" || /^-[a-z]*R/.test(raw))
}

function hasDiffRecursive(words: string[]): boolean {
  return hasFlag(words, (f) => f === "-r" || f === "--recursive")
}

// Extract positionals: words after leaf that are not flags and not flag values
// This is a best-effort; flag values for known flags are skipped
const FLAGS_WITH_VALUE: Record<string, Set<string>> = {
  find: new Set(["-maxdepth", "--max-depth", "-mindepth", "-name", "-iname", "-path", "-ipath", "-regex", "-iregex", "-type", "-user", "-group", "-perm", "-size", "-mtime", "-atime", "-ctime", "-exec", "-execdir", "-ok", "-okdir", "-printf", "-fprintf"]),
  grep: new Set(["-A", "-B", "-C", "--context", "-m", "--max-count", "-e", "--regexp", "--include", "--exclude", "--exclude-dir", "--include-dir"]),
  rg: new Set(["-A", "-B", "-C", "--context", "-m", "--max-count", "-e", "--regexp", "--glob", "-g", "--igrep"]),
  du: new Set(["--max-depth", "--threshold", "-t", "-d"]),
  fd: new Set(["-d", "--max-depth", "--maxdepth", "-e", "--extension", "--exclude", "-E", "--search-path"]),
  tar: new Set(["-f", "--file", "-C", "--directory"]),
  cp: new Set([]),
  rsync: new Set(["--exclude", "--include", "--filter"]),
  ls: new Set([]),
  diff: new Set([]),
}

function positionalsFor(words: string[], leaf: string): string[] {
  const withValue = FLAGS_WITH_VALUE[leaf] ?? new Set<string>()
  const out: string[] = []
  for (let i = 1; i < words.length; i++) {
    const tok = words[i] ?? ""
    if (tok === "--") {
      // Rest are positionals
      for (let j = i + 1; j < words.length; j++) out.push(words[j] ?? "")
      break
    }
    if (tok.startsWith("-")) {
      const lower = tok.toLowerCase()
      // Handle --flag=value
      if (lower.includes("=")) {
        const name = lower.split("=")[0] ?? ""
        if (withValue.has(name)) continue
        continue
      }
      if (withValue.has(lower)) {
        i++ // skip value
        continue
      }
      // Combined short flags: if any char corresponds to flag that takes value, skip next? Simplified
      continue
    }
    out.push(tok)
  }
  return out
}

// find options that take a value and may appear before the first path.
const FIND_PATH_OPTIONS_WITH_VALUE = new Set(["-maxdepth", "--max-depth", "-mindepth", "-regextype", "--regextype"])
// find global options that take no value and may appear before the first path.
const FIND_GLOBAL_OPTIONS = new Set([
  "-l",
  "-h",
  "-p",
  "-xdev",
  "-mount",
  "--xdev",
  "-ignore_readdir_race",
  "-noignore_readdir_race",
  "-noleaf",
  "-daystart",
  "-warn",
  "-nowarn",
])

// For find, roots are the path args; expression predicates end the path list,
// but global/path options before the first path must not.
function findRoots(words: string[]): string[] {
  const roots: string[] = []
  for (let i = 1; i < words.length; i++) {
    const tok = words[i] ?? ""
    if (tok === "--") {
      for (let j = i + 1; j < words.length; j++) roots.push(words[j] ?? "")
      break
    }
    if (tok.startsWith("-")) {
      const lower = tok.toLowerCase()
      if (FIND_PATH_OPTIONS_WITH_VALUE.has(lower)) {
        i++ // skip value
        continue
      }
      if (
        FIND_GLOBAL_OPTIONS.has(lower) ||
        lower.startsWith("--max-depth=") ||
        lower.startsWith("-maxdepth=") ||
        lower.startsWith("-mindepth=")
      ) {
        continue
      }
      break
    }
    if (tok === "(" || tok === ")" || tok === "!" || tok === ",") break
    roots.push(tok)
  }
  // If no roots collected (e.g., bare `find .`), treat as "." -> will be resolved via cwd, not expensive due to worktree check
  // But for `find` without path, implicit "." -> we can return []
  return roots
}

function scanFinding(leaf: string, words: string[], ctx: { cwd: string; worktree: string; maxDepth: number }): SlowCommandFinding | undefined {
  // Depth check for find/rg/fd
  if ((leaf === "find" || leaf === "rg" || leaf === "fd") && depthAtMost(words, ctx.maxDepth)) return undefined
  // Also consider -xdev / -mount as mitigation for find (does not cross filesystem)
  if (leaf === "find" && hasFlag(words, (f) => f === "-xdev" || f === "-mount" || f === "--xdev")) return undefined
  if (leaf === "grep" && !hasRecursiveFlag(words)) return undefined
  if (leaf === "diff" && !hasDiffRecursive(words)) return undefined
  if (leaf === "ls" && !hasLsRecursive(words)) return undefined
  if (leaf === "cp" && !hasFlag(words, (f) => f === "-r" || f === "-R" || f === "-a" || f === "--recursive" || /^-[a-z]*r[a-z]*$/.test(f) || /^-[a-z]*a[a-z]*$/.test(f))) return undefined
  // tar: only when creating/extracting
  if (leaf === "tar" && !hasFlag(words, (f) => f === "-c" || f === "--create" || f === "-x" || f === "--extract" || f === "-v" || /^[a-z]*c[a-z]*$/.test(f) || /^[a-z]*x[a-z]*$/.test(f))) {
    // tar without -c/-x is like list, not necessarily expensive unless root is /
    // We'll still check if roots contain expensive
  }
  // rsync: always check if any root is expensive (source)
  let roots: string[] = []
  if (leaf === "find") {
    roots = findRoots(words)
    // If no explicit roots remain (e.g. bare `find`), the implicit root is
    // "." — worktree-relative and not expensive, so no flag below.
  } else if (leaf === "grep" || leaf === "rg") {
    const pos = positionalsFor(words, leaf)
    // First positional is pattern, rest are roots
    roots = pos.slice(1)
  } else if (leaf === "tar" || leaf === "cp" || leaf === "rsync") {
    roots = positionalsFor(words, leaf)
    // For cp/rsync, first positional is source, last is dest; check all
  } else {
    roots = positionalsFor(words, leaf)
    // For diff, positions are files/dirs to compare; check both
  }

  // For find with no explicit roots, don't flag
  if (leaf === "find" && roots.length === 0) return undefined

  for (const root of roots) {
    if (isExpensiveRoot(root, ctx.cwd, ctx.worktree)) {
      return {
        kind: "unbounded-scan",
        rule: "performance.unbounded",
        reason: `${OPTIMIZE_HINT}: ${leaf} on ${root}`,
      }
    }
  }
  // Also check for brace expansion that we missed due to word splitting: already handled via scan's word? scan keeps brace as literal, not expanded; we should check raw resource for brace patterns
  // Fallback: check raw roots for brace containing expensive
  return undefined
}

function neverExitsFinding(leaf: string, words: string[]): SlowCommandFinding | undefined {
  const lowerWords = words.map((w) => w.toLowerCase())
  const flags = lowerWords.slice(1)
  const subcommand = lowerWords[1] ?? ""
  const follow = flags.some((f) => f === "-f" || f === "-F" || f === "--follow" || f.startsWith("--follow="))
  if (
    (leaf === "tail" && follow) ||
    (leaf === "tailf") ||
    (leaf === "journalctl" && follow) ||
    ((leaf === "docker" || leaf === "podman" || leaf === "kubectl") && subcommand === "logs" && follow)
  ) {
    return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: ${leaf} follow` }
  }
  // docker compose up (foreground, no -d), logs -f, watch — long-running / streaming
  if (leaf === "docker" && subcommand === "compose") {
    const composeSub = lowerWords[2] ?? ""
    if (composeSub === "up" && !flags.includes("-d") && !flags.includes("--detach")) {
      return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: docker compose up` }
    }
    if (composeSub === "logs" && follow) {
      return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: docker compose logs -f` }
    }
    if (composeSub === "watch") {
      return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: docker compose watch` }
    }
  }
  if (
    (leaf === "docker" && subcommand === "events") ||
    (leaf === "kubectl" && (flags.includes("-w") || flags.includes("--watch"))) ||
    (leaf === "kubectl" && subcommand === "get" && (flags.includes("-w") || flags.includes("--watch")))
  ) {
    return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: ${leaf} watch/events` }
  }
  if (leaf === "watch") {
    return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: watch loops` }
  }
  // On Linux `ping -t` sets the TTL, not a deadline — it does not bound the run.
  // Only -c (count), -w (deadline), -W (per-reply timeout), --deadline bound ping.
  if ((leaf === "ping" || leaf === "ping6") && !hasFlag(words, (f) => f === "-c" || f === "-w" || f === "-W" || f.startsWith("-c") || f.startsWith("--count") || f === "--deadline")) {
    return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: ${leaf} without -c/-w` }
  }
  if (leaf === "tcpdump" && !flags.some((f) => f === "-c" || f.startsWith("-c") || f === "--count" || f.startsWith("--count="))) {
    return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: tcpdump without -c` }
  }
  if (leaf === "yes") {
    return { kind: "never-exits", rule: "performance.never-exits", reason: `${NEVER_EXITS_HINT}: yes infinite output` }
  }
  return undefined
}

function devServerFinding(leaf: string, words: string[]): SlowCommandFinding | undefined {
  const lower = leaf.toLowerCase()
  const second = (words[1] ?? "").toLowerCase()
  const third = (words[2] ?? "").toLowerCase()
  // python -m http.server / uvicorn / flask / rails / php -S / node servers
  if (lower === "python" || lower === "python3" || lower === "py") {
    if (second === "-m" && (third === "http.server" || third === "uvicorn" || third.startsWith("uvicorn"))) {
      return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（python -m ${third}）` }
    }
    if (words.some((w) => w.toLowerCase() === "http.server")) {
      return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（python http.server）` }
    }
  }
  if (lower === "flask" && second === "run") return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（flask run）` }
  if (lower === "rails" && (second === "server" || second === "s")) return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（rails server）` }
  if (lower === "php" && second === "-s") return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（php -S）` }
  if (lower === "npm" && (second === "run" && ["dev", "start", "serve"].includes(third) || ["dev", "start", "serve"].includes(second))) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（npm ${second} ${third}）` }
  }
  if (lower === "yarn" && (second === "dev" || second === "start" || (second === "run" && ["dev", "start"].includes(third)))) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（yarn）` }
  }
  if (["vite", "next", "nuxt", "webpack"].includes(lower) && (second === "dev" || words.includes("--watch") || words.includes("-w"))) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（${leaf}）` }
  }
  if (lower === "tsc" && flagsContain(words, ["-w", "--watch"])) return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（tsc --watch）` }
  if (lower === "jest" && flagsContain(words, ["--watch", "--watchAll"])) return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（jest --watch）` }
  if (lower === "cargo" && second === "watch") return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（cargo watch）` }
  // pnpm dev|start|serve (and pnpm run dev|start|serve)
  if (lower === "pnpm" && (["dev", "start", "serve"].includes(second) || (second === "run" && ["dev", "start", "serve"].includes(third)))) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（pnpm）` }
  }
  // bun --watch / bun run dev|start|serve
  if (lower === "bun" && (words.some((w) => w.toLowerCase() === "--watch") || (second === "run" && ["dev", "start", "serve"].includes(third)))) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（bun）` }
  }
  // deno task dev|start|serve / deno --watch
  if (lower === "deno" && ((second === "task" && ["dev", "start", "serve"].includes(third)) || words.some((w) => w.toLowerCase() === "--watch"))) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（deno）` }
  }
  // npx <pkg> dev|start|serve — covers npx vite dev, npx next dev, npx nuxt dev
  if (lower === "npx" && ["vite", "next", "nuxt"].includes(second) && ["dev", "start", "serve"].includes(third)) {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（npx ${second}）` }
  }
  // uvicorn / gunicorn direct invocation — these are always long-running dev servers
  if (lower === "uvicorn" || lower === "gunicorn") {
    return { kind: "dev-server", rule: "performance.dev-server", reason: `${DEV_SERVER_HINT}（${leaf}）` }
  }
  return undefined
}

function flagsContain(words: string[], names: string[]): boolean {
  const lower = words.map((w) => w.toLowerCase())
  return names.some((n) => lower.includes(n.toLowerCase()))
}

function sleepFinding(words: string[], thresholdSec: number): SlowCommandFinding | undefined {
  let total = 0
  for (let i = 1; i < words.length; i++) {
    const raw = words[i] ?? ""
    if (raw.startsWith("-")) continue
    if (raw.toLowerCase() === "infinity" || raw.toLowerCase() === "inf") total = Number.POSITIVE_INFINITY
    const match = raw.match(/^(\d+(?:\.\d+)?)([smhd]?)$/i)
    if (!match) continue
    const scale: Record<string, number> = { "": 1, s: 1, m: 60, h: 3600, d: 86400 }
    total += Number.parseFloat(match[1] ?? "0") * (scale[(match[2] ?? "").toLowerCase()] ?? 1)
  }
  if (total >= thresholdSec) {
    return {
      kind: "long-sleep",
      rule: "performance.long-sleep",
      reason: `${SLEEP_HINT}: sleep ${Number.isFinite(total) ? total + "s" : "infinity"} >= ${thresholdSec}s`,
    }
  }
  return undefined
}

function stripQuotesAndComments(s: string): string {
  // Remove single/double quoted strings and comments to avoid FP on echo "while true"
  let out = ""
  let i = 0
  let inSingle = false
  let inDouble = false
  let escaped = false
  while (i < s.length) {
    const c = s[i]
    if (escaped) { escaped = false; i++; continue }
    if (c === "\\" && !inSingle) { escaped = true; i++; continue }
    if (c === "'" && !inDouble) { inSingle = !inSingle; i++; continue }
    if (c === '"' && !inSingle) { inDouble = !inDouble; i++; continue }
    if (c === "#" && !inSingle && !inDouble) {
      // comment until newline
      const nl = s.indexOf("\n", i)
      if (nl === -1) break
      i = nl
      continue
    }
    if (!inSingle && !inDouble) out += c
    i++
  }
  return out
}

function loopFinding(rawScript: string): SlowCommandFinding | undefined {
  const stripped = stripQuotesAndComments(rawScript).trim()
  // while <cond> where cond is an always-true literal: `true`, `:`, `1`, `[ 1 ]`.
  // Use lookahead (?=\s|;|$) instead of trailing \b — \b fails after non-word
  // chars like `:` and `]`, which caused the most common forms (`while :;`, `while [ 1 ];`) to be missed.
  if (/\bwhile\s+(?:true|:|1|\[\s*1\s*\])(?=\s|;|$)/i.test(stripped) && /\bdo\b/i.test(stripped)) {
    return { kind: "infinite-loop", rule: "performance.never-exits", reason: `${LOOP_HINT} (while true)` }
  }
  if (/for\s*\(\(\s*;\s*;\s*\)\)/i.test(stripped) || /for\s*\(\(\s*true\s*\)\)/i.test(stripped)) {
    return { kind: "infinite-loop", rule: "performance.never-exits", reason: `${LOOP_HINT} (for ((;;)))` }
  }
  if (/\buntil\s+false\b/i.test(stripped) && /\bdo\b/i.test(stripped)) {
    return { kind: "infinite-loop", rule: "performance.never-exits", reason: `${LOOP_HINT} (until false)` }
  }
  return undefined
}

function isWrapperLeaf(leaf: string): boolean {
  return WRAPPER_SHELLS.has(leaf)
}

function parseTimeoutDuration(words: string[]): { durationSec: number; innerStart: number } | undefined {
  // timeout [options] DURATION COMMAND...
  // Supports: timeout [-s SIG] [--signal=SIG] [--kill-after=...] DURATION
  let idx = 1
  while (idx < words.length) {
    const w = words[idx] ?? ""
    const lower = w.toLowerCase()
    if (lower === "-s" || lower === "--signal") {
      idx += 2
      continue
    }
    if (lower.startsWith("--signal=") || lower.startsWith("-s") && w.length > 2) {
      idx++
      continue
    }
    if (lower === "--kill-after" || lower.startsWith("--kill-after=")) {
      if (!lower.includes("=")) idx += 2
      else idx++
      continue
    }
    if (lower === "-k" || lower.startsWith("-k")) {
      idx += lower === "-k" ? 2 : 1
      continue
    }
    if (w.startsWith("-")) {
      idx++
      continue
    }
    break
  }
  if (idx >= words.length) return undefined
  const durRaw = words[idx] ?? ""
  const m = durRaw.match(/^(\d+(?:\.\d+)?)([smhd]?)$/i)
  if (!m) return undefined
  const val = Number.parseFloat(m[1] ?? "")
  if (!Number.isFinite(val)) return undefined
  const scale: Record<string, number> = { "": 1, s: 1, m: 60, h: 3600, d: 86400 }
  const sec = val * (scale[(m[2] ?? "").toLowerCase()] ?? 1)
  return { durationSec: sec, innerStart: idx + 1 }
}

function expandBraceRoots(roots: string[]): string[] {
  const out: string[] = []
  for (const r of roots) {
    if (r.includes("{") && r.includes("}")) {
      const open = r.indexOf("{")
      const close = r.indexOf("}", open + 1)
      if (open !== -1 && close !== -1) {
        const prefix = r.slice(0, open)
        const suffix = r.slice(close + 1)
        const inner = r.slice(open + 1, close)
        const parts = inner.split(",").filter((p) => p.length > 0).slice(0, 16)
        for (const p of parts) out.push(`${prefix}${p}${suffix}`)
        continue
      }
    }
    out.push(r)
  }
  return out
}

// Maximum number of wrapper-shell unwraps (bash -c "..." recursion). Hardcoded
// to 2 to bound recursion while covering the common double-wrap evasion.
const MAX_UNWRAP_DEPTH = 2

// Analyze a single command's words for slow-command findings. Handles exec prefix,
// wrapper-shell unwrapping (bounded recursion), scan findings (with brace expansion),
// never-exits, dev-server, and long-sleep.
function analyzeWords(
  words: string[],
  ctx: { cwd: string; worktree: string; maxDepth: number },
  sleepThreshold: number,
  depth: number,
): SlowCommandFinding | undefined {
  if (words.length === 0) return undefined
  const leaf = words[0]?.replaceAll("\\", "/").split("/").pop()?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "").toLowerCase() ?? ""
  if (!leaf) return undefined

  // exec replaces the shell process with the given command; treat it as a
  // transparent prefix (does not add a wrapper layer, so depth is unchanged).
  if (leaf === "exec" && words.length > 1) {
    return analyzeWords(words.slice(1), ctx, sleepThreshold, depth)
  }

  // Unwrap wrapper shells: bash -c "cmd" (bounded recursion, depth ≤ MAX_UNWRAP_DEPTH)
  if (isWrapperLeaf(leaf) && depth < MAX_UNWRAP_DEPTH) {
    const cIdx = words.findIndex((w) => w === "-c" || w === "-lc")
    if (cIdx !== -1 && cIdx + 1 < words.length) {
      const innerScript = words[cIdx + 1] ?? ""
      const innerLoop = loopFinding(innerScript)
      if (innerLoop) return innerLoop
      const innerResult = scan(innerScript)
      if (innerResult.kind === "scanned") {
        for (const innerCmd of innerResult.commands) {
          const f = analyzeWords(innerCmd.words, ctx, sleepThreshold, depth + 1)
          if (f) return f
        }
      }
      return undefined
    }
  }

  if (SCAN_COMMANDS.has(leaf)) {
    const finding = scanFinding(leaf, words, ctx)
    if (finding) return finding
    // Brace expansion: re-check expanded roots whenever any root contains braces,
    // even if the expansion count is unchanged (e.g. single-part `/{etc}` → `/etc`).
    const rawRoots = leaf === "find" ? findRoots(words) : positionalsFor(words, leaf)
    if (rawRoots.some((r) => r.includes("{") && r.includes("}"))) {
      const expanded = expandBraceRoots(rawRoots)
      for (const r of expanded) {
        if (isExpensiveRoot(r, ctx.cwd, ctx.worktree)) {
          return {
            kind: "unbounded-scan",
            rule: "performance.unbounded",
            reason: `${OPTIMIZE_HINT}: ${leaf} on ${r} (brace)`,
          }
        }
      }
    }
  }

  const never = neverExitsFinding(leaf, words)
  if (never) return never

  const dev = devServerFinding(leaf, words)
  if (dev) return dev

  if (leaf === "sleep") {
    const s = sleepFinding(words, sleepThreshold)
    if (s) return s
  }

  return undefined
}

export function analyzeSlowCommand(
  script: string,
  shell: string,
  ctx: { cwd: string; worktree: string; maxDepth?: number; sleepThresholdSeconds?: number },
): SlowCommandFinding | undefined {
  const maxDepth = ctx.maxDepth ?? 3
  const sleepThreshold = ctx.sleepThresholdSeconds ?? 120 // Spec says 120, not 600

  // Fast loop check before scan
  const loop = loopFinding(script)
  if (loop) return loop

  // Use shell-scan for proper tokenization
  const lowerShell = shell.toLowerCase()
  const isPowerShell = lowerShell.includes("pwsh") || lowerShell.includes("powershell")
  // For now, only bash scan is vendored; ps would need powerShell scan but we fallback to simple
  // If powershell, just do not block (avoid FP)
  if (isPowerShell) return undefined

  const result = scan(script)
  if (result.kind === "opaque") {
    // Opaque: dynamic, compound, etc. Don't block to avoid FP; dynamic reviewer can handle
    return undefined
  }

  for (const cmd of result.commands) {
    const words = cmd.words
    if (words.length === 0) continue
    const leaf = words[0]?.replaceAll("\\", "/").split("/").pop()?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "").toLowerCase() ?? ""
    if (!leaf) continue

    // Unwrap timeout prefix: timeout [opts] DURATION COMMAND...
    if (TIMEOUT_COMMANDS.has(leaf)) {
      const parsed = parseTimeoutDuration(words)
      if (parsed) {
        if (parsed.durationSec <= 60) continue // short timeout, skip
        if (parsed.innerStart < words.length) {
          const innerWords = words.slice(parsed.innerStart)
          const f = analyzeWords(innerWords, { cwd: ctx.cwd, worktree: ctx.worktree, maxDepth }, sleepThreshold, 0)
          if (f) return f
        }
        continue
      }
      // Unparseable duration: fall through to analyze the command as-is
    }

    const f = analyzeWords(words, { cwd: ctx.cwd, worktree: ctx.worktree, maxDepth }, sleepThreshold, 0)
    if (f) return f
  }

  return undefined
}

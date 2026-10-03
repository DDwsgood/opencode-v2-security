// Semantic static-allow provers.
//
// Each prover answers one narrow question — "is this exact invocation
// read-only / side-effect free?" — from literal argv (or, for Python, from the
// program's AST). A prover either proves the invocation safe or returns
// undefined; it never produces ASK/DENY. Callers run these only after every
// danger scan has passed, so a missed proof costs a dynamic review and a wrong
// proof is the only failure mode that matters: every check here is written to
// reject anything it does not fully understand.

import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { existsSync, readFileSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { checkPathSensitivity, classifyPathTarget, type PathContext } from "./paths"

export type SemanticProof = { rule: string; reason: string }

// --- Python read-only prover -------------------------------------------------

const PROVER_SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "python-readonly.py")
const PROVER_TIMEOUT_MS = 5_000
const PROOF_CACHE_TTL_MS = 30_000
const PROOF_CACHE_LIMIT = 512

export type PythonProof = { ok: true; paths: string[] } | { ok: false; reason: string }

const proofCache = new Map<string, { at: number; proof: Promise<PythonProof> }>()

function runPythonProver(source: string, searchDirs: string[]): Promise<PythonProof> {
  return new Promise((resolve) => {
    let settled = false
    const finish = (proof: PythonProof) => {
      if (settled) return
      settled = true
      resolve(proof)
    }
    let child: ReturnType<typeof spawn>
    try {
      // -I: isolated (no PYTHON* env, no user site, no cwd on sys.path);
      // -S: no site import; the prover itself only needs ast/json/re/os.
      child = spawn("python3", ["-I", "-S", "-B", PROVER_SCRIPT], {
        cwd: "/",
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", LANG: "C.UTF-8" },
        stdio: ["pipe", "pipe", "ignore"],
      })
    } catch {
      finish({ ok: false, reason: "python3 unavailable" })
      return
    }
    const timer = setTimeout(() => {
      child.kill("SIGKILL")
      finish({ ok: false, reason: "prover timeout" })
    }, PROVER_TIMEOUT_MS)
    let stdout = ""
    child.stdout?.setEncoding("utf8")
    child.stdout?.on("data", (chunk: string) => {
      stdout += chunk
      if (stdout.length > 1_000_000) child.kill("SIGKILL")
    })
    child.on("error", () => {
      clearTimeout(timer)
      finish({ ok: false, reason: "python3 unavailable" })
    })
    child.on("close", () => {
      clearTimeout(timer)
      try {
        const parsed = JSON.parse(stdout) as { ok?: unknown; paths?: unknown; reason?: unknown }
        if (parsed.ok === true && Array.isArray(parsed.paths) && parsed.paths.every((p) => typeof p === "string")) {
          finish({ ok: true, paths: parsed.paths as string[] })
          return
        }
        finish({ ok: false, reason: typeof parsed.reason === "string" ? parsed.reason : "not proven" })
      } catch {
        finish({ ok: false, reason: "prover output unreadable" })
      }
    })
    child.stdin?.on("error", () => {})
    child.stdin?.end(JSON.stringify({ source, searchDirs }))
  })
}

/** AST-level proof that a Python program cannot write, delete, spawn, reach the
 *  network, evaluate dynamic code, or import a module from `searchDirs`. */
export function provePythonReadOnly(source: string, searchDirs: string[]): Promise<PythonProof> {
  const key = createHash("sha256").update(source).update("\0").update(searchDirs.join("\0")).digest("hex")
  const now = Date.now()
  const hit = proofCache.get(key)
  if (hit && now - hit.at < PROOF_CACHE_TTL_MS) return hit.proof
  const proof = runPythonProver(source, searchDirs)
  proofCache.set(key, { at: now, proof })
  if (proofCache.size > PROOF_CACHE_LIMIT) {
    const oldest = proofCache.keys().next().value
    if (oldest !== undefined) proofCache.delete(oldest)
  }
  return proof
}

/** Path-like literals found by the prover still face the classifier's own
 *  read policy (credential stores, foreign homes, broad scan roots). */
export function provenPathsReadable(paths: string[], ctx: PathContext): boolean {
  for (const raw of paths) {
    if (checkPathSensitivity(raw, ctx).sensitive) return false
    if (classifyPathTarget(raw, "read", ctx).kind !== "pass") return false
  }
  return true
}

const PYTHON_INTERPRETER = /^python(?:3(?:\.\d{1,2})?)?$/
// Interpreter flags that change neither what code runs nor where imports
// resolve. `-W` is excluded because a warning category name imports a module.
const PYTHON_SAFE_FLAGS = new Set(["-u", "-B", "-I", "-E", "-s", "-S", "-q", "-O", "-OO", "-b", "-bb"])
const PYTHON_SAFE_ENV = new Set([
  "PYTHONIOENCODING", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8",
  "PYTHONHASHSEED", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "NO_COLOR", "FORCE_COLOR", "COLUMNS", "TERM",
])

/** Bare interpreter name resolved through PATH: a path-qualified interpreter
 *  (a venv or a file in the worktree) may carry its own site hooks. */
export function isPlainPythonInterpreter(word: string): boolean {
  return PYTHON_INTERPRETER.test(word)
}

/** Leading `NAME=value` words, accepted only from `allowed`. Returns the index
 *  of the first non-assignment word, or -1 when an assignment is not allowed. */
function skipAssignments(argv: string[], allowed: ReadonlySet<string>): number {
  let i = 0
  while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i])) {
    const name = argv[i].slice(0, argv[i].indexOf("="))
    if (!allowed.has(name)) return -1
    i += 1
  }
  return i
}

/** Python invocation shape `python3 [safe flags] <rest>`; returns the index of
 *  the first word after the safe flags. */
export function pythonFlagsEnd(argv: string[], start: number): number {
  let i = start + 1
  while (i < argv.length && PYTHON_SAFE_FLAGS.has(argv[i])) i += 1
  if (argv[i] === "-X" && argv[i + 1] === "utf8") return pythonFlagsEnd(argv, i + 1)
  return i
}

/** `python3 [safe flags] [-]` reading its program from stdin, with only
 *  harmless environment assignments in front. */
export function pythonStdinInvocation(argv: string[]): boolean {
  const i = skipAssignments(argv, PYTHON_SAFE_ENV)
  if (i < 0 || !isPlainPythonInterpreter(argv[i] ?? "")) return false
  const j = pythonFlagsEnd(argv, i)
  return j === argv.length || (j === argv.length - 1 && argv[j] === "-")
}

/** `python3 [safe flags] <script.py> …` naming exactly `script`. */
export function pythonRunsScript(argv: string[], script: string): boolean {
  const i = skipAssignments(argv, PYTHON_SAFE_ENV)
  if (i < 0 || !isPlainPythonInterpreter(argv[i] ?? "")) return false
  return argv[pythonFlagsEnd(argv, i)] === script
}

/** True when `<module>.py` or `<module>/` exists in `dir` — `python -m`,
 *  `-c` and stdin programs put the working directory first on sys.path. */
function shadowsModule(dir: string, module: string): boolean {
  const top = module.split(".")[0] ?? module
  return existsSync(path.join(dir, `${top}.py`)) || existsSync(path.join(dir, top))
}

// --- SQL (sqlite3 CLI) --------------------------------------------------------

const SQL_READ_START = /^\s*(?:\(\s*)*(?:SELECT|WITH|PRAGMA|EXPLAIN|VALUES)\b/i
const SQL_WRITE_WORD =
  /\b(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE|ATTACH|DETACH|VACUUM|REINDEX|ANALYZE|load_extension|writefile|readfile|edit|fts3_tokenizer|zipfile)\b/i
const SQLITE_DOT_READ = /^\.(?:tables|schema|indexes|indices|headers|header|mode|width|dbinfo|databases|show|help|nullvalue|separator|timer|stats|eqp|print|fullschema|lint\s+fkey-indexes)(?:\s|$)/i

// A bare `PRAGMA name` reads only for these names: names left out either
// write without any argument (`optimize`, `wal_checkpoint`,
// `incremental_vacuum`) or were not audited. `name = v` and `name(v)` are the
// assignment forms — the parenthesized form stays read-only only for the
// pragmas below that take an object-name argument.
const SQLITE_PRAGMA_READ = new Set([
  "application_id", "analysis_limit", "auto_vacuum", "automatic_index",
  "busy_timeout", "cache_size", "cache_spill", "case_sensitive_like",
  "cell_size_check", "checkpoint_fullfsync", "collation_list",
  "compile_options", "count_changes", "data_version", "database_list",
  "defer_foreign_keys", "encoding", "foreign_key_check", "foreign_key_list",
  "foreign_keys", "freelist_count", "full_column_names", "fullfsync",
  "function_list", "hard_heap_limit", "ignore_check_constraints",
  "index_info", "index_list", "index_xinfo", "integrity_check",
  "journal_mode", "journal_size_limit", "legacy_alter_table",
  "legacy_file_format", "locking_mode", "max_page_count", "mmap_size",
  "module_list", "page_count", "page_size", "pragma_list", "query_only",
  "quick_check", "read_uncommitted", "recursive_triggers",
  "reverse_unordered_selects", "schema_version", "secure_delete",
  "short_column_names", "soft_heap_limit", "stats", "synchronous",
  "table_info", "table_list", "table_xinfo", "temp_store", "threads",
  "trusted_schema", "user_version", "wal_autocheckpoint", "writable_schema",
])
const SQLITE_PRAGMA_READ_ARG = new Set([
  "table_info", "table_xinfo", "index_list", "index_info", "index_xinfo",
  "foreign_key_list", "integrity_check", "quick_check", "foreign_key_check",
])

/** `PRAGMA name` / `PRAGMA schema.name` with no value is a read for the
 *  whitelisted names. `name(v)` is allowed only for the read pragmas that
 *  take an object-name argument, and the argument must be a plain literal —
 *  no nested statement can hide inside it. */
function pragmaReadOnly(statement: string): boolean {
  const m = /^\s*PRAGMA\s+(?:[A-Za-z_]\w*\s*\.\s*)?([A-Za-z_]\w*)([\s\S]*)$/i.exec(statement)
  if (!m) return false
  const name = m[1].toLowerCase()
  if (!SQLITE_PRAGMA_READ.has(name)) return false
  const tail = m[2].trim()
  if (tail === "") return true
  if (!tail.startsWith("(") || !/\)\s*$/.test(tail)) return false
  if (!SQLITE_PRAGMA_READ_ARG.has(name)) return false
  const arg = tail.slice(1, tail.lastIndexOf(")")).trim()
  return arg !== "" && /^[\w$'".-]+$/.test(arg)
}

/** Scans one quoted literal starting at `start` (sql[start] === quote) with
 *  SQL doubling escapes (`'it''s'`); returns the index just past the closer
 *  or -1 when unterminated. `[bracket]` identifiers have no escape in the
 *  SQL Server form SQLite accepts, so the first `]` ends them — a `]]` that
 *  SQLite might read as a literal `]` only over-rejects, never hides text. */
function sqlQuotedEnd(sql: string, start: number, quote: string): number {
  if (quote === "[") {
    const close = sql.indexOf("]", start + 1)
    return close < 0 ? -1 : close + 1
  }
  let i = start + 1
  for (;;) {
    const close = sql.indexOf(quote, i)
    if (close < 0) return -1
    if (sql[close + 1] === quote) {
      i = close + 2
      continue
    }
    return close + 1
  }
}

/** Skips whitespace and comments after a token. Returns -1 on an
 *  unterminated block comment. */
function skipSqlTrivia(sql: string, i: number): number {
  for (;;) {
    while (i < sql.length && /\s/.test(sql[i])) i += 1
    if (sql[i] === "-" && sql[i + 1] === "-") {
      const nl = sql.indexOf("\n", i)
      i = nl < 0 ? sql.length : nl + 1
      continue
    }
    if (sql[i] === "/" && sql[i + 1] === "*") {
      const close = sql.indexOf("*/", i + 2)
      if (close < 0) return -1
      i = close + 2
      continue
    }
    return i
  }
}

/** Comment stripping that knows SQL quoting: contents of '…', "…", `…` and
 *  […] collapse to their delimiters, `--` and `/*…*\/` comments collapse to
 *  a space. A `--` or `;` inside a literal is data, never a comment or a
 *  statement boundary; anything quoted stays quoted so a literal can never
 *  hide a real `; UPDATE`/`PRAGMA`. One exception: a quoted token in call
 *  position (`"writefile"('f','x')` — SQLite executes quoted function names,
 *  single-quoted included) emits its inner text instead, so `writefile`/
 *  `load_extension`/`fts3_tokenizer` still hit the write-word scan; a quoted
 *  "name" that is not a plain identifier there stays unproven. Returns null
 *  on an unterminated quote or block comment — the script is then left
 *  unproven. */
function maskSqlLiteralsAndComments(sql: string): string | null {
  let out = ""
  let i = 0
  while (i < sql.length) {
    const ch = sql[i]
    if (ch === "'" || ch === '"' || ch === "`" || ch === "[") {
      const end = sqlQuotedEnd(sql, i, ch)
      if (end < 0) return null
      // Call position: the quoted token is a function name and stays
      // executable when quoted. Emit a clean identifier so the write-word
      // scan still sees `writefile`/`load_extension`; anything else (a name
      // no CREATE FUNCTION could register anyway) is left unproven.
      const call = skipSqlTrivia(sql, end)
      if (call < 0) return null
      if (sql[call] === "(") {
        const inner = sql.slice(i + 1, end - 1)
        if (!/^[A-Za-z_]\w*$/.test(inner)) return null
        out += ` ${inner} `
      } else {
        out += ch === "[" ? "[]" : ch + ch
      }
      i = end
      continue
    }
    if (ch === "-" && sql[i + 1] === "-") {
      const nl = sql.indexOf("\n", i)
      out += " "
      i = nl < 0 ? sql.length : nl
      continue
    }
    if (ch === "/" && sql[i + 1] === "*") {
      const close = sql.indexOf("*/", i + 2)
      if (close < 0) return null
      out += " "
      i = close + 2
      continue
    }
    out += ch
    i += 1
  }
  return out
}

/** Every statement is a read: SELECT/WITH/EXPLAIN/VALUES or a non-assigning
 *  PRAGMA, and no write/attach/file keyword appears anywhere. Dot-commands
 *  are accepted only from a display-only allowlist. */
export function sqlScriptReadOnly(script: string): boolean {
  const lines = script.split("\n")
  const sqlParts: string[] = []
  for (const line of lines) {
    const trimmed = line.trim()
    if (trimmed.startsWith(".")) {
      if (!SQLITE_DOT_READ.test(trimmed)) return false
      if (/^\.(?:mode|headers?)\b/i.test(trimmed) && /\s(?:\S*\/|>)/.test(trimmed)) return false
      continue
    }
    sqlParts.push(line)
  }
  const sql = maskSqlLiteralsAndComments(sqlParts.join("\n"))
  if (sql === null || SQL_WRITE_WORD.test(sql)) return false
  const statements = sql.split(";").map((s) => s.trim()).filter(Boolean)
  for (const statement of statements) {
    if (!SQL_READ_START.test(statement)) return false
    // `EXPLAIN` hides the statement behind it from this check; a pragma is
    // processed while the statement is prepared, so do not reason about it.
    if (/^\s*EXPLAIN\s+PRAGMA\b/i.test(statement)) return false
    if (/^\s*PRAGMA\b/i.test(statement) && !pragmaReadOnly(statement)) return false
  }
  return true
}

const SQLITE_FLAG_ONLY = new Set([
  "-readonly", "--readonly", "-header", "--header", "-noheader", "--noheader", "-column", "--column",
  "-csv", "--csv", "-json", "--json", "-line", "--line", "-list", "--list", "-box", "--box",
  "-markdown", "--markdown", "-table", "--table", "-bail", "--bail", "-batch", "--batch",
  "-html", "--html", "-quote", "--quote", "-tabs", "--tabs", "-safe", "--safe", "-nofollow", "--nofollow",
])
const SQLITE_FLAG_VALUE = new Set(["-separator", "--separator", "-nullvalue", "--nullvalue", "-newline", "--newline"])

function proveSqliteCli(argv: string[], i: number, ctx: PathContext): boolean {
  let db: string | undefined
  const sql: string[] = []
  for (let k = i + 1; k < argv.length; k += 1) {
    const word = argv[k]
    if (db === undefined && word.startsWith("-")) {
      if (SQLITE_FLAG_ONLY.has(word)) continue
      if (SQLITE_FLAG_VALUE.has(word)) {
        k += 1
        continue
      }
      return false // -cmd/-init/-A/-deserialize/... run or load extra input
    }
    if (db === undefined) {
      db = word
      continue
    }
    sql.push(word)
  }
  // With no SQL argument sqlite3 reads its program from stdin, which this
  // segment does not control.
  if (db === undefined || sql.length === 0) return false
  const dbPath = db.replace(/^file:/, "").replace(/\?.*$/, "")
  if (dbPath !== ":memory:" && dbPath !== "") {
    if (classifyPathTarget(dbPath, "read", ctx).kind !== "pass") return false
    if (checkPathSensitivity(dbPath, ctx).sensitive) return false
  }
  return sql.every(sqlScriptReadOnly)
}

/** sqlite3 CLI fed by a quoted heredoc: the body is the whole program. */
export function proveSqliteHeredoc(consumerArgv: string[], body: string, ctx: PathContext): boolean {
  if (consumerArgv.length < 2 || consumerArgv[0] !== "sqlite3") return false
  let db: string | undefined
  for (let k = 1; k < consumerArgv.length; k += 1) {
    const word = consumerArgv[k]
    if (db === undefined && word.startsWith("-")) {
      if (SQLITE_FLAG_ONLY.has(word)) continue
      if (SQLITE_FLAG_VALUE.has(word)) {
        k += 1
        continue
      }
      return false
    }
    if (db !== undefined) return false // trailing SQL args: stdin is not read
    db = word
  }
  if (db === undefined) return false
  const dbPath = db.replace(/^file:/, "").replace(/\?.*$/, "")
  if (classifyPathTarget(dbPath, "read", ctx).kind !== "pass" || checkPathSensitivity(dbPath, ctx).sensitive) return false
  return sqlScriptReadOnly(body)
}

// --- curl GET to loopback --------------------------------------------------------

const CURL_FLAG_ONLY = new Set([
  "--silent", "--show-error", "--fail", "--fail-with-body", "--include",
  "--head", "--verbose", "--compressed", "--no-buffer", "--http1.1", "--http2",
  "--insecure", "--globoff", "--no-progress-meter",
])
// Short boolean options that may be clustered (`-sSf`).
const CURL_SHORT_FLAGS = /^-[sSfiIvkNg46]+$/
const CURL_FLAG_VALUE = new Set([
  "-m", "--max-time", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time",
  "-A", "--user-agent", "-H", "--header", "-w", "--write-out", "-X", "--request", "-e", "--referer",
])
const LOOPBACK_URL = /^(?:https?:\/\/)?(?:localhost|127(?:\.\d{1,3}){3}|\[::1\]|0\.0\.0\.0)(?::\d{1,5})?(?:[/?#][^\s]*)?$/i

function proveCurlLoopbackGet(argv: string[], i: number): boolean {
  let urls = 0
  for (let k = i + 1; k < argv.length; k += 1) {
    const word = argv[k]
    if (word.startsWith("-") && word.length > 1) {
      if (CURL_FLAG_ONLY.has(word) || CURL_SHORT_FLAGS.test(word)) continue
      if (word === "-o" || word === "--output") {
        if (argv[k + 1] !== "/dev/null") return false
        k += 1
        continue
      }
      const eq = word.indexOf("=")
      const flag = eq > 0 ? word.slice(0, eq) : word
      if (!CURL_FLAG_VALUE.has(flag)) return false
      const value = eq > 0 ? word.slice(eq + 1) : argv[k + 1]
      if (value === undefined) return false
      if (eq < 0) k += 1
      // `@file` reads a local file into the request or output.
      if (value.startsWith("@")) return false
      if ((flag === "-X" || flag === "--request") && !/^(?:GET|HEAD)$/i.test(value)) return false
      // `--write-out` writes every byte it produces into a file with
      // `%output{name}` (`%output{>>name}` appends); other %{} expansions
      // only print.
      if ((flag === "-w" || flag === "--write-out") && /%output\s*\{/i.test(value)) return false
      continue
    }
    if (!LOOPBACK_URL.test(word)) return false
    urls += 1
  }
  return urls > 0
}

// --- version / help queries ---------------------------------------------------------

const VERSION_TOOLS = new Set([
  "bun", "node", "deno", "npm", "npx", "pnpm", "yarn", "python", "python3", "pip", "pip3", "uv",
  "poetry", "cargo", "rustc", "rustup", "go", "java", "javac", "gradle", "mvn", "git", "gh", "docker",
  "podman", "kubectl", "tsc", "ruff", "black", "isort", "eslint", "prettier", "jq", "rg", "fd", "curl",
  "wget", "gcc", "g++", "clang", "make", "cmake", "bwrap", "sqlite3", "tmux", "opencode", "codex",
  "claude", "gemini", "adb", "ffmpeg", "pandoc", "dotnet", "ruby", "perl", "php", "lua", "zig",
])
// Which tools treat a given lone argument as "print version/help and exit".
// Short spellings and bare words are tool-specific: `node help` runs a file,
// `npx version` downloads a package, `ruby -v` then reads a script from stdin.
const VERSION_ARG_TOOLS: Record<string, ReadonlySet<string> | "all"> = {
  "--version": "all",
  "--help": "all",
  "-h": "all",
  "-V": new Set(["python", "python3", "cargo", "rustc", "perl", "uv", "poetry"]),
  "-v": new Set(["node", "bun", "npm", "pnpm", "yarn", "deno", "docker", "podman", "tsc", "php", "gradle", "mvn", "git"]),
  version: new Set(["go", "docker", "podman", "kubectl", "gh", "zig", "uv", "cargo", "git", "adb", "dotnet"]),
  help: new Set(["go", "git", "gh", "cargo", "uv", "docker", "podman", "npm", "pnpm", "deno", "zig", "adb", "kubectl"]),
  "-version": new Set(["java", "javac"]),
}

function systemBinaryLeaf(word: string): string | undefined {
  if (!word.includes("/")) return word
  const match = /^\/(?:usr\/(?:local\/)?)?s?bin\/([\w.+-]+)$|^\/opt\/homebrew\/bin\/([\w.+-]+)$/.exec(word)
  return match?.[1] ?? match?.[2]
}

function proveVersionQuery(argv: string[], i: number): boolean {
  if (argv.length !== i + 2) return false
  const leaf = systemBinaryLeaf(argv[i])
  if (!leaf || !VERSION_TOOLS.has(leaf)) return false
  const tools = VERSION_ARG_TOOLS[argv[i + 1]]
  if (tools === undefined) return false
  return tools === "all" || tools.has(leaf)
}

// --- gh / tmux / xargs read surfaces ----------------------------------------------

const GH_READ: Record<string, ReadonlySet<string>> = {
  pr: new Set(["view", "list", "diff", "checks", "status"]),
  issue: new Set(["view", "list", "status"]),
  run: new Set(["list", "view", "watch"]),
  repo: new Set(["view", "list"]),
  release: new Set(["list", "view"]),
  workflow: new Set(["list", "view"]),
  search: new Set(["repos", "issues", "prs", "code", "commits"]),
  label: new Set(["list"]),
  cache: new Set(["list"]),
}

// `gh api` boolean flags that only print or page the response.
const GH_API_BOOL = new Set(["-i", "--include", "--paginate", "--silent", "--verbose"])
// `gh api` value flags whose argument is a request header or an output filter.
const GH_API_VALUE = new Set(["-H", "--header", "-q", "--jq", "-p", "--preview"])

function proveGhRead(argv: string[], i: number): boolean {
  const group = argv[i + 1]
  const rest = argv.slice(i + 2)
  if (rest.some((word) => word === "--web" || word === "-w" || word.startsWith("--web="))) return false
  if (group === "api") {
    // Every flag must come from the two whitelists below or be a `-X`/`--method`
    // spelling of GET/HEAD. Anything unlisted — `--input` (file body), `--cache`
    // (writes), `--hostname` (sends the stored token to another host),
    // `--template` (its `env` function interpolates secrets) — stays unproven.
    let endpoint = false
    for (let k = 0; k < rest.length; k += 1) {
      const word = rest[k]
      if (word === "--") continue
      if (!word.startsWith("-") || word === "-") {
        endpoint = true
        continue
      }
      if (GH_API_BOOL.has(word)) continue
      const eq = word.indexOf("=")
      const name = eq > 0 ? word.slice(0, eq) : word
      // `-f`/`-F` carry request fields and imply POST in every spelling
      // (`-f k=v`, `-fk=v`, `--field k=v`, `--field=k=v`).
      if (/^--(?:field|raw-field|input)(?:=|$)/.test(word) || /^-[fF]/.test(word)) return false
      if (name === "--method" || word === "-X" || /^-X\S+$/.test(word)) {
        let method: string | undefined
        if (/^-X\S+$/.test(word)) method = word.slice(2).replace(/^=/, "")
        else if (name === "--method" && eq > 0) method = word.slice(eq + 1)
        else if (k + 1 < rest.length) {
          method = rest[k + 1]
          k += 1
        }
        if (!/^(?:GET|HEAD)$/i.test(method ?? "")) return false
        continue
      }
      if (GH_API_VALUE.has(name)) {
        if (eq < 0) {
          if (k + 1 >= rest.length) return false
          k += 1
        }
        continue
      }
      // Clustered shorthand spellings of the same value flags (`-HAccept:x`,
      // `-q.foo`, `-pname`).
      if (/^-[Hqp]\S+$/.test(word)) continue
      return false
    }
    return endpoint
  }
  if (group === "auth") {
    // `-t`/`--show-token` prints the OAuth token; that includes clustered
    // shorthands (`-ta`) and `--show-token=true`.
    const leaksToken = (w: string) => /^--show-token(?:=|$)/.test(w) || /^-[^-]*t/.test(w)
    return rest[0] === "status" && !rest.some(leaksToken)
  }
  const subs = group ? GH_READ[group] : undefined
  if (!subs || !rest[0] || !subs.has(rest[0])) return false
  // `gh run view --log` / `gh pr view` read; anything that downloads or edits
  // has its own subcommand and is not listed above.
  return true
}

const TMUX_READ = new Set([
  "ls", "list-sessions", "list-windows", "list-panes", "list-clients", "has-session", "has",
  "show-options", "show", "show-environment",
])

function proveTmuxRead(argv: string[], i: number): boolean {
  const sub = argv[i + 1]
  if (!sub) return false
  // `;` is a tmux command separator even inside argv: `list-sessions ';'
  // run-shell '…'` runs a second command behind the read one. Any `;` in the
  // remaining words leaves the invocation unproven rather than trusting only
  // the first command.
  if (argv.slice(i + 2).some((word) => word.includes(";"))) return false
  if (TMUX_READ.has(sub)) return true
  // capture-pane without -p copies into a paste buffer; with -p it prints.
  if ((sub === "capture-pane" || sub === "capturep") && argv.slice(i + 2).includes("-p")) return true
  if ((sub === "display-message" || sub === "display") && argv.slice(i + 2).includes("-p")) return true
  return false
}

// Input-derived paths are never content-revealing: `find ~ -name '*.pem' |
// xargs cat` would read keys the literal-path checks never see, so only
// readers that print names, sizes, or hashes qualify.
const XARGS_READERS = new Set([
  "echo", "printf", "basename", "dirname", "wc", "ls", "file", "stat", "du",
  "realpath", "readlink", "sha256sum", "sha1sum", "md5sum",
])
const XARGS_VALUE_FLAGS = new Set(["-n", "-L", "-P", "-d", "-I", "-s", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--max-lines"])
const XARGS_FLAG_ONLY = new Set(["-0", "-r", "-t", "--null", "--no-run-if-empty", "--verbose", "-x", "--exit"])

function proveXargsRead(argv: string[], i: number): boolean {
  let k = i + 1
  for (; k < argv.length; k += 1) {
    const word = argv[k]
    if (word === "--") {
      k += 1
      break
    }
    if (XARGS_FLAG_ONLY.has(word)) continue
    if (XARGS_VALUE_FLAGS.has(word)) {
      if (word === "-a") return false // reads arguments from a file the segment does not show
      k += 1
      continue
    }
    if (/^-[nLPdIsE]\S+$/.test(word) || /^--(?:max-args|max-procs|delimiter|max-lines)=/.test(word)) continue
    if (word.startsWith("-")) return false
    break
  }
  // Input-derived words become arguments of the consumer; every reader listed
  // here has no option that executes a program or writes a file.
  const leaf = argv[k]
  if (leaf === "grep" || leaf === "egrep" || leaf === "fgrep") {
    // Name/count-only output (`-l`, `-L`, `-c`, `-q`) reveals no content.
    const rest = argv.slice(k + 1)
    return rest.some((w) => /^-[a-zA-Z]*[lLcq][a-zA-Z]*$/.test(w) || /^--(?:files-with(?:out)?-matches|count|quiet)$/.test(w)) &&
      !rest.some((w) => /^-[a-zA-Z]*[oA-CZ]/.test(w) || /^--(?:only-matching|after-context|before-context|context)/.test(w))
  }
  return Boolean(leaf && XARGS_READERS.has(leaf))
}

// --- python -m / -c ------------------------------------------------------------------

const JSON_TOOL_FLAGS = new Set(["--sort-keys", "--compact", "--no-ensure-ascii", "--json-lines", "--tab", "--no-indent"])

async function provePythonInvocation(argv: string[], i: number, ctx: PathContext): Promise<SemanticProof | undefined> {
  if (!isPlainPythonInterpreter(argv[i])) return undefined
  const j = pythonFlagsEnd(argv, i)
  const mode = argv[j]
  if (mode === "-m") {
    const module = argv[j + 1]
    const args = argv.slice(j + 2)
    if (module === "json.tool") {
      const positional: string[] = []
      for (let k = 0; k < args.length; k += 1) {
        if (JSON_TOOL_FLAGS.has(args[k])) continue
        if (args[k] === "--indent") {
          if (!/^\d{1,2}$/.test(args[k + 1] ?? "")) return undefined
          k += 1
          continue
        }
        if (args[k].startsWith("-")) return undefined
        positional.push(args[k])
      }
      // A second positional is an output file.
      if (positional.length > 1) return undefined
      if (positional[0] && classifyPathTarget(positional[0], "read", ctx).kind !== "pass") return undefined
      if (shadowsModule(ctx.cwd, "json")) return undefined
      return { rule: "operation.semantic-read", reason: "Pretty-prints JSON with the standard library" }
    }
    if (module === "unittest") {
      if (shadowsModule(ctx.cwd, "unittest")) return undefined
      return { rule: "operation.known-safe", reason: "Runs the project's unit tests" }
    }
    return undefined
  }
  if (mode === "-c") {
    const program = argv[j + 1]
    if (program === undefined) return undefined
    const proof = await provePythonReadOnly(program, [ctx.cwd])
    if (!proof.ok || !provenPathsReadable(proof.paths, ctx)) return undefined
    return { rule: "execution.python-readonly", reason: "The inline Python program is statically proven read-only" }
  }
  return undefined
}

// --- dispatcher ------------------------------------------------------------------------

const GENERIC_SAFE_ENV = new Set([
  "LANG", "LC_ALL", "LC_CTYPE", "TZ", "NO_COLOR", "FORCE_COLOR", "TERM", "COLUMNS", "LINES",
  "PYTHONIOENCODING", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PYTHONUTF8",
])

/** Literal-argv provers. `argv` is the segment's literal argv with inert
 *  redirects removed; the caller already path-checked any write redirect. */
export async function proveLiteralInvocation(argv: string[], ctx: PathContext): Promise<SemanticProof | undefined> {
  const i = skipAssignments(argv, GENERIC_SAFE_ENV)
  if (i < 0 || i >= argv.length) return undefined
  const head = argv[i]
  if (proveVersionQuery(argv, i)) {
    return { rule: "operation.semantic-read", reason: "Prints a tool's version or help text" }
  }
  if (isPlainPythonInterpreter(head)) {
    if (skipAssignments(argv, PYTHON_SAFE_ENV) !== i) return undefined
    return provePythonInvocation(argv, i, ctx)
  }
  switch (head) {
    case "sqlite3":
      return proveSqliteCli(argv, i, ctx)
        ? { rule: "operation.semantic-read", reason: "Runs read-only SQL through the sqlite3 shell" }
        : undefined
    case "curl":
      return proveCurlLoopbackGet(argv, i)
        ? { rule: "operation.semantic-read", reason: "Sends a GET request to a loopback address" }
        : undefined
    case "gh":
      return proveGhRead(argv, i)
        ? { rule: "operation.semantic-read", reason: "Reads GitHub state through the gh CLI" }
        : undefined
    case "tmux":
      return proveTmuxRead(argv, i)
        ? { rule: "operation.semantic-read", reason: "Inspects tmux sessions without sending input" }
        : undefined
    case "xargs":
      return proveXargsRead(argv, i)
        ? { rule: "operation.semantic-read", reason: "Feeds input to a read-only command through xargs" }
        : undefined
    default:
      return undefined
  }
}

// --- user-trusted commands --------------------------------------------------------------

/** Parses `trustedCommands` entries (`"agent-browser"`, `"opencode2 --version"`)
 *  into argv prefixes. Entries with shell syntax are dropped. */
export function parseTrustedCommands(entries: readonly string[]): string[][] {
  const out: string[][] = []
  for (const entry of entries) {
    if (typeof entry !== "string") continue
    const words = entry.trim().split(/\s+/).filter(Boolean)
    if (words.length === 0) continue
    if (words.some((w) => /[$`'"\\;&|<>(){}*?[\]]/.test(w))) continue
    out.push(words)
  }
  return out
}

/** Bare names match through PATH only; an absolute rule matches that exact
 *  path. A relative path in the segment (`./tool`) never matches a bare name
 *  — it would run whatever file the worktree holds under that name. */
export function matchesTrustedCommand(words: string[], rules: readonly string[][]): boolean {
  return rules.some((rule) => {
    if (words.length < rule.length) return false
    return rule.every((part, k) => words[k] === part)
  })
}

export function isRegularFile(p: string): boolean {
  try {
    return statSync(p).isFile()
  } catch {
    return false
  }
}

/** `.git/config` of a repository outside the worktree that arms external
 *  programs read subcommands can reach (`core.fsmonitor` on status, clean
 *  filters, textconv/external diff, pagers, signature programs, includes)
 *  turns even `git -C <dir> status` into code execution. Hooks, aliases,
 *  editors and network helpers never run on the read subcommands allowed. */
export function foreignGitConfigArmed(dir: string): boolean {
  const gitPath = path.join(dir, ".git")
  let configPath = path.join(gitPath, "config")
  try {
    if (statSync(gitPath).isFile()) return true // worktree/submodule pointer: not inspected
  } catch {
    // Not a repo root (or unreadable): a parent repo may apply — not inspected.
    return true
  }
  if (!existsSync(configPath)) return true
  let text: string
  try {
    text = readFileSync(configPath, "utf8")
  } catch {
    return true
  }
  return /^\s*(?:fsmonitor|pager|textconv|external|program|clean|smudge|process|command|path|worktree)\s*=|^\s*\[(?:include|includeif|filter|diff\s|pager|gpg)/im.test(text)
}

import { execFile } from "node:child_process"
import { existsSync, lstatSync, realpathSync } from "node:fs"
import { realpath, stat } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import path from "node:path"

function contains(root: string, target: string): boolean {
  const relative = path.relative(root, target)
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
}

/** Host-owned unconditional write roots, shared by all session modes. */
export function alwaysWritableRoots(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): string[] {
  if (platform === "linux") return ["/tmp"]
  if (platform !== "win32") return []
  const temporary = env.TEMP?.trim()
  if (!temporary || !path.win32.isAbsolute(temporary)) return []
  const normalized = path.win32.normalize(temporary)
  // Cross-platform callers can compare Windows paths without asking the local
  // filesystem to interpret a different OS's drive letters.
  if (platform !== process.platform) return [normalized]
  const canonical = canonicalCandidate(normalized)
  return canonical === undefined ? [] : [canonical]
}

/** Callers pass a canonical target: external symlink/junction referents do not
 * borrow the temp directory's unconditional write allowance. */
export function isAlwaysWritablePath(target: string, platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): boolean {
  const paths = platform === "win32" ? path.win32 : path.posix
  return alwaysWritableRoots(platform, env).some((root) => {
    const relative = paths.relative(root, target)
    return relative === "" || (relative !== ".." && !relative.startsWith(`..${paths.sep}`) && !paths.isAbsolute(relative))
  })
}

/** Resolve an existing ancestor without creating anything. Dangling symlinks
 *  and non-missing-path failures are not grants. */
export function canonicalCandidate(target: string): string | undefined {
  try {
    return realpathSync(target)
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code
    if (code !== "ENOENT" && code !== "ENOTDIR") return undefined
    try {
      if (lstatSync(target).isSymbolicLink()) return undefined
    } catch (missing) {
      const code = (missing as NodeJS.ErrnoException).code
      if (code !== "ENOENT" && code !== "ENOTDIR") return undefined
    }
    const parent = path.dirname(target)
    if (parent === target) return undefined
    const resolved = canonicalCandidate(parent)
    return resolved === undefined ? undefined : path.join(resolved, path.basename(target))
  }
}

/** Small Auto-mode expansion for ordinary tool caches, not all HOME or user
 *  settings/state. Roots redirected through symlinks are never adopted. */
export function standardCacheWriteRoots(home = homedir()): string[] {
  if (process.platform !== "linux" || !path.isAbsolute(home)) return []
  return [path.join(home, ".cache"), path.join(home, ".npm", "_cacache")]
    .filter((root) => canonicalCandidate(root) === root)
}

/** Incidental tool cache/history write roots, shared by Auto and ReadOnly
 *  sessions: read-oriented CLIs append these as a side effect, and treating
 *  them as boundary crossings either kills the command (ReadOnly) or spends a
 *  model review on a `.lesshst` append (Auto). They are passed to the runtime
 *  observer as extra write roots — the observer canonicalizes targets before
 *  matching, so a symlinked file still resolves to the exempted object.
 *
 *  Directory entries keep the strict no-redirect rule of
 *  standardCacheWriteRoots (a symlinked directory would roam the grant).
 *  Single-file entries may not exist yet, so the deepest-existing-ancestor
 *  canonical form is used; a dangling symlink leaf is refused by
 *  canonicalCandidate and never adopted. */
export function incidentalWriteRoots(home = homedir(), env = process.env): string[] {
  if (process.platform !== "linux" || !path.isAbsolute(home)) return []
  const stateHome = env.XDG_STATE_HOME && path.isAbsolute(env.XDG_STATE_HOME)
    ? env.XDG_STATE_HOME
    : path.join(home, ".local", "state")
  const directories = [path.join(home, ".cache")]
  const files = [
    path.join(home, ".sqlite_history"),
    // less writes its history to $XDG_STATE_HOME/lesshst when set, else
    // ~/.local/state/lesshst, else the legacy ~/.lesshst.
    path.join(stateHome, "lesshst"),
    path.join(home, ".local", "state", "lesshst"),
    path.join(home, ".lesshst"),
    path.join(home, ".python_history"),
    path.join(home, ".node_repl_history"),
    path.join(home, ".psql_history"),
    path.join(home, ".mysql_history"),
    path.join(home, ".rediscli_history"),
  ]
  const roots: string[] = []
  for (const directory of directories) {
    if (canonicalCandidate(directory) === directory && !roots.includes(directory)) roots.push(directory)
  }
  for (const file of files) {
    const canonical = canonicalCandidate(file)
    if (canonical === undefined) continue
    try {
      if (!lstatSync(canonical).isFile()) continue
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") continue
    }
    if (canonical !== undefined && !roots.includes(canonical)) roots.push(canonical)
  }
  return roots
}

/** Path components whose writes are incidental tool artifacts wherever they
 *  appear: interpreter bytecode caches (Python writes `*.pyc` payloads under a
 *  short-lived `name.pyc.PID` sibling, so the directory itself and every
 *  rename inside it must match) and pytest's `.pytest_cache` state. */
const INCIDENTAL_WRITE_COMPONENTS = new Set(["__pycache__", ".pytest_cache"])

/** Name-matched incidental write: the target is one of the exempt component
 *  directories or sits inside one. Callers MUST additionally exclude
 *  denyWrite/protect/credential paths — a `.pytest_cache` directory inside a
 *  protected tree is not exempt. */
export function isIncidentalToolWrite(target: string): boolean {
  return target.split(path.sep).some((component) => INCIDENTAL_WRITE_COMPONENTS.has(component))
}

export function isStandardCacheWrite(target: string, home = homedir()): boolean {
  const roots = standardCacheWriteRoots(home)
  if (!roots.some((root) => contains(root, target))) return false
  const canonical = canonicalCandidate(target)
  return canonical !== undefined && roots.some((root) => contains(root, canonical))
}

function capture(file: string, args: string[]): Promise<string | undefined> {
  return new Promise((resolve) => {
    try {
      execFile(file, args, { timeout: 3_000, cwd: "/" }, (error, stdout) => resolve(error ? undefined : String(stdout)))
    } catch {
      resolve(undefined)
    }
  })
}

let wslWindowsTemp: Promise<string[]> | undefined

/** WSL only: use inherited Windows paths or the conventional profile temp
 * directory. Never launch a Windows executable: discovery can itself run
 * inside a watched command and must not trigger an interop boundary. */
function wslWindowsTempDirs(): Promise<string[]> {
  return wslWindowsTemp ??= (async () => {
    if (!process.env.WSL_DISTRO_NAME && !existsSync("/proc/sys/fs/binfmt_misc/WSLInterop")) return []
    const candidates = [process.env.TEMP, process.env.TMP]
    if (process.env.LOCALAPPDATA) {
      candidates.push(path.win32.join(process.env.LOCALAPPDATA, "Temp"))
    } else if (process.env.USERPROFILE) {
      candidates.push(path.win32.join(process.env.USERPROFILE, "AppData", "Local", "Temp"))
    } else {
      const username = process.env.USERNAME ?? path.basename(homedir())
      if (username && !/[\\/]/.test(username)) {
        candidates.push(`/mnt/c/Users/${username}/AppData/Local/Temp`)
      }
    }
    const dirs: string[] = []
    for (const candidate of candidates) {
      if (!candidate) continue
      const converted = /^[A-Za-z]:[\\/]/.test(candidate)
        ? (await capture("wslpath", ["-u", candidate]))?.trim()
        : candidate
      if (converted && path.isAbsolute(converted)) dirs.push(converted)
    }
    return dirs
  })()
}

/** Global temporary directories that stay writable in Read only mode:
 *  `extra` (the configured scratch), /tmp, /var/tmp, the process temp dir and,
 *  on WSL, the Windows user's temp dir. Explicit extra roots may be missing
 *  so mkdir can create them; discovered temp dirs must already exist.
 *  A redirected TMPDIR never turns "/" or HOME into a temp root. */
export async function globalTempWriteRoots(extra: readonly string[] = [], home = homedir()): Promise<string[]> {
  if (process.platform === "win32") return alwaysWritableRoots()
  if (process.platform !== "linux") return []
  const roots: string[] = []
  for (const candidate of extra) {
    if (!path.isAbsolute(candidate)) continue
    const canonical = canonicalCandidate(candidate)
    if (canonical !== candidate || (!isAlwaysWritablePath(canonical) && contains(canonical, home)) || canonical === path.parse(canonical).root) continue
    const directory = await stat(canonical).catch((error: NodeJS.ErrnoException) => error.code === "ENOENT" ? undefined : null)
    if (directory === null) continue
    if ((!directory || directory.isDirectory()) && !roots.includes(canonical)) roots.push(canonical)
  }
  for (const candidate of ["/tmp", "/var/tmp", tmpdir(), ...await wslWindowsTempDirs()]) {
    if (!path.isAbsolute(candidate)) continue
    const canonical = await realpath(candidate).catch(() => undefined)
    if (!canonical || !(await stat(canonical).catch(() => undefined))?.isDirectory()) continue
    if ((!isAlwaysWritablePath(canonical) && contains(canonical, home)) || canonical === path.parse(canonical).root) continue
    if (!roots.includes(canonical)) roots.push(canonical)
  }
  return roots
}

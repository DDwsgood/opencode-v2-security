import { execFile } from "node:child_process"
import { existsSync, lstatSync, realpathSync, statSync } from "node:fs"
import { realpath, stat } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import path from "node:path"

function contains(root: string, target: string): boolean {
  return containsUnder(path, root, target)
}

function containsUnder(paths: typeof path.posix, root: string, target: string): boolean {
  const relative = paths.relative(root, target)
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${paths.sep}`) && !paths.isAbsolute(relative))
}

/** Host-owned unconditional write roots, shared by all session modes. */
export function alwaysWritableRoots(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): string[] {
  if (platform === "linux") return ["/tmp"]
  if (platform !== "win32") return []
  const temporary = env.TEMP?.trim()
  if (!temporary) return []
  // TEMP is host-configured, not host-trusted: a redirected TMPDIR must not
  // turn HOME, a profile/system directory or a volume root into an
  // unconditional write grant. Validate the raw spelling first.
  const home = env.USERPROFILE?.trim() || env.HOME?.trim() || ""
  const normalized = windowsTempRootCandidate(temporary, home)
  if (normalized === undefined) return []
  // Cross-platform callers can compare Windows paths without asking the local
  // filesystem to interpret a different OS's drive letters.
  if (platform !== process.platform) return [normalized]
  const canonical = canonicalCandidate(normalized)
  if (canonical === undefined) return []
  // A junction/symlink TEMP must not resolve onto a rejected root either, and
  // the grant itself has to be a directory. The canonical spelling also
  // absorbs case differences, which Windows compares without case.
  if (windowsTempRootCandidate(canonical, home) === undefined) return []
  try {
    if (!statSync(canonical).isDirectory()) return []
  } catch {
    return []
  }
  return [canonical]
}

/** The string is spelled as a Windows path: drive-letter (absolute or
 *  drive-relative) or a UNC/device namespace. Callers use this to choose the
 *  Windows validator without consulting the host platform. */
export function isWindowsPath(value: string): boolean {
  return /^[A-Za-z]:/.test(value) || value.startsWith("\\\\")
}

const WINDOWS_RESERVED_NAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?$/i

/** Windows-only path shapes that a POSIX "absolute path" check does not see.
 *
 * Returns a human-readable reason, or undefined for a plain absolute drive
 * path. Rejected: control characters, UNC/device namespaces (`\\server\share`,
 * `\\?\…`, `\\.\…`), drive-relative spellings (`C:foo`), alternate data
 * streams (`file:stream`), the bare volume root, `.`/`..` segments, reserved
 * device names, characters Windows forbids, and segments ending in a space or
 * dot (Windows aliases those to the trimmed name, so a written path would not
 * name the object the caller validated). */
export function windowsPathHazard(value: string): string | undefined {
  if (/[\u0000-\u001F]/.test(value)) return "the path contains control characters"
  const unified = value.replaceAll("/", "\\")
  if (unified.startsWith("\\\\")) return "UNC and device-namespace paths are not supported"
  if (!/^[A-Za-z]:\\/.test(unified)) return "the path must be an absolute drive path"
  if (unified.slice(2).includes(":")) return "alternate data stream paths are not supported"
  if (/[*?"<>|]/.test(unified)) return "the path contains characters Windows does not allow"
  const segments = unified.slice(3).split("\\").filter((segment) => segment.length > 0)
  if (segments.length === 0) return "the volume root is not supported"
  if (segments.some((segment) => segment === "." || segment === "..")) return 'the path may not contain "." or ".." segments'
  if (segments.some((segment) => WINDOWS_RESERVED_NAME.test(segment))) return "reserved device names are not supported"
  if (segments.some((segment) => /[ .]$/.test(segment))) return "path segments may not end with a space or dot"
  return undefined
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

/** Windows-only rejection of a candidate temp/write root: HOME itself, an
 *  ancestor of HOME (volume root, `C:\Users`, `C:\Windows`), and every
 *  UNC/device/ADS/traversal spelling. Purely lexical; redirect checks follow. */
export function windowsTempRootRejection(candidate: string, home: string): string | undefined {
  if (!path.win32.isAbsolute(candidate)) return "the path is not absolute"
  const hazard = windowsPathHazard(candidate)
  if (hazard) return hazard
  const normalized = path.win32.normalize(candidate)
  const trimmed = normalized.replace(/\\+$/, "") || normalized
  if (/^[A-Za-z]:$/.test(trimmed)) return "the volume root is not supported"
  if (/^[A-Za-z]:\\(?:users|windows)$/i.test(trimmed)) return "the root is a profile or system directory"
  if (home.trim() && path.win32.isAbsolute(home)) {
    if (containsUnder(path.win32, trimmed, path.win32.normalize(home))) return "the root covers HOME"
  }
  return undefined
}

/** Lexically accepted Windows temp root, normalized; undefined when the
 *  spelling is dangerous. Filesystem checks (redirect, kind) follow in
 *  alwaysWritableRoots/globalTempWriteRoots on an actual Windows host. */
export function windowsTempRootCandidate(candidate: string, home: string): string | undefined {
  if (windowsTempRootRejection(candidate, home)) return undefined
  const normalized = path.win32.normalize(candidate)
  return normalized.replace(/\\+$/, "") || normalized
}

/** Windows Read only temp roots: the validated unconditional TEMP grant plus
 *  the configured scratch. Explicit roots may be missing so mkdir can create
 *  them; a redirected root (junction/symlink) is never adopted. */
async function windowsTempWriteRoots(extra: readonly string[], home: string): Promise<string[]> {
  const roots = alwaysWritableRoots("win32")
  for (const candidate of extra) {
    const normalized = windowsTempRootCandidate(candidate, home)
    if (normalized === undefined || roots.includes(normalized)) continue
    // A Windows path can only be inspected from a Windows host: resolving it
    // through the local POSIX filesystem would prove nothing.
    if (process.platform !== "win32") continue
    if (canonicalCandidate(normalized) !== normalized) continue
    const directory = await stat(normalized).catch((error: NodeJS.ErrnoException) => error.code === "ENOENT" ? undefined : null)
    if (directory === null) continue
    if (!directory || directory.isDirectory()) roots.push(normalized)
  }
  return roots
}

/** Global temporary directories that stay writable in Read only mode:
 *  `extra` (the configured scratch), /tmp, /var/tmp, the process temp dir and,
 *  on WSL, the Windows user's temp dir. Explicit extra roots may be missing
 *  so mkdir can create them; discovered temp dirs must already exist.
 *  A redirected TMPDIR never turns "/" or HOME into a temp root. On Windows
 *  the same rule applies to the configured scratch: a volume root, HOME or an
 *  ancestor of HOME (profile/system directory), a redirected root, or a
 *  UNC/device/ADS spelling never becomes a temp root. */
export async function globalTempWriteRoots(
  extra: readonly string[] = [],
  home = homedir(),
  platform: NodeJS.Platform = process.platform,
): Promise<string[]> {
  if (platform === "win32") return windowsTempWriteRoots(extra, home)
  if (platform !== "linux") return []
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

import { lstatSync } from "node:fs"
import path from "node:path"
import { canonicalCandidate } from "./automatic-write-roots"
import { checkResolvedPathSensitivity } from "./paths"

export interface WriteRootPolicy {
  home: string
  cwd: string
  credentialPaths: readonly string[]
  denyWrite: readonly string[]
  protect: readonly string[]
  brokerBase?: string
}

export function containsWritePath(root: string, target: string): boolean {
  const relative = path.relative(root, target)
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
}

function overlaps(root: string, target: string): boolean {
  return containsWritePath(root, target) || containsWritePath(target, root)
}

const BROKER_DIRECTORIES_KEY = Symbol.for("opencode-v2-security.runtime-broker-directories.v1")
const processState = globalThis as typeof globalThis & { [BROKER_DIRECTORIES_KEY]?: Set<string> }
const activeBrokerDirectories = processState[BROKER_DIRECTORIES_KEY] ??= new Set<string>()

/** Share protection across plugin instances without reserving other processes'
 * broker names or preventing a traced child from creating its own broker. */
export function registerRuntimeBrokerDirectory(directory: string): () => void {
  const normalized = path.resolve(directory)
  activeBrokerDirectories.add(normalized)
  return () => { activeBrokerDirectories.delete(normalized) }
}

export function isRuntimeBrokerPath(target: string, base?: string): boolean {
  return [...activeBrokerDirectories].some((directory) =>
    (!base || containsWritePath(base, directory)) && containsWritePath(directory, target))
}

/** A grant never follows a redirected root or a symlinked leaf, including a
 * missing descendant whose deepest existing ancestor is redirected. */
export function canonicalWriteRoot(target: string): string | undefined {
  const normalized = path.resolve(target)
  if (canonicalCandidate(normalized) !== normalized) return undefined
  try {
    if (lstatSync(normalized).isSymbolicLink()) return undefined
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") return undefined
  }
  return normalized
}

function protectedOverlap(target: string, policy: WriteRootPolicy): boolean {
  return [...policy.credentialPaths, ...policy.denyWrite, ...policy.protect].some((blocked) =>
    overlaps(target, blocked) || overlaps(target, canonicalCandidate(blocked) ?? blocked))
}

export function writeRootRejection(root: string, policy: WriteRootPolicy): string | undefined {
  if (canonicalWriteRoot(root) !== root) return "the root is redirected or cannot be canonicalized"
  if (root === path.parse(root).root || containsWritePath(root, policy.home) ||
    containsWritePath(root, canonicalCandidate(policy.home) ?? policy.home)) return "the root covers HOME or the filesystem root"
  if (protectedOverlap(root, policy)) return "the root overlaps a denied, credential, or protected path"
  if (policy.brokerBase && isRuntimeBrokerPath(root, policy.brokerBase)) {
    return "the root overlaps the runtime broker directory"
  }
  const sensitivity = checkResolvedPathSensitivity(root)
  if (!sensitivity.parseable || sensitivity.sensitive) return "the root is sensitive or unparseable"
  return undefined
}

/** Shared per-target backstop for incidental, configured and temporary roots.
 * Ancestor mutations cannot replace a denied/protected subtree. */
export function writeTargetExempt(target: string, policy: WriteRootPolicy): boolean {
  if (protectedOverlap(target, policy)) return false
  if (policy.brokerBase && isRuntimeBrokerPath(target, policy.brokerBase)) return false
  const sensitivity = checkResolvedPathSensitivity(target)
  return sensitivity.parseable && !sensitivity.sensitive
}

export function resolveAllowWriteRoots(raw: unknown, policy: WriteRootPolicy): { roots: string[]; warnings: string[] } {
  if (raw === undefined) return { roots: [], warnings: [] }
  if (!Array.isArray(raw)) throw new Error("sandbox.allowWrite must be an array of absolute path strings")
  const roots: string[] = []
  const warnings: string[] = []
  for (const [index, entry] of raw.entries()) {
    if (typeof entry !== "string" || !entry.trim()) throw new Error("sandbox.allowWrite entries must be absolute path strings")
    const trimmed = entry.trim()
    let expanded = trimmed
    if (trimmed === "~") expanded = policy.home
    else if (trimmed.startsWith("~/")) expanded = path.join(policy.home, trimmed.slice(2))
    if (!path.isAbsolute(expanded)) throw new Error("sandbox.allowWrite entries must be absolute path strings (or ~ / ~/…)")
    const normalized = path.resolve(expanded)
    const rejection = /[\0\r\n]/.test(expanded) ? "the path contains control characters" : writeRootRejection(normalized, policy)
    if (rejection) warnings.push(`sandbox.allowWrite entry ${index + 1} ignored: ${rejection}`)
    else if (!roots.includes(normalized)) roots.push(normalized)
  }
  return { roots, warnings }
}

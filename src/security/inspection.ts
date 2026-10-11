import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, statfsSync, type Dirent, type Stats } from "node:fs"
import { lstat, open, opendir, readlink, statfs } from "node:fs/promises"

/** Diagnostics describe the inspection, never the contents or a raw provider error. */
export function inspectionErrorCode(error: unknown): string {
  const code = error && typeof error === "object" && "code" in error ? error.code : undefined
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "unavailable"
}

export function isMissingPathError(error: unknown): boolean {
  return inspectionErrorCode(error) === "ENOENT" || inspectionErrorCode(error) === "ENOTDIR"
}

export function isPseudoFilePath(target: string): boolean {
  return /^\/(?:proc|sys|dev)(?:\/|$)/.test(target)
}

// Pseudo-files can report S_IFREG while open/read has device-like side effects.
const PSEUDO_FILESYSTEMS = new Set([0x9fa0, 0x62656572, 0x64626720, 0x74726163, 0x73636673, 0x62656570, 0x27e0eb, 0x63677270, 0xcafe4a11])
const READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0) | (constants.O_NOCTTY ?? 0)

export async function inspectDirectory(target: string, maximumEntries: number): Promise<{ entries: Dirent[]; truncated: boolean } | undefined> {
  try {
    const entries: Dirent[] = []
    const directory = await opendir(target)
    for await (const entry of directory) {
      if (entries.length === maximumEntries) return { entries, truncated: true }
      entries.push(entry)
    }
    return { entries, truncated: false }
  } catch {
    return undefined
  }
}

export type TextInspection =
  | { ok: true; content: Buffer; text: string; info: Stats }
  | { ok: false; reason: string }

function inspectedText(content: Buffer, info: Stats, maximumBytes: number): TextInspection {
  if (content.length > maximumBytes) return { ok: false, reason: `exceeds ${maximumBytes}-byte evidence bound` }
  if (content.includes(0)) return { ok: false, reason: "binary file" }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(content)
    return { ok: true, content, text, info }
  } catch {
    return { ok: false, reason: "file is not valid UTF-8" }
  }
}

/** Only ordinary, bounded files are opened. Errors and object races mean missing
 * evidence, not a safe verdict. NONBLOCK also covers a regular→FIFO swap. */
export async function inspectRegularTextFile(target: string, maximumBytes: number): Promise<TextInspection> {
  try {
    if (isPseudoFilePath(target)) return { ok: false, reason: "pseudo-file content is not collected" }
    const before = await lstat(target)
    if (!before.isFile()) return { ok: false, reason: "not a regular file" }
    if (before.size > maximumBytes) return { ok: false, reason: `exceeds ${maximumBytes}-byte evidence bound` }
    if (process.platform === "linux" && PSEUDO_FILESYSTEMS.has((await statfs(target)).type)) {
      return { ok: false, reason: "pseudo-filesystem content is not collected" }
    }
    const handle = await open(target, READ_FLAGS)
    try {
      const info = await handle.stat()
      if (!info.isFile() || info.dev !== before.dev || info.ino !== before.ino) return { ok: false, reason: "file identity changed during inspection" }
      if (info.size > maximumBytes) return { ok: false, reason: `exceeds ${maximumBytes}-byte evidence bound` }
      const licensed = await lstat(target)
      if (licensed.dev !== info.dev || licensed.ino !== info.ino) return { ok: false, reason: "file identity changed during inspection" }
      if (process.platform === "linux") {
        const backing = await readlink(`/proc/self/fd/${handle.fd}`)
        if (backing !== target) return { ok: false, reason: "file backing path changed during inspection" }
      }
      const buffer = Buffer.alloc(maximumBytes + 1)
      let bytesRead = 0
      while (bytesRead < buffer.length) {
        const chunk = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead)
        if (chunk.bytesRead === 0) break
        bytesRead += chunk.bytesRead
      }
      const after = await handle.stat()
      if (after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs || bytesRead !== info.size) {
        return { ok: false, reason: "file changed during inspection" }
      }
      return inspectedText(buffer.subarray(0, bytesRead), info, maximumBytes)
    } finally {
      await handle.close()
    }
  } catch (error) {
    return { ok: false, reason: inspectionErrorCode(error) }
  }
}

/** Synchronous counterpart for the existing Git-config static prover. */
export function inspectRegularTextFileSync(target: string, maximumBytes: number): TextInspection {
  try {
    if (isPseudoFilePath(target)) return { ok: false, reason: "pseudo-file content is not collected" }
    const before = lstatSync(target)
    if (!before.isFile()) return { ok: false, reason: "not a regular file" }
    if (before.size > maximumBytes) return { ok: false, reason: `exceeds ${maximumBytes}-byte evidence bound` }
    if (process.platform === "linux" && PSEUDO_FILESYSTEMS.has(statfsSync(target).type)) return { ok: false, reason: "pseudo-filesystem content is not collected" }
    const descriptor = openSync(target, READ_FLAGS)
    try {
      const info = fstatSync(descriptor)
      if (!info.isFile() || info.dev !== before.dev || info.ino !== before.ino) return { ok: false, reason: "file identity changed during inspection" }
      const buffer = Buffer.alloc(maximumBytes + 1)
      let bytesRead = 0
      while (bytesRead < buffer.length) {
        const count = readSync(descriptor, buffer, bytesRead, buffer.length - bytesRead, bytesRead)
        if (count === 0) break
        bytesRead += count
      }
      const after = fstatSync(descriptor)
      const licensed = lstatSync(target)
      if (licensed.dev !== info.dev || licensed.ino !== info.ino || after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs || bytesRead !== info.size) {
        return { ok: false, reason: "file changed during inspection" }
      }
      return inspectedText(buffer.subarray(0, bytesRead), info, maximumBytes)
    } finally {
      closeSync(descriptor)
    }
  } catch (error) {
    return { ok: false, reason: inspectionErrorCode(error) }
  }
}

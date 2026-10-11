import { lstat, readFile, realpath } from "node:fs/promises"
import path from "node:path"

/** Read a small text file (git metadata pointers are tiny). Anything missing,
 *  unreadable or unexpectedly large is a verification failure, never a root. */
async function readSmallText(file: string): Promise<string | undefined> {
  try {
    const text = await readFile(file, "utf8")
    if (text.length > 4096) return undefined
    return text.trim()
  } catch {
    return undefined
  }
}

/** Resolve the path inside a `gitdir:` pointer file. Git writes absolute
 *  paths; relative values are resolved against the directory containing the
 *  pointer file, which is also how git itself reads them. */
function resolveGitPointer(raw: string, base: string): string {
  return path.isAbsolute(raw) ? raw : path.resolve(base, raw)
}

/**
 * The private metadata directory of a LINKED git worktree.
 *
 * When the session workspace is a linked worktree, `cwd/.git` is a FILE whose
 * `gitdir: <path>` pointer names the worktree's private directory
 * `<main-repo>/.git/worktrees/<name>`. Ordinary git activity there (index,
 * HEAD, reflogs, MERGE_HEAD…) is routine bookkeeping, not a boundary
 * crossing — so the caller adds exactly that directory to the shell write
 * roots of Auto/write sessions.
 *
 * Every link is verified before the directory is returned; ANY failure or
 * inconsistency yields `undefined` (no extra root, never a refusal):
 *
 * - `cwd/.git` must be a regular file with a parseable `gitdir:` pointer;
 * - the pointer must canonicalize (realpath) to an existing directory;
 * - that directory must contain a `commondir` file whose target
 *   canonicalizes to the repository's common `.git` directory (a real git
 *   dir: `HEAD` file + `objects` directory);
 * - the private directory must be exactly `<commondir>/worktrees/<name>`;
 * - the private directory's `gitdir` file must point back to `cwd/.git`,
 *   so a forged `.git` file naming some other worktree's private dir (or an
 *   unrelated directory) is ignored.
 */
export async function linkedWorktreePrivateDir(cwd: string): Promise<string | undefined> {
  try {
    const dotGit = path.join(cwd, ".git")
    const pointerInfo = await lstat(dotGit)
    if (!pointerInfo.isFile()) return undefined
    const pointer = await readSmallText(dotGit)
    const match = /^gitdir:\s*(\S.*?)\s*$/.exec(pointer ?? "")
    if (!match) return undefined
    const privateDir = await realpath(resolveGitPointer(match[1], cwd))
    if (!(await lstat(privateDir)).isDirectory()) return undefined

    // The private dir must describe a real worktree of one repository.
    const commondirText = await readSmallText(path.join(privateDir, "commondir"))
    if (!commondirText) return undefined
    const commondir = await realpath(resolveGitPointer(commondirText, privateDir))
    if (!(await lstat(commondir)).isDirectory()) return undefined
    if (!(await lstat(path.join(commondir, "HEAD"))).isFile()) return undefined
    if (!(await lstat(path.join(commondir, "objects"))).isDirectory()) return undefined
    if (path.dirname(privateDir) !== path.join(commondir, "worktrees")) return undefined

    // The link must point back to THIS workspace: a `.git` file naming
    // another worktree's (or repository's) private directory is not a grant.
    const gitdirBack = await readSmallText(path.join(privateDir, "gitdir"))
    if (!gitdirBack) return undefined
    const backCanonical = await realpath(resolveGitPointer(gitdirBack, privateDir))
    const dotGitCanonical = await realpath(dotGit)
    if (backCanonical !== dotGitCanonical) return undefined
    return privateDir
  } catch {
    return undefined
  }
}
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import { cleanupTestArtifacts } from "./artifacts"
import { globalTempWriteRoots, isStandardCacheWrite, standardCacheWriteRoots } from "../src/security/automatic-write-roots"
import { classifyPathTarget, looseRelaxationScope } from "../src/security/paths"
import { planFileBoundary } from "../src/tool-boundary"

let root: string
let home: string
let workspace: string
let outside: string
beforeAll(async () => {
  root = await mkdtemp("/tmp/opencode/automatic-cache-")
  home = path.join(root, "home")
  workspace = path.join(root, "workspace")
  outside = path.join(root, "outside")
  await Promise.all([mkdir(path.join(home, ".cache"), { recursive: true }), mkdir(workspace), mkdir(outside)])
})
afterAll(async () => { await cleanupTestArtifacts(root, { recursive: true, force: true }) })

describe("small automatic cache write scope", () => {
  test("ordinary and missing cache targets qualify, adjacent HOME data does not", () => {
    expect(standardCacheWriteRoots(home)).toEqual([path.join(home, ".cache"), path.join(home, ".npm/_cacache")])
    expect(isStandardCacheWrite(path.join(home, ".cache/pip/new/item"), home)).toBe(true)
    expect(isStandardCacheWrite(path.join(home, ".npm/_cacache/new/item"), home)).toBe(true)
    for (const target of [".cache-other/data", ".npmrc", ".npm/config", ".config/settings", ".local/state/data", "ordinary.txt"]) {
      expect(isStandardCacheWrite(path.join(home, target), home)).toBe(false)
    }
  })

  test("cache child symlinks cannot grant writes outside the cache", async () => {
    await symlink(outside, path.join(home, ".cache/escape"))
    expect(isStandardCacheWrite(path.join(home, ".cache/escape/new.txt"), home)).toBe(false)
    const plan = await planFileBoundary("write", { path: path.join(home, ".cache/escape/new.txt"), content: "fixture" }, {
      cwd: workspace, writableRoots: [workspace, ...standardCacheWriteRoots(home)],
    })
    expect(plan.verdict).toBe("ASK")
  })

  test("redirected or dangling cache roots are not adopted", async () => {
    const redirectedHome = path.join(root, "redirected-home")
    await mkdir(redirectedHome)
    await symlink(outside, path.join(redirectedHome, ".cache"))
    expect(standardCacheWriteRoots(redirectedHome)).not.toContain(path.join(redirectedHome, ".cache"))
    expect(isStandardCacheWrite(path.join(redirectedHome, ".cache/file"), redirectedHome)).toBe(false)
    await mkdir(path.join(redirectedHome, ".npm"))
    await symlink(path.join(root, "missing-directory"), path.join(redirectedHome, ".npm/_cacache"))
    expect(standardCacheWriteRoots(redirectedHome)).toEqual([])
  })

  test("ordinary native cache writes skip review but secrets in caches do not", async () => {
    const options = { cwd: workspace, writableRoots: [workspace, ...standardCacheWriteRoots(home)] }
    expect((await planFileBoundary("write", { path: path.join(home, ".cache/plain.txt"), content: "fixture" }, options)).verdict).toBe("ALLOW")
    await writeFile(path.join(home, ".cache/private.key"), "FAKE TEST DATA")
    expect((await planFileBoundary("write", { path: path.join(home, ".cache/private.key"), content: "fixture" }, options)).verdict).toBe("ASK")
  })

  test("Read only temp roots are canonical existing directories and never cover HOME", async () => {
    const roots = await globalTempWriteRoots([path.join(root, "missing"), workspace], "/nonexistent-home")
    expect(roots).toContain(workspace)
    expect(roots).toContain("/tmp")
    expect(roots).not.toContain(path.join(root, "missing"))
    expect(await globalTempWriteRoots([root], path.join(root, "home"))).not.toContain(root)
  })

  test("shell path relaxation is RW-only and credential checks still precede it", () => {
    const oldHome = process.env.HOME
    const oldProfile = process.env.USERPROFILE
    process.env.HOME = home
    delete process.env.USERPROFILE
    try {
      const context = { cwd: workspace, worktree: workspace }
      const plain = path.join(home, ".cache/plain.txt")
      expect(looseRelaxationScope.run("rw", () => classifyPathTarget(plain, "write", context)).kind).toBe("pass")
      expect(looseRelaxationScope.run("ro", () => classifyPathTarget(plain, "write", context)).kind).toBe("ask")
      const secret = looseRelaxationScope.run("rw", () => classifyPathTarget(path.join(home, ".cache/private.key"), "write", context))
      expect(secret.kind).toBe("ask")
      expect("rule" in secret && secret.rule).toBe("credentials.sensitive-access")
      expect(looseRelaxationScope.run("rw", () => classifyPathTarget(path.join(home, ".cache/escape/new.txt"), "write", context)).kind).toBe("ask")
    } finally {
      if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome
      if (oldProfile === undefined) delete process.env.USERPROFILE; else process.env.USERPROFILE = oldProfile
    }
  })
})

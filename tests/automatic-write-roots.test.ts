import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test"
import * as childProcess from "node:child_process"
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import { cleanupTestArtifacts } from "./artifacts"
import { alwaysWritableRoots, globalTempWriteRoots, isAlwaysWritablePath, isStandardCacheWrite, standardCacheWriteRoots } from "../src/security/automatic-write-roots"
import { classifyPathTarget, looseRelaxationScope } from "../src/security/paths"
import { planFileBoundary } from "../src/tool-boundary"

let root: string
let home: string
let workspace: string
let outside: string
beforeAll(async () => {
  root = await mkdtemp("/var/tmp/opencode-automatic-cache-")
  home = path.join(root, "home")
  workspace = path.join(root, "workspace")
  outside = path.join(root, "outside")
  await Promise.all([mkdir(path.join(home, ".cache"), { recursive: true }), mkdir(workspace), mkdir(outside)])
})
afterAll(async () => { await cleanupTestArtifacts(root, { recursive: true, force: true }) })

describe("small automatic cache write scope", () => {
  test("Windows TEMP has the same recursive unconditional grant as Linux /tmp", () => {
    const env = { TEMP: "C:\\Users\\Fixture\\AppData\\Local\\Temp" }
    expect(alwaysWritableRoots("win32", env)).toEqual([env.TEMP])
    for (const target of [env.TEMP, `${env.TEMP}\\nested\\private.key`, "c:/users/fixture/appdata/local/temp/.env.fixture"]) {
      expect(isAlwaysWritablePath(target, "win32", env)).toBe(true)
    }
    for (const target of [`${env.TEMP}-other\\file`, `${env.TEMP}\\..\\outside.txt`, "D:\\Users\\Fixture\\AppData\\Local\\Temp\\file"]) {
      expect(isAlwaysWritablePath(target, "win32", env)).toBe(false)
    }
    expect(alwaysWritableRoots("win32", {})).toEqual([])
    expect(alwaysWritableRoots("win32", { TEMP: "relative" })).toEqual([])
    expect(isAlwaysWritablePath("/tmp", "linux", env)).toBe(true)
    expect(isAlwaysWritablePath("/tmp/nested/private.key", "linux", env)).toBe(true)
    expect(isAlwaysWritablePath("/tmp-other/file", "linux", env)).toBe(false)
  })
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

  test("Read only temp roots accept missing explicit directories but never cover HOME", async () => {
    const oldDistro = process.env.WSL_DISTRO_NAME
    const oldTemp = process.env.TEMP
    process.env.WSL_DISTRO_NAME = "fixture"
    process.env.TEMP = outside
    const spawn = spyOn(childProcess, "execFile")
    try {
      const roots = await globalTempWriteRoots([path.join(root, "missing"), workspace], "/nonexistent-home")
      expect(roots).toContain(workspace)
      expect(roots).toContain("/tmp")
      expect(roots).toContain(outside)
      expect(roots).toContain(path.join(root, "missing"))
      expect(await globalTempWriteRoots([root], path.join(root, "home"))).not.toContain(root)
      expect(await globalTempWriteRoots([], "/tmp/fixture-home")).toContain("/tmp")
      expect(spawn.mock.calls.some(([file]) => /(?:^|[\\/])cmd\.exe$/i.test(String(file)))).toBe(false)
    } finally {
      spawn.mockRestore()
      if (oldDistro === undefined) delete process.env.WSL_DISTRO_NAME
      else process.env.WSL_DISTRO_NAME = oldDistro
      if (oldTemp === undefined) delete process.env.TEMP
      else process.env.TEMP = oldTemp
    }
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

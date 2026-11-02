import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test"
import * as childProcess from "node:child_process"
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import { cleanupTestArtifacts } from "./artifacts"
import { alwaysWritableRoots, globalTempWriteRoots, isAlwaysWritablePath, isStandardCacheWrite, standardCacheWriteRoots, windowsTempRootCandidate, windowsTempRootRejection } from "../src/security/automatic-write-roots"
import { checkResolvedPathSensitivity, classifyPathTarget, credentialStoreReadPaths, looseRelaxationScope } from "../src/security/paths"
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
      if (oldHome === undefined) delete process.env.HOME
      else process.env.HOME = oldHome
      if (oldProfile === undefined) delete process.env.USERPROFILE; else process.env.USERPROFILE = oldProfile
    }
  })
})

describe("Windows temp and credential roots", () => {
  const profile = "C:\\Users\\alice"

  test("configured scratch is accepted; HOME, volume/profile roots and hazardous spellings are not", () => {
    expect(windowsTempRootCandidate("C:\\Temp\\opencode-scratch\\", profile)).toBe("C:\\Temp\\opencode-scratch")
    expect(windowsTempRootCandidate("c:/Temp/opencode-scratch", profile)).toBe("c:\\Temp\\opencode-scratch")
    expect(windowsTempRootRejection("C:\\Temp", profile)).toBeUndefined()
    // An ordinary subdirectory of HOME is a user choice (Linux parity); HOME
    // itself and every ancestor of it are refused.
    expect(windowsTempRootCandidate("C:\\Users\\alice\\scratch", profile)).toBe("C:\\Users\\alice\\scratch")
    for (const bad of [
      "C:\\",
      "C:",
      "C:Temp",
      "C:\\Users",
      "D:\\Users",
      "C:\\Windows",
      profile,
      "c:\\users\\ALICE",
      "\\\\server\\share\\temp",
      "\\\\?\\C:\\Temp",
      "\\\\.\\PhysicalDrive0",
      "C:\\Temp\\a:b",
      "C:\\Temp\\..\\escape",
      "C:\\Temp\\NUL",
      "C:\\Temp\\bad \\sub",
      "relative\\temp",
    ]) {
      expect(windowsTempRootCandidate(bad, profile)).toBeUndefined()
    }
  })

  test("TEMP is validated before it becomes an unconditional grant", () => {
    const base = { USERPROFILE: profile }
    for (const bad of [
      "C:\\",
      "C:",
      "C:Temp",
      "C:\\Users",
      "C:\\Users\\",
      "D:\\Users",
      "C:\\Windows",
      profile,
      "c:\\users\\ALICE",
      "\\\\server\\share\\temp",
      "\\\\?\\C:\\Temp",
      "C:\\Temp\\a:b",
      "C:\\Temp\\..\\escape",
      "C:\\Temp\\NUL",
      "C:\\Temp\\bad \\sub",
      "relative\\temp",
      "",
    ]) {
      expect(alwaysWritableRoots("win32", { ...base, TEMP: bad })).toEqual([])
    }
    // HOME is the fallback when USERPROFILE is not exported.
    expect(alwaysWritableRoots("win32", { HOME: profile, TEMP: profile })).toEqual([])
    // A normal TEMP, including a subdirectory of HOME, is preserved.
    expect(alwaysWritableRoots("win32", { ...base, TEMP: "C:\\Users\\alice\\AppData\\Local\\Temp" }))
      .toEqual(["C:\\Users\\alice\\AppData\\Local\\Temp"])
    expect(alwaysWritableRoots("win32", { ...base, TEMP: "c:/Temp/opencode\\cache\\" }))
      .toEqual(["c:\\Temp\\opencode\\cache"])
  })

  test("a canonicalized TEMP is re-validated, so a redirect cannot land on HOME or a volume root", () => {
    // A junction/symlink TEMP is resolved first and then fed through the same
    // lexical validator; every dangerous canonical target stays rejected.
    for (const resolved of ["C:\\", "C:\\Users", "C:\\Windows", profile]) {
      expect(windowsTempRootCandidate(resolved, profile)).toBeUndefined()
    }
    expect(windowsTempRootCandidate("C:\\Users\\alice\\AppData\\Local\\Temp", profile))
      .toBe("C:\\Users\\alice\\AppData\\Local\\Temp")
  })

  test("Read only Windows roots never grant a dangerous TEMP", async () => {
    const oldTemp = process.env.TEMP
    const oldProfile = process.env.USERPROFILE
    process.env.USERPROFILE = profile
    try {
      for (const bad of [profile, "C:\\", "C:\\Users", "C:\\Windows"]) {
        process.env.TEMP = bad
        expect(await globalTempWriteRoots([], profile, "win32")).toEqual([])
      }
    } finally {
      if (oldTemp === undefined) delete process.env.TEMP
      else process.env.TEMP = oldTemp
      if (oldProfile === undefined) delete process.env.USERPROFILE
      else process.env.USERPROFILE = oldProfile
    }
  })

  test("Windows temp roots keep TEMP and never adopt a dangerous scratch", async () => {
    const oldTemp = process.env.TEMP
    process.env.TEMP = "C:\\Users\\alice\\AppData\\Local\\Temp"
    try {
      const roots = await globalTempWriteRoots(
        [profile, "C:\\", "C:\\Users", "C:\\Windows", "\\\\server\\share", "C:\\Temp\\a:b"],
        profile,
        "win32",
      )
      expect(roots).toEqual(["C:\\Users\\alice\\AppData\\Local\\Temp"])
    } finally {
      if (oldTemp === undefined) delete process.env.TEMP
      else process.env.TEMP = oldTemp
    }
  })

  test("credentialStoreReadPaths spells native Windows AppData stores with Windows separators", () => {
    const paths = credentialStoreReadPaths(profile, "win32")
    expect(paths).toContain("C:\\Users\\alice\\.ssh")
    expect(paths).toContain("C:\\Users\\alice\\.docker\\config.json")
    expect(paths).toContain("C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Credentials")
    expect(paths).toContain("C:\\Users\\alice\\AppData\\Local\\Microsoft\\Vault")
    expect(paths).toContain("C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect")
    expect(paths).toContain("C:\\Users\\alice\\AppData\\Roaming\\GitHub CLI")
    expect(paths).toContain("C:\\Users\\alice\\_netrc")
    // POSIX homes stay POSIX: no invented AppData roots for a Linux user.
    expect(credentialStoreReadPaths("/home/alice", "linux").some((entry) => entry.includes("AppData"))).toBe(false)
    // A Windows spelling on a non-Windows host is not a POSIX absolute path.
    expect(credentialStoreReadPaths(profile, "linux")).toEqual([])
    expect(credentialStoreReadPaths("relative-home", "linux")).toEqual([])
  })

  test("Linux classification is unchanged by the Windows registry entries", () => {
    const oldHome = process.env.HOME
    process.env.HOME = "/home/alice"
    try {
      const sensitive = (target: string) => checkResolvedPathSensitivity(target, "linux").sensitive
      // A Linux directory literally named appdata/... under HOME is not the
      // Windows DPAPI store, and `/windows/...` is not a Windows hive.
      expect(sensitive("/home/alice/appdata/roaming/microsoft/credentials/blob")).toBe(false)
      expect(sensitive("/home/alice/appdata/roaming/microsoft/windows/start menu/programs/startup/run.sh")).toBe(false)
      expect(sensitive("/tmp/windows/system32/config/sam")).toBe(false)
      expect(sensitive("/tmp/ntuser.dat")).toBe(false)
      // The original POSIX stores still classify.
      expect(sensitive("/home/alice/.ssh/id_rsa")).toBe(true)
      expect(sensitive("/tmp/staged/.aws/credentials")).toBe(true)
      // Relative escapes do not pick up the Windows suffix table on Linux.
      if (process.platform === "linux") {
        const ctx = { cwd: workspace, worktree: workspace }
        expect(classifyPathTarget("../../windows/system32/config/sam", "read", ctx).kind).toBe("pass")
        expect(classifyPathTarget("../../ntuser.dat", "read", ctx).kind).toBe("pass")
      }
    } finally {
      if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome
    }
  })

  test("sensitivity covers native Windows credentials, hives and system roots, ignoring case and separator", () => {
    const oldProfile = process.env.USERPROFILE
    process.env.USERPROFILE = profile
    const sensitive = (target: string) => checkResolvedPathSensitivity(target, "win32").sensitive
    try {
      for (const target of [
        "C:\\Users\\alice\\.ssh\\id_rsa",
        "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Credentials\\abc",
        "c:\\users\\alice\\appdata\\local\\microsoft\\vault\\policy.vpol",
        "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21\\master",
        "C:\\Users\\alice\\AppData\\Roaming\\GitHub CLI\\hosts.yml",
        "C:\\Users\\alice\\_netrc",
        "C:\\Users\\alice\\NTUSER.DAT",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM.LOG1",
        "C:\\Windows\\NTDS\\ntds.dit",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys\\key",
        "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\run.bat",
        "D:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Credentials\\abc",
      ]) {
        expect(sensitive(target)).toBe(true)
      }
      for (const target of [
        "C:\\Users\\alice\\AppData\\Local\\Temp\\plain.txt",
        "C:\\Users\\alice\\source\\app.ts",
        "C:\\Users\\alice\\.opencode\\reviewer-trace.jsonl",
      ]) {
        expect(sensitive(target)).toBe(false)
      }
      // Only absolute paths are parseable; a relative spelling never is.
      expect(checkResolvedPathSensitivity("relative\\path", "win32").parseable).toBe(false)
      expect(checkResolvedPathSensitivity("C:\\Users\\alice\\source\\app.ts", "win32").parseable).toBe(true)
      expect(checkResolvedPathSensitivity("/home/alice/.ssh/id_rsa", "linux").sensitive).toBe(true)
    } finally {
      if (oldProfile === undefined) delete process.env.USERPROFILE
      else process.env.USERPROFILE = oldProfile
    }
  })
})

import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import { incidentalWriteRoots, isIncidentalToolWrite } from "../src/security/automatic-write-roots"
import { cleanupTestArtifacts } from "./artifacts"

let root: string
let home: string
beforeAll(async () => {
  root = await mkdtemp("/tmp/opencode/incidental-writes-")
  home = path.join(root, "home")
  await mkdir(home)
})
afterAll(async () => { await cleanupTestArtifacts(root, { recursive: true, force: true }) })

describe("incidental tool cache/history roots", () => {
  test("all named histories are included without exempting adjacent settings", () => {
    const roots = incidentalWriteRoots(home, {})
    for (const name of [".cache", ".sqlite_history", ".lesshst", ".local/state/lesshst", ".python_history",
      ".node_repl_history", ".psql_history", ".mysql_history", ".rediscli_history"]) {
      expect(roots).toContain(path.join(home, name))
    }
    expect(roots).not.toContain(home)
    expect(roots).not.toContain(path.join(home, ".npm/_cacache"))
    expect(roots).not.toContain(path.join(home, ".local/state"))
  })

  test("absolute XDG less history supplements both fallback paths", () => {
    const stateHome = path.join(root, "xdg-state")
    const roots = incidentalWriteRoots(home, { XDG_STATE_HOME: stateHome })
    expect(roots).toContain(path.join(stateHome, "lesshst"))
    expect(roots).toContain(path.join(home, ".local/state/lesshst"))
    expect(roots).toContain(path.join(home, ".lesshst"))
    expect(new Set(roots).size).toBe(roots.length)
    expect(incidentalWriteRoots(home, { XDG_STATE_HOME: "relative" })).toEqual(incidentalWriteRoots(home, {}))
  })

  test("only complete cache path components match, including directory creation", () => {
    for (const target of ["/tree/__pycache__", "/tree/__pycache__/module.pyc.123", "/tree/.pytest_cache/v/cache/state"]) {
      expect(isIncidentalToolWrite(target)).toBe(true)
    }
    for (const target of ["/tree/not__pycache__/state", "/tree/.pytest_cache-old/state", "/tree/__pycache__.pyc"]) {
      expect(isIncidentalToolWrite(target)).toBe(false)
    }
  })

  test("redirected cache directories and dangling histories are not adopted", async () => {
    const redirected = path.join(root, "redirected")
    const outside = path.join(root, "outside")
    await Promise.all([mkdir(redirected), mkdir(outside)])
    await symlink(outside, path.join(redirected, ".cache"))
    await symlink(path.join(root, "missing"), path.join(redirected, ".sqlite_history"))
    const roots = incidentalWriteRoots(redirected, {})
    expect(roots).not.toContain(outside)
    expect(roots).not.toContain(path.join(redirected, ".cache"))
    expect(roots).not.toContain(path.join(redirected, ".sqlite_history"))
    expect(roots).not.toContain(path.join(root, "missing"))
  })

  test("a history symlink grants exactly its regular-file destination", async () => {
    const linkedHome = path.join(root, "linked-home")
    const destination = path.join(root, "history-destination")
    await mkdir(linkedHome)
    await writeFile(destination, "synthetic history")
    await symlink(destination, path.join(linkedHome, ".sqlite_history"))
    const roots = incidentalWriteRoots(linkedHome, {})
    expect(roots).toContain(destination)
    expect(roots).not.toContain(root)
    expect(roots).not.toContain(path.join(linkedHome, ".sqlite_history"))
    await symlink(root, path.join(linkedHome, ".lesshst"))
    expect(incidentalWriteRoots(linkedHome, {})).not.toContain(root)
  })

  test("symlinked missing-file ancestors resolve to the canonical leaf", async () => {
    const state = path.join(root, "real-state")
    const link = path.join(root, "state-link")
    await mkdir(state)
    await symlink(state, link)
    const roots = incidentalWriteRoots(home, { XDG_STATE_HOME: link })
    expect(roots).toContain(path.join(state, "lesshst"))
    expect(roots).not.toContain(path.join(link, "lesshst"))
    expect(incidentalWriteRoots("relative-home", {})).toEqual([])
  })
})

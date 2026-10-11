import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, writeFile, symlink, mkdir } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { collectBoundedEvidence } from "../src/security/automatic"

// Collector hardening for the bounded evidence pass (the only release-blocker
// suite that survived the single-policy rework):
//   * resolved-path sensitive-name guard (a symlink alias to .env-like names
//     is never collected);
//   * byte-bounded descriptor reads — oversized subjects report missing;
//   * subject bound + resolved-path dedupe;
//   * read-time object identity on every piece of script evidence.
//
// No fixture command is executed and no real secret file is ever touched
// (fake .env values only).

let workdir: string | undefined

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "release-blockers-"))
  return workdir
}

afterAll(async () => {
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

describe("bounded evidence collector", () => {
  test("a symlink alias to a sensitive name is never collected", async () => {
    const dir = await ensureWorkdir()
    const fake = path.join(dir, "linked.env")
    await writeFile(fake, "TOKEN=fake-fixture-not-real\n")
    const alias = path.join(dir, "script.py")
    await symlink(fake, alias)

    const { evidence, missing } = await collectBoundedEvidence(
      [{ subject: "script.py" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(0)
    expect(missing).toContain("script.py")
    expect(JSON.stringify(evidence)).not.toContain("fake-fixture")
  })

  test("a direct sensitive name is missing even inside the worktree", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const { evidence, missing } = await collectBoundedEvidence(
      [{ subject: ".env" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(0)
    expect(missing).toContain(".env")
  })

  test("oversized files report missing — a prefix is not treated as evidence", async () => {
    const dir = await ensureWorkdir()
    const big = path.join(dir, "huge.py")
    await writeFile(big, "x".repeat(80 * 1024))
    const { evidence, missing } = await collectBoundedEvidence(
      [{ subject: "huge.py" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(0)
    expect(missing.some((m) => m.includes("huge.py"))).toBe(true)
  })

  test("resolved-path dedupe reads a file once; subject bound is enforced", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, "a.py"), "print('a')\n")
    const subjects = [
      { subject: "a.py" },
      { subject: "./a.py" },
      { subject: "sub/../a.py" },
    ]
    await mkdir(path.join(dir, "sub"))
    const { evidence } = await collectBoundedEvidence(subjects, { cwd: dir, worktree: dir })
    expect(evidence).toHaveLength(1)

    const over = Array.from({ length: 20 }, (_, i) => ({ subject: `missing-${i}.py` }))
    const result = await collectBoundedEvidence(over, { cwd: dir, worktree: dir })
    // Subjects past the bound are named missing, not silently dropped.
    expect(result.missing.length).toBe(20)
    expect(result.missing.some((m) => m.includes("bound"))).toBe(true)
  })

  test("directory listings stream with a real cap — truncation is detected without reading the whole tree", async () => {
    const dir = await ensureWorkdir()
    const big = path.join(dir, "many")
    await mkdir(big)
    for (let i = 0; i < 140; i++) {
      await writeFile(path.join(big, `f${String(i).padStart(3, "0")}.txt`), "x")
    }
    const { evidence } = await collectBoundedEvidence(
      [{ subject: "many" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(1)
    expect(evidence[0].kind).toBe("directory")
    expect(evidence[0].truncated).toBe(true)
    expect(evidence[0].excerpt.split("\n").length).toBe(128)
    // Evidence carries an identity the admission path can re-verify.
    expect(evidence[0].identity?.resolvedPath).toBe(big)
  })

  test("script evidence carries the read-time object identity", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, "a.py"), "print('a')\n")
    const { evidence } = await collectBoundedEvidence(
      [{ subject: "a.py" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(1)
    expect(evidence[0].identity).toBeDefined()
    expect(evidence[0].identity!.ino).toBeGreaterThan(0)
    expect(evidence[0].identity!.resolvedPath).toBe(path.join(dir, "a.py"))
  })

  test("outside-worktree subjects stay missing until the reader boundary widens", async () => {
    const dir = await ensureWorkdir()
    const outside = await mkdtemp(path.join("/tmp/opencode/", "collector-out-"))
    try {
      await writeFile(path.join(outside, "ext.py"), "print('ext')\n")
      const confined = await collectBoundedEvidence(
        [{ subject: path.join(outside, "ext.py") }],
        { cwd: dir, worktree: dir },
      )
      expect(confined.evidence).toHaveLength(0)
      const widened = await collectBoundedEvidence(
        [{ subject: path.join(outside, "ext.py") }],
        { cwd: dir, worktree: dir, allowFullReadAccess: true },
      )
      expect(widened.evidence).toHaveLength(1)
      expect(widened.evidence[0].excerpt).toContain("ext")
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })
})
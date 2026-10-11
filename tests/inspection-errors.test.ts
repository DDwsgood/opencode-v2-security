import { afterAll, describe, expect, test } from "bun:test"
import { execFileSync } from "node:child_process"
import { chmod, mkdtemp, mkdir, rename, symlink, unlink, writeFile } from "node:fs/promises"
import { createServer } from "node:net"
import path from "node:path"
import { currentCacheTargets, targetIdentitiesMatch } from "../src/runtime-boundary"
import { planFileBoundary, planShellBoundary, verifyFileBoundaryPlan } from "../src/tool-boundary"
import { collectBoundedEvidence } from "../src/security/automatic"
import { createApprovalCache } from "../src/security/approval-cache"
import { classifyShellCommand, verifyScriptFingerprints } from "../src/security/classifier"
import { inspectRegularTextFile, inspectRegularTextFileSync } from "../src/security/inspection"
import { foreignGitConfigArmed } from "../src/security/semantic-allow"
import { cleanupTestArtifacts } from "./artifacts"

const root = await mkdtemp("/tmp/opencode/inspection-errors-")
afterAll(() => cleanupTestArtifacts(root, { recursive: true, force: true }))
const classify = (script: string) => classifyShellCommand({ script, cwd: root, worktree: root, shell: "/bin/bash", strictness: "LOOSE" })

describe("inspection failures are unavailable evidence, not decisions", () => {
  test("EACCES on trace-marker-shaped paths is reviewable and is not cached as absence", async () => {
    const directory = path.join(root, "debug-tracing")
    const target = path.join(directory, "trace_marker")
    await mkdir(directory)
    await writeFile(target, "fixture")
    await chmod(directory, 0)
    try {
      const read = await inspectRegularTextFile(target, 1024)
      expect(read).toEqual({ ok: false, reason: "EACCES" })
      const targets = await currentCacheTargets([{ path: target, domain: "linux", exists: false }])
      expect(targets[0].inspectionError).toContain("EACCES")
      const plan = await planFileBoundary("read", { path: target }, { cwd: root, writableRoots: [root] })
      expect(plan.verdict).toBe("ASK")
      expect(plan.facts.join("\n")).toContain("EACCES")
      await verifyFileBoundaryPlan(plan)
      const shell = await planShellBoundary(`printf fixture > '${target}'`, { cwd: root, shell: "/bin/bash", writableRoots: [] })
      expect(shell.writeRoots).toEqual([])
      expect(shell.facts.join("\n")).toContain("EACCES")
      const cache = createApprovalCache()
      const scope = { sessionID: "inspection", securitySnapshot: "auto", userAuthorizationDigest: "fixture" }
      const facts = { exactDigest: "same", kind: "write" as const, operation: "create", targets, requiresFullApproval: false, effect: "replace" as const }
      cache.store(scope, facts, { decision: "allow", floor: "no", source: "bounded" } as never)
      expect(cache.lookup(scope, facts)).toBeUndefined()
      expect(targetIdentitiesMatch(targets, targets)).toBe(true)
      expect(targetIdentitiesMatch([{ ...targets[0], dev: "1" }], [{ ...targets[0], dev: "2" }])).toBe(false)
    } finally {
      await chmod(directory, 0o700)
    }
    const pseudo = await collectBoundedEvidence([{ subject: "/sys/kernel/debug/tracing/trace_marker" }], { cwd: root, worktree: root, allowFullReadAccess: true })
    expect(pseudo.evidence).toEqual([])
    expect(pseudo.missing[0]).toContain("pseudo-file")
  })

  test("unreadable scripts go through the uninspected-script route", async () => {
    const script = path.join(root, "unreadable.sh")
    await writeFile(script, "echo fixture\n", { mode: 0 })
    try {
      const decision = await classify("bash unreadable.sh")
      expect(decision.verdict).toBe("ASK")
      expect(decision.reviewContext?.uninspectedLocalScripts).toContain("unreadable.sh")
      expect(decision.fingerprints).toEqual([])
    } finally {
      await chmod(script, 0o600)
    }
  })

  test("FIFOs and sockets are never opened for text inspection or fingerprint rechecks", async () => {
    const fifo = path.join(root, "fifo.sh")
    execFileSync("mkfifo", [fifo])
    expect(await inspectRegularTextFile(fifo, 1024)).toEqual({ ok: false, reason: "not a regular file" })
    expect(inspectRegularTextFileSync(fifo, 1024)).toEqual({ ok: false, reason: "not a regular file" })
    const collected = await collectBoundedEvidence([{ subject: fifo }], { cwd: root, worktree: root })
    expect(collected.evidence).toEqual([])
    expect(collected.missing[0]).toContain("not a regular file")
    const decision = await classify("bash fifo.sh")
    expect(decision.reviewContext?.uninspectedLocalScripts).toContain("fifo.sh")
    expect(await verifyScriptFingerprints([{ path: fifo, size: 0, mtimeMs: 0, sha256: "fixture" }])).toBe(false)
    const socketPath = path.join(root, "socket")
    const server = createServer()
    await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve) })
    try {
      expect(await inspectRegularTextFile(socketPath, 1024)).toEqual({ ok: false, reason: "not a regular file" })
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()))
    }
  })

  test("broken links, removed objects, invalid traversal and symlink loops stay bounded", async () => {
    const broken = path.join(root, "broken.sh")
    await symlink(path.join(root, "absent.sh"), broken)
    const removed = path.join(root, "removed.sh")
    await writeFile(removed, "echo fixture\n")
    const fingerprint = (await classify("bash removed.sh")).fingerprints
    await unlink(removed)
    expect(await verifyScriptFingerprints(fingerprint)).toBe(false)
    const loop = path.join(root, "loop.sh")
    await symlink("loop.sh", loop)
    await writeFile(path.join(root, "ordinary-file"), "fixture")
    const subjects = [broken, removed, loop, path.join(root, "ordinary-file", "child"), path.join(root, "x".repeat(300))]
    const result = await collectBoundedEvidence(subjects.map((subject) => ({ subject })), { cwd: root, worktree: root })
    expect(result.evidence).toEqual([])
    expect(result.missing).toHaveLength(subjects.length)
    expect(result.missing.join("\n")).toMatch(/ENOENT/)
    expect(result.missing.join("\n")).toMatch(/ELOOP/)
    expect(result.missing.join("\n")).toMatch(/ENOTDIR/)
    expect(result.missing.join("\n")).toMatch(/ENAMETOOLONG/)
    const plan = await planFileBoundary("write", { path: loop }, { cwd: root, writableRoots: [root] })
    expect(plan.verdict).toBe("ASK")
    expect(plan.facts.join("\n")).toContain("ELOOP")
    // A separately identified sensitive effect cannot disappear with the gap.
    const credential = await planFileBoundary("grep", { path: loop, pattern: "fixture", include: ".env" }, { cwd: root, writableRoots: [root] })
    expect(credential.facts.join("\n")).toContain("credentials.sensitive-access")
  })

  test("binary, non-UTF8, oversized and directory content is not used as script proof", async () => {
    const binary = path.join(root, "binary.sh")
    const invalid = path.join(root, "invalid.sh")
    const huge = path.join(root, "huge.sh")
    await writeFile(binary, Buffer.from([0, 1]))
    await writeFile(invalid, Buffer.from([0xff, 0xfe]))
    await writeFile(huge, "x".repeat(300_000))
    for (const target of [binary, invalid, huge, root]) {
      expect((await inspectRegularTextFile(target, 1024)).ok).toBe(false)
    }
    expect((await classify("bash invalid.sh")).verdict).toBe("ASK")
    const script = path.join(root, "replaced.sh")
    await writeFile(script, "echo fixture\n")
    const fingerprints = (await classify("bash replaced.sh")).fingerprints
    await rename(script, `${script}.old`)
    execFileSync("mkfifo", [script])
    expect(await verifyScriptFingerprints(fingerprints)).toBe(false)
  })

  test("a foreign Git config FIFO is not read and cannot earn a safe proof", async () => {
    const repository = path.join(root, "foreign")
    await mkdir(path.join(repository, ".git"), { recursive: true })
    execFileSync("mkfifo", [path.join(repository, ".git", "config")])
    expect(foreignGitConfigArmed(repository)).toBe(true)
  })
})

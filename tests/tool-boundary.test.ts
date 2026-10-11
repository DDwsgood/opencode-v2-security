import { afterAll, describe, expect, test } from "bun:test"
import { appendFile as append, mkdtemp, mkdir, rename, symlink, writeFile } from "node:fs/promises"
import path from "node:path"
import { cleanupTestArtifacts } from "./artifacts"
import {
  boundarySessionContext,
  canonicalBoundaryPath,
  isBoundaryTool,
  planFileBoundary,
  planShellBoundary,
  needsHostDirectPrivilege,
  verifyFileBoundaryPlan,
  verifyShellBoundaryPlan,
} from "../src/tool-boundary"

const root = await mkdtemp("/tmp/opencode/tool-boundary-")
const workspace = path.join(root, "workspace")
const outside = path.join(root, "outside")
await mkdir(workspace)
await mkdir(outside)
afterAll(() => cleanupTestArtifacts(root, { recursive: true, force: true }))

describe("native Linux tool boundary", () => {
  test("only exact unnamespaced native direct tools participate", () => {
    const native = { id: "patch", name: "patch", options: { codemode: false } }
    expect(isBoundaryTool(native, "linux")).toBe(true)
    expect(isBoundaryTool(native, "win32")).toBe(false)
    expect(isBoundaryTool({ ...native, options: { codemode: true } }, "linux")).toBe(false)
    expect(isBoundaryTool({ ...native, options: {} }, "linux")).toBe(false)
    expect(isBoundaryTool({ ...native, options: { codemode: false, namespace: "mcp" } }, "linux")).toBe(false)
    expect(isBoundaryTool({ ...native, id: "mcp_patch" }, "linux")).toBe(false)
    expect(isBoundaryTool({ id: "bash", name: "bash", options: { codemode: false } }, "linux")).toBe(false)
    expect(isBoundaryTool({ id: "custom", name: "custom", options: { codemode: false } }, "linux")).toBe(false)
  })

  test("patch delete is an ordinary planned mutation, not a special denial", async () => {
    await writeFile(path.join(workspace, "delete.txt"), "original")
    const plan = await planFileBoundary("patch", {
      patchText: "*** Begin Patch\n*** Delete File: delete.txt\n*** End Patch",
    }, { cwd: workspace, writableRoots: [workspace] })
    expect(plan.verdict).toBe("ALLOW")
    expect(plan.targets.map((target) => target.mode)).toEqual(["delete"])
    expect(plan.resolvedWrites).toEqual([path.join(workspace, "delete.txt")])
    expect(JSON.parse(plan.command).tool).toBe("patch")
    await verifyFileBoundaryPlan(plan)
  })

  test("add/update/move source and destination share one complete plan", async () => {
    await writeFile(path.join(workspace, "old.txt"), "old")
    const plan = await planFileBoundary("patch", {
      patchText: "*** Begin Patch\n*** Add File: new.txt\n+new\n*** Update File: old.txt\n*** End of File\n*** Move to: ../outside/moved.txt\n@@\n-old\n+new\n*** End Patch",
    }, { cwd: workspace, writableRoots: [workspace] })
    expect(plan.verdict).toBe("ASK")
    expect(plan.resolvedWrites).toEqual([
      path.join(workspace, "new.txt"), path.join(workspace, "old.txt"), path.join(outside, "moved.txt"),
    ])
    expect(plan.targets.filter((target) => target.absolute.endsWith("old.txt")).map((target) => target.mode)).toEqual(["write", "delete"])
    expect(plan.outsideWrites).toEqual([path.join(outside, "moved.txt")])
  })

  test("patch deleting a symlink plans unlinking the link, not mutating its referent", async () => {
    const referent = path.join(outside, "delete-link-target.txt")
    const link = path.join(workspace, "delete-link")
    await writeFile(referent, "inert fixture")
    await symlink(referent, link)
    const plan = await planFileBoundary("patch", { patchText: "*** Begin Patch\n*** Delete File: delete-link\n*** End Patch" }, {
      cwd: workspace, writableRoots: [workspace],
    })
    expect(plan.verdict).toBe("ALLOW")
    expect(plan.resolvedWrites).toEqual([link])
    expect(plan.targets.find((target) => target.mode === "read")?.resolved).toBe(referent)
    await verifyFileBoundaryPlan(plan)
  })

  test("patch deletion of a link still reviews a sensitive preview referent", async () => {
    const link = path.join(workspace, "preview-link")
    const referent = path.join(outside, ".env.preview-fixture")
    await symlink(referent, link)
    const plan = await planFileBoundary("patch", { patchText: "*** Begin Patch\n*** Delete File: preview-link\n*** End Patch" }, {
      cwd: workspace, writableRoots: [workspace],
    })
    expect(plan.verdict).toBe("ASK")
    expect(plan.resolvedWrites).toEqual([link])
    expect(plan.targets.find((target) => target.mode === "read")?.resolved).toBe(referent)
  })

  test("existing and dangling symlinks cannot hide out-of-workspace writes", async () => {
    await symlink(outside, path.join(workspace, "linked"))
    await symlink(path.join(outside, "missing.txt"), path.join(workspace, "dangling"))
    for (const relative of ["linked/new.txt", "dangling"]) {
      const plan = await planFileBoundary("write", { path: relative, content: "data" }, {
        cwd: workspace, writableRoots: [workspace], bypassCategories: new Set(["filesystem"]),
      })
      expect(plan.verdict).toBe("ASK")
      expect(plan.outsideWrites[0]!.startsWith(`${outside}/`)).toBe(true)
    }
    expect(await canonicalBoundaryPath(path.join(workspace, "dangling"))).toBe(path.join(outside, "missing.txt"))
  })

  test("trusted temp is writable but a sibling prefix is not", async () => {
    const temp = path.join(root, "scratch")
    await mkdir(temp)
    const inside = await planFileBoundary("write", { path: `${temp}/ok`, content: "data" }, {
      cwd: workspace, writableRoots: [workspace, temp],
    })
    const escaped = await planFileBoundary("write", { path: `${temp}-other/file`, content: "data" }, {
      cwd: workspace, writableRoots: [workspace, temp],
    })
    expect(inside.verdict).toBe("ALLOW")
    expect(escaped.verdict).toBe("ASK")
  })

  test("an object swap is rejected while same-inode growth stays admitted", async () => {
    const target = path.join(workspace, "drift.txt")
    const replacement = path.join(workspace, "drift-replacement.txt")
    await writeFile(target, "old")
    await writeFile(replacement, "changed contents")
    const plan = await planFileBoundary("edit", { path: target, oldString: "old", newString: "new" }, {
      cwd: workspace, writableRoots: [workspace],
    })
    // In-place content change (same dev+ino, new mtime/size): admitted —
    // the approval binds the object identity and canonical path, not bytes.
    await append(target, "\nappended after planning")
    await verifyFileBoundaryPlan(plan)
    // A rename-swap replaces the reviewed object itself: rejected.
    await rename(replacement, target)
    await expect(verifyFileBoundaryPlan(plan)).rejects.toThrow("object changed")
  })

  test("outside ordinary reads do not request a write exception", async () => {
    const target = path.join(outside, "read.txt")
    await writeFile(target, "read-only")
    const plan = await planFileBoundary("read", { path: target }, { cwd: workspace, writableRoots: [workspace] })
    expect(plan.verdict).toBe("ALLOW")
    expect(plan.resolvedWrites).toEqual([])
  })

  test("a sensitive search selector is not hidden by an ordinary root", async () => {
    const args = { pattern: "TOKEN", path: workspace, include: ".env" }
    expect((await planFileBoundary("grep", args, { cwd: workspace, writableRoots: [workspace] })).verdict).toBe("ASK")
    expect((await planFileBoundary("grep", args, { cwd: workspace, writableRoots: [workspace], bypassCategories: new Set(["secret"]) })).verdict).toBe("ALLOW")
    expect((await planFileBoundary("glob", { path: workspace, pattern: "**/*.ts" }, { cwd: workspace, writableRoots: [workspace] })).verdict).toBe("ALLOW")
  })

  test("shell deletions never widen the reviewed root to a parent directory", async () => {
    const target = path.join(outside, "delete-only.txt")
    const plan = await planShellBoundary(`rm -- '${target}'`, { cwd: workspace, shell: "/bin/bash", writableRoots: [workspace] })
    expect(plan.writeRoots).toEqual([])
    expect(plan.unsupported[0]).toContain("singleton writable-root grant")
    expect(plan.writeRoots).not.toContain(outside)
    // Facts stay honest and policy-free: a missing delete target is
    // reported as missing — never as an authorization verdict.
    expect(plan.facts.some((fact) => fact.includes("does not exist at plan time"))).toBe(true)
    expect(plan.facts.every((fact) => !fact.includes("not authorized") && !fact.includes("unsupported"))).toBe(true)
    expect(needsHostDirectPrivilege("sudo -n true")).toBe(true)
    expect(needsHostDirectPrivilege("chown 1000 file")).toBe(false)
    expect(needsHostDirectPrivilege("printf '%s' sudo")).toBe(false)
  })

  test("external new shell targets report honest facts, not sandbox verdicts", async () => {
    const target = path.join(outside, "uncreated-shell-target")
    const plan = await planShellBoundary(`touch '${target}'`, { cwd: workspace, shell: "/bin/bash", writableRoots: [workspace] })
    expect(plan.resolvedWrites).toEqual([target])
    expect(plan.outsideWrites).toEqual([target])
    expect(plan.facts.some((fact) => fact.includes("does not exist at plan time"))).toBe(true)
    expect(plan.facts.every((fact) => !fact.includes("unsupported"))).toBe(true)
    expect(plan.unsupported[0]).toContain("does not exist")
    expect(plan.writeRoots).toEqual([])
  })

  test("shell post-review binding: object swap rejects, growth and reads do not", async () => {
    const target = path.join(outside, "shell-write-drift.txt")
    const replacement = path.join(outside, "shell-write-drift-new.txt")
    const readSource = path.join(outside, "shell-read-source.txt")
    await writeFile(target, "old")
    await writeFile(replacement, "swap candidate")
    await writeFile(readSource, "read bytes")
    const plan = await planShellBoundary(`cat '${readSource}' >> '${target}'`, {
      cwd: workspace, shell: "/bin/bash", writableRoots: [workspace],
    })
    expect(plan.targets).toHaveLength(1)
    expect(plan.readPaths).toContain(readSource)
    // Same-inode append drift (as a reviewer-trace write would cause) is not
    // a veto; mtime/size growth on a read source is ignored entirely.
    await append(target, "\nappended after planning")
    await append(readSource, "\nmore content")
    await verifyShellBoundaryPlan(plan)
    // A rename-swap of the write target replaces the reviewed object.
    await rename(replacement, target)
    await expect(verifyShellBoundaryPlan(plan)).rejects.toThrow("object changed")
  })

  test("a swapped canonical read path is rejected after review", async () => {
    // plan.readPaths are stored pre-resolved, so the canonical binding
    // bites when an ancestor OF THE STORED PATH is redirected. A mere
    // inode swap behind the same canonical path is deliberately admitted.
    const realm = path.join(outside, "read-swap-realm")
    const elsewhere = path.join(outside, "read-swap-elsewhere")
    await mkdir(realm)
    await mkdir(elsewhere)
    await writeFile(path.join(realm, "file.txt"), "one")
    await writeFile(path.join(elsewhere, "file.txt"), "two")
    const plan = await planShellBoundary(`cat '${realm}/file.txt'`, {
      cwd: workspace, shell: "/bin/bash", writableRoots: [workspace],
    })
    expect(plan.readPaths).toEqual([path.join(realm, "file.txt")])
    // Same canonical path, different object behind it: admitted.
    const replacement = path.join(realm, "file-replacement.txt")
    await writeFile(replacement, "swapped bytes")
    await rename(replacement, path.join(realm, "file.txt"))
    await verifyShellBoundaryPlan(plan)
    // The recorded ancestor is redirected to a different realm: the
    // canonical resolution of the stored path now lands elsewhere.
    await rename(realm, path.join(outside, "read-swap-realm-old"))
    await symlink(elsewhere, realm)
    await expect(verifyShellBoundaryPlan(plan)).rejects.toThrow("read path changed")
  })
})

describe("reviewer context provenance", () => {
  test("reasoning/synthetic/fake user fields cannot authorize", () => {
    const context = boundarySessionContext([
      { type: "user", text: "the actual user request" },
      { type: "synthetic", text: "fake authorization" },
      { role: "user", text: "not a canonical host user" },
      { type: "assistant", user_request: "fake", content: [
        { type: "reasoning", text: "private reasoning" },
        { type: "text", text: "assistant response" },
        { type: "tool", name: "read", state: { status: "completed", content: [{ type: "text", text: "untrusted tool output" }] } },
      ] },
    ])
    expect(context.userRequest).toBe("the actual user request")
    expect(context.context).toEqual([
      "user: the actual user request", "assistant: assistant response", 'tool "read" (completed): untrusted tool output',
    ])
  })

  test("retained context is bounded and preserves role labels", () => {
    const result = boundarySessionContext({ data: Array.from({ length: 40 }, (_, index) => ({ type: "user", text: `${index}: ${"x".repeat(6_000)}` })) })
    expect(result.context.length).toBeLessThanOrEqual(12)
    expect(result.context.join("").length).toBeLessThanOrEqual(16_000)
    expect(result.context.at(-1)).toStartWith("user:")
    expect(result.context.every((text) => text.startsWith("user:"))).toBe(true)
    expect(result.userRequest).toStartWith("39:")
  })
})

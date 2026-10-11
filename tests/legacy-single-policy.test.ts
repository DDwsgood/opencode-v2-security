import { afterAll, describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import path from "node:path"
import { cleanupTestArtifacts as rm } from "./artifacts"
import {
  parseReviewResult,
  requestForPolicy,
  ReviewError,
  reviewCommandWithAuditor,
  reviewerEnvironment,
  type CloudReviewRequest,
} from "../src/security/reviewer"

// The legacy reviewer supports exactly ONE policy, "LOOSE". The strict "HARD"
// policy was removed: it is not selectable, not defaulted, and an explicit
// "HARD" input is rejected rather than silently converted. These tests cover
// policy selection, the minimal LOOSE parse, and the protocol/abort contract.

const minimalRequest: CloudReviewRequest = {
  command: "printf hello",
  localScripts: [],
  uninspectedLocalScripts: [],
  targetDirectories: [],
  uninspectedTargetDirectories: [],
  referencedPaths: [],
  referencedPathsTruncated: false,
  worktree: "/tmp/opencode",
  cwd: "/tmp/opencode",
}

let workdir: string | undefined

async function ensureWorkdir(): Promise<string> {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "legacy-single-policy-"))
  return workdir
}

afterAll(async () => {
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

async function stubScript(name: string, body: string): Promise<string> {
  const dir = await ensureWorkdir()
  const file = path.join(dir, name)
  await writeFile(file, body)
  return file
}

describe("single review policy", () => {
  test("parseReviewResult rejects HARD explicitly", () => {
    expect(() => parseReviewResult('{"decision":"ALLOW"}', "HARD" as never)).toThrow(
      /HARD.*removed/,
    )
  })

  test("requestForPolicy rejects HARD explicitly", () => {
    expect(() => requestForPolicy(minimalRequest, "HARD" as never)).toThrow(/HARD.*removed/)
  })

  test("an unknown policy string is rejected, not coerced", () => {
    expect(() => parseReviewResult('{"decision":"ALLOW"}', "STRICT" as never)).toThrow(
      /only "LOOSE"/,
    )
  })

  test("reviewCommandWithAuditor rejects HARD before any reviewer is spawned", async () => {
    await expect(
      reviewCommandWithAuditor("printf hello", {
        jev: { endpoint: "https://unused.invalid/systemone", model: "jev-latest", apiKey: "fixture-only" },
        policy: "HARD" as never,
        maxRounds: 1,
      }),
    ).rejects.toThrow(/HARD.*removed/)
  })

  test("LOOSE is the only policy rendered into the child environment", () => {
    const env = reviewerEnvironment({
      maxRounds: 1,
      policy: "LOOSE",
      jev: { endpoint: "http://o/v1", model: "m", apiKey: "k" },
    })
    expect(env.OPENCODE_V2_SECURITY_REVIEW_POLICY).toBe("LOOSE")
    expect(env.JEV_ENDPOINT).toBe("http://o/v1")
  })
})

describe("LOOSE minimal parse", () => {
  test("a minimal ALLOW needs no bypassing field", () => {
    const result = parseReviewResult('{"decision":"ALLOW"}', "LOOSE")
    expect(result.decision).toBe("ALLOW")
    expect(result.categories).toEqual([])
    expect(result.bypassing).toBeUndefined()
  })

  test("a legacy bypassing field is tolerated but never carried through", () => {
    const result = parseReviewResult(
      '{"decision":"DENY","categories":["host"],"bypassing":true}',
      "LOOSE",
    )
    expect(result.decision).toBe("DENY")
    expect(result.categories).toEqual(["host"])
    expect(result.bypassing).toBeUndefined()
  })

  test("a DENY with no category still falls back to indirection", () => {
    const result = parseReviewResult('{"decision":"DENY","categories":[]}', "LOOSE")
    expect(result.categories).toEqual(["indirection"])
  })

  test("LOOSE collects a script verdict that requires no bypassing boolean", () => {
    const result = parseReviewResult('{"decision":"collect_evidence"}', "LOOSE")
    expect(result.decision).toBe("collect_evidence")
    expect(result.bypassing).toBeUndefined()
  })
})

describe("protocol and abort non-interruption contract", () => {
  const jev = { endpoint: "https://unused.invalid/systemone", model: "jev-latest", apiKey: "fixture-only" }

  test("malformed reviewer stdout is a protocol failure, not a verdict", async () => {
    const jevPath = await stubScript(
      "bad-json.py",
      "import sys\nsys.stdin.buffer.read()\nsys.stdout.write('not json')\nsys.stdout.flush()\n",
    )
    await expect(
      reviewCommandWithAuditor("printf hello", { jev, policy: "LOOSE", maxRounds: 1, jevPath, python: "python3" }),
    ).rejects.toMatchObject({ kind: "protocol" })
  })

  test("exit 4 is an infrastructure failure; an unrecognized exit stays protocol", async () => {
    const httpErr = await stubScript("exit4.py", "import sys\nsys.stdin.buffer.read()\nsys.exit(4)\n")
    await expect(
      reviewCommandWithAuditor("printf hello", { jev, policy: "LOOSE", maxRounds: 1, jevPath: httpErr, python: "python3" }),
    ).rejects.toMatchObject({ kind: "infra", exitCode: 4 })

    const otherErr = await stubScript("exit7.py", "import sys\nsys.stdin.buffer.read()\nsys.exit(7)\n")
    await expect(
      reviewCommandWithAuditor("printf hello", { jev, policy: "LOOSE", maxRounds: 1, jevPath: otherErr, python: "python3" }),
    ).rejects.toMatchObject({ kind: "protocol", exitCode: 7 })
  })

  test("an abort rejects as infra promptly and never hangs", async () => {
    const jevPath = await stubScript(
      "slow.py",
      "import sys, time\nsys.stdin.buffer.read()\ntime.sleep(30)\n",
    )
    const controller = new AbortController()
    const started = Date.now()
    const promise = reviewCommandWithAuditor("printf hello", {
      jev,
      policy: "LOOSE",
      maxRounds: 1,
      jevPath,
      python: "python3",
      timeout: 20000,
      signal: controller.signal,
    })
    setTimeout(() => controller.abort(), 100)
    await expect(promise).rejects.toBeInstanceOf(ReviewError)
    await expect(promise).rejects.toMatchObject({ kind: "infra" })
    await expect(promise).rejects.toThrow(/aborted/)
    expect(Date.now() - started).toBeLessThan(10000)
  })
})

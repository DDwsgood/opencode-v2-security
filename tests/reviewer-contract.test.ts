import { afterAll, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp, writeFile } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { isValidReviewResult, rulesHintCategories } from "../src/index"
import { parseReviewResult, ReviewError, reviewCommandWithAuditor } from "../src/security/reviewer"

// --- 1.1.0 reviewer contract: {decision, categories, secondary_categories?}
// plus JEV-only engine behavior and the risk-category hint plumbing.

let workdir: string | undefined
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "reviewer-contract-"))
  return workdir
}

afterAll(async () => {
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

/** A port that is guaranteed closed: bind, read the port, close. */
async function deadEndpoint(): Promise<string> {
  const server = createServer()
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const port = (server.address() as AddressInfo).port
  await new Promise<void>((resolve) => server.close(() => resolve()))
  return `http://127.0.0.1:${port}/v1`
}

// --- hint categories -------------------------------------------------------

describe("rulesHintCategories", () => {
  test("unions the required categories across rules and skips floor/unmapped rules", () => {
    const categories = rulesHintCategories([
      "filesystem.dangerous-write", // -> filesystem
      "credentials.aws-env", // -> secret
      "exfiltration.credential-upload", // -> secret + network (conjunctive)
      "network.reverse-shell", // floor: contributes nothing
      "input.empty", // unbypassable: nothing
      "no.such.rule", // unmapped: nothing
    ])
    expect([...categories].sort()).toEqual(["filesystem", "network", "secret"])
  })

  test("a purely floor/unmapped rule set yields no hint", () => {
    expect(rulesHintCategories(["filesystem.root-delete", "network.reverse-shell"])).toEqual([])
    expect(rulesHintCategories([])).toEqual([])
  })
})

// --- reviewer output contract (host-side validator) -------------------------

describe("isValidReviewResult", () => {
  test("accepts the 1.1.0 contract without a reason field", () => {
    const allow = { decision: "ALLOW", categories: [] }
    expect(isValidReviewResult(allow, false)).toBe(true)

    const deny = { decision: "DENY", categories: ["secret", "network"] }
    expect(isValidReviewResult(deny, false)).toBe(true)
    expect(deny.categories).toEqual(["secret", "network"])
  })

  test("a DENY with no usable category falls back to indirection", () => {
    for (const value of [
      { decision: "DENY" },
      { decision: "DENY", categories: [] },
      { decision: "DENY", categories: ["bogus", "not-a-category"] },
    ]) {
      expect(isValidReviewResult(value, false)).toBe(true)
      expect((value as { categories: string[] }).categories).toEqual(["indirection"])
    }
  })

  test("unknown category names are stripped, not fatal", () => {
    const value = { decision: "DENY", categories: ["bogus", "host", "host"] }
    expect(isValidReviewResult(value, false)).toBe(true)
    expect(value.categories).toEqual(["host"])
  })

  test("secondary_categories are sanitized and primaries win", () => {
    const value = {
      decision: "DENY",
      categories: ["secret"],
      secondary_categories: ["network", "secret", "bogus"],
    }
    expect(isValidReviewResult(value, false)).toBe(true)
    expect(value.secondary_categories).toEqual(["network"])
  })

  test("rejects malformed shapes", () => {
    for (const value of [
      undefined,
      null,
      "DENY",
      [],
      { decision: "MAYBE" },
      { decision: "ALLOW", verdict: "allow" }, // unknown key
      { decision: "ALLOW", categories: "secret" },
      { decision: "DENY", categories: ["secret"], reason: 42 },
    ]) {
      expect(isValidReviewResult(value, false)).toBe(false)
    }
  })

  test("a legacy reason string is still tolerated (and trimmed)", () => {
    const value = { decision: "DENY", categories: ["host"], reason: "  too   risky  " }
    expect(isValidReviewResult(value, false)).toBe(true)
    expect(value.reason).toBe("too risky")
  })
})

describe("parseReviewResult (auditor stdout)", () => {
  test("parses the categories contract and applies the same fallbacks", () => {
    const deny = parseReviewResult('{"decision":"DENY","categories":["network"]}', "LOOSE")
    expect(deny.decision).toBe("DENY")
    expect(deny.categories).toEqual(["network"])

    const fallback = parseReviewResult('{"decision":"DENY","categories":[]}', "LOOSE")
    expect(fallback.categories).toEqual(["indirection"])

    const allow = parseReviewResult('{"decision":"ALLOW"}', "LOOSE")
    expect(allow.categories).toEqual([])
  })

  test("rejects unknown fields and invalid decisions", () => {
    expect(() => parseReviewResult('{"decision":"ALLOW","extra":1}', "LOOSE")).toThrow()
    expect(() => parseReviewResult('{"decision":"MAYBE"}', "LOOSE")).toThrow()
    expect(() => parseReviewResult("not json", "LOOSE")).toThrow()
  })
})

// --- JEV-only review chain ---------------------------------------------------

describe("review engine selection", () => {
  async function stubJev(name: string, output: string): Promise<string> {
    const dir = await ensureWorkdir()
    const file = path.join(dir, name)
    await writeFile(file, `import sys\nsys.stdin.buffer.read()\nsys.stdout.write(${JSON.stringify(JSON.stringify(output))})\nsys.stdout.flush()\n`)
    return file
  }

  const review = (options: Record<string, unknown>) =>
    reviewCommandWithAuditor("echo hello", {
      endpoint: "http://127.0.0.1:1/v1",
      model: "test-model",
      apiKey: "test-key",
      maxRounds: 1,
      policy: "LOOSE",
      timeout: 20000,
      ...options,
    })

  test("a jev infrastructure failure rejects instead of falling back", async () => {
    // There is no OpenAI fallback anymore: an unreachable jev endpoint is a
    // hard ReviewError, never a retry through another engine.
    await expect(
      review({
        reviewer: "jev",
        jev: { endpoint: await deadEndpoint(), model: "jev-1.13", apiKey: "jev-key" },
      }),
    ).rejects.toBeInstanceOf(ReviewError)
  })

  test("a jev protocol failure rejects without any fallback", async () => {
    // The jev engine ran to completion but produced an invalid verdict: that
    // is a protocol failure (fail-close), never a reason to retry elsewhere.
    const jevPath = await stubJev("bad-jev.py", { decision: "MAYBE", categories: [] })
    await expect(
      review({
        reviewer: "auto",
        jev: { endpoint: await deadEndpoint(), model: "jev-1.13", apiKey: "jev-key" },
        jevPath,
      }),
    ).rejects.toBeInstanceOf(ReviewError)
  })

  test("a review without a usable jev config is a hard error", async () => {
    await expect(review({ reviewer: "jev" })).rejects.toThrow("Jev reviewer is not configured")
  })
})
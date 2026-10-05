import { afterAll, beforeEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp, writeFile } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { isValidReviewResult, rulesHintCategories } from "../src/index"
import {
  parseReviewResult,
  ReviewError,
  reviewCommandWithAuditor,
  reviewerEnvironment,
} from "../src/security/reviewer"
import { findSimilarFailedEscalation } from "../src/security/escalation-state"
import { resetEscalationReviewLimiter, reviewEscalation } from "../src/security/escalation-reviewer"

// --- 1.1.0 reviewer contract: {decision, categories, secondary_categories?}
// plus the Jev engine selection, the risk-category hint plumbing, the
// previousDenial wire field, and the widened-category retry exemption.

let workdir: string | undefined
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "reviewer-contract-"))
  return workdir
}

beforeEach(() => {
  resetEscalationReviewLimiter()
})

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
    // bypassing is only type-checked under the strict policy.
    expect(isValidReviewResult({ decision: "DENY", categories: ["secret"], bypassing: "yes" }, true)).toBe(false)
  })

  test("strict policy requires a boolean bypassing", () => {
    expect(isValidReviewResult({ decision: "DENY", categories: ["host"] }, true)).toBe(false)
    const value = { decision: "DENY", categories: ["host"], bypassing: false }
    expect(isValidReviewResult(value, true)).toBe(true)
    expect(value.bypassing).toBe(false)
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

  test("HARD requires a boolean bypassing", () => {
    expect(() => parseReviewResult('{"decision":"ALLOW","categories":[]}', "HARD")).toThrow()
    const result = parseReviewResult('{"decision":"DENY","categories":["host"],"bypassing":true}', "HARD")
    expect(result.bypassing).toBe(true)
  })
})

// --- engine selection --------------------------------------------------------

describe("reviewerEnvironment engine routing", () => {
  const base = { endpoint: "http://o/v1", model: "oa-model", apiKey: "oa-key", maxRounds: 1, policy: "LOOSE" as const }

  test("engine jev exports JEV_* only", () => {
    const env = reviewerEnvironment({
      ...base,
      engine: "jev",
      jev: { endpoint: "http://jev/systemone", model: "jev-1.13", apiKey: "jev-key" },
    })
    expect(env.JEV_ENDPOINT).toBe("http://jev/systemone")
    expect(env.JEV_MODEL).toBe("jev-1.13")
    expect(env.JEV_API_KEY).toBe("jev-key")
    expect(env.OPENCODE_V2_SECURITY_REVIEW_ENDPOINT).toBeUndefined()
    expect(env.OPENCODE_V2_SECURITY_REVIEW_API_KEY).toBeUndefined()
    // Shared fields still apply to both engines.
    expect(env.OPENCODE_V2_SECURITY_REVIEW_POLICY).toBe("LOOSE")
  })

  test("engine openai exports OPENCODE_* only", () => {
    const env = reviewerEnvironment({ ...base, engine: "openai" })
    expect(env.OPENCODE_V2_SECURITY_REVIEW_ENDPOINT).toBe("http://o/v1")
    expect(env.OPENCODE_V2_SECURITY_REVIEW_MODEL).toBe("oa-model")
    expect(env.JEV_API_KEY).toBeUndefined()
  })
})

describe("review engine selection", () => {
  async function stubAuditor(name: string, output: string): Promise<string> {
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

  test("reviewer:auto falls back to the OpenAI auditor on a jev infra failure", async () => {
    // The real bundled jev-reviewer.py against a dead port exits 5 (network)
    // — an infra failure — so auto retries through the stubbed OpenAI engine.
    // The internal fallback_reason provenance rides the result (injected
    // after wire validation, never part of the schema).
    const auditorPath = await stubAuditor("allow-auditor.py", { decision: "ALLOW", categories: [] })
    const result = await review({
      reviewer: "auto",
      jev: { endpoint: await deadEndpoint(), model: "jev-1.13", apiKey: "jev-key" },
      auditorPath,
    })
    expect(result.decision).toBe("ALLOW")
    expect(result.engine).toBe("openai")
    expect(typeof result.fallback_reason).toBe("string")
    expect(result.fallback_reason!.length).toBeGreaterThan(0)
  })

  test("reviewer:auto falls back when jev exits 4 (HTTP error incl. 4xx)", async () => {
    // Exit 4 covers every HTTP failure (4xx included): an infra-layer
    // failure, not a verdict — auto still retries via the OpenAI engine.
    const dir = await ensureWorkdir()
    const jevPath = path.join(dir, "http-err-jev.py")
    await writeFile(jevPath, "import sys\nsys.stdin.buffer.read()\nsys.exit(4)\n")
    const auditorPath = await stubAuditor("allow-auditor-http.py", { decision: "ALLOW", categories: [] })
    const result = await review({
      reviewer: "auto",
      jev: { endpoint: "http://127.0.0.1:1/x", model: "jev-1.13", apiKey: "jev-key" },
      jevPath,
      auditorPath,
    })
    expect(result.decision).toBe("ALLOW")
    expect(result.engine).toBe("openai")
    expect(result.fallback_reason).toBeTruthy()
  })

  test("an explicit reviewer:'jev' NEVER falls back to the OpenAI auditor", async () => {
    // Item 8: infra failure under the explicit (non-auto) preference is a
    // hard error — the caller asked for jev specifically.
    const auditorPath = await stubAuditor("allow-auditor-novfb.py", { decision: "ALLOW", categories: [] })
    await expect(
      review({
        reviewer: "jev",
        jev: { endpoint: await deadEndpoint(), model: "jev-1.13", apiKey: "jev-key" },
        auditorPath,
      }),
    ).rejects.toBeInstanceOf(ReviewError)
  })

  test("a DENY carrying the internal engine stamp stays a valid DENY", async () => {
    // Item 1: runEngine stamps `engine` on the validated wire object; the
    // host validator must reject it pre-strip but the verdict must survive
    // intact (previously a real DENY under fail_open ran unreviewed).
    const auditorPath = await stubAuditor("deny-auditor.py", { decision: "DENY", categories: ["secret"] })
    const result = await review({ auditorPath })
    expect(result.decision).toBe("DENY")
    expect(result.categories).toEqual(["secret"])
    expect(result.engine).toBe("openai")
    // The internal field is outside the wire schema: isValidReviewResult
    // stays strict on it.
    const stamped = { decision: "DENY", categories: ["secret"], engine: "openai" }
    expect(isValidReviewResult(stamped, false)).toBe(false)
    // Stripping the internal fields restores a valid wire object.
    delete (stamped as Record<string, unknown>).engine
    expect(isValidReviewResult(stamped, false)).toBe(true)
    expect(stamped.categories).toEqual(["secret"])
  })

  test("reviewer:auto does NOT fall back on a jev protocol failure", async () => {
    // The jev engine ran to completion but produced an invalid verdict: that
    // is a protocol failure (fail-close), never a reason to retry elsewhere.
    const jevPath = await stubAuditor("bad-jev.py", { decision: "MAYBE", categories: [] })
    const auditorPath = await stubAuditor("allow-auditor.py", { decision: "ALLOW", categories: [] })
    await expect(
      review({
        reviewer: "auto",
        jev: { endpoint: await deadEndpoint(), model: "jev-1.13", apiKey: "jev-key" },
        jevPath,
        auditorPath,
      }),
    ).rejects.toBeInstanceOf(ReviewError)
  })

  test("reviewer:jev without a usable jev config is a hard error", async () => {
    await expect(review({ reviewer: "jev" })).rejects.toThrow("Jev reviewer is not configured")
  })
})

// --- widened-category retry exemption ---------------------------------------

describe("findSimilarFailedEscalation categories exemption", () => {
  const failure = {
    command: "cat ~/.aws/credentials",
    categories: ["secret"],
    justification: "need credentials",
    decision: "ask_user" as const,
  }

  test("a retry that strictly widens the requested categories is exempt", () => {
    // Same command, but now also requesting filesystem: a coverage-fix retry
    // pointed at by the "Risk categories:" hint, not a disguised retry.
    expect(findSimilarFailedEscalation(failure.command, [failure], ["secret", "filesystem"])).toBeUndefined()
  })

  test("identical or narrowed category sets stay blocked", () => {
    expect(findSimilarFailedEscalation(failure.command, [failure], ["secret"])).toBe(failure)
    expect(findSimilarFailedEscalation(failure.command, [failure], ["filesystem"])).toBe(failure)
    expect(findSimilarFailedEscalation(failure.command, [failure])).toBe(failure)
    expect(findSimilarFailedEscalation(failure.command, [failure], [])).toBe(failure)
  })
})

// --- previousDenial wire shape ------------------------------------------------

describe("previousDenial reaches the escalation reviewer", () => {
  type MockReviewer = { endpoint: string; bodies: unknown[] }

  async function startReviewer(content: string): Promise<MockReviewer> {
    const bodies: unknown[] = []
    const server = createServer((req, res) => {
      let body = ""
      req.on("data", (chunk) => (body += chunk))
      req.on("end", () => {
        try {
          bodies.push(JSON.parse(body))
        } catch {
          bodies.push(body)
        }
        res.writeHead(200, { "Content-Type": "application/json" })
        res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content } }] }))
      })
    })
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
    servers.push(server)
    const port = (server.address() as AddressInfo).port
    return { endpoint: `http://127.0.0.1:${port}/v1`, bodies }
  }

  const request = {
    command: "cat ~/.aws/credentials",
    categories: ["secret", "filesystem"],
    justification: "inspect the credential file the task references",
    currentUserInput: "check the aws credentials",
    recentContext: [],
    permScope: { r: true, w: true, x: true },
  }

  test("the {command, riskCategories} shape is accepted and reaches the model prompt", async () => {
    const mock = await startReviewer("allow_once")
    const decision = await reviewEscalation(
      {
        ...request,
        previousDenial: { command: request.command, riskCategories: ["secret", "filesystem"] },
      },
      { endpoint: mock.endpoint, model: "esc-model", apiKey: "esc-key", timeout: 15000 },
    )
    expect(decision).toBe("allow_once")
    expect(mock.bodies).toHaveLength(1)
    const prompt = (mock.bodies[0] as { messages: Array<{ content: string }> }).messages.at(-1)!.content
    expect(prompt).toContain("Previous denial")
    expect(prompt).toContain('["secret","filesystem"]')
  })

  test("a previousDenial with extra keys is rejected by the strict validator", async () => {
    const mock = await startReviewer("allow_once")
    const malformed = {
      ...request,
      previousDenial: {
        command: request.command,
        riskCategories: ["secret"],
        reason: "legacy field the wire contract does not allow",
      },
    }
    await expect(
      reviewEscalation(malformed as never, {
        endpoint: mock.endpoint,
        model: "esc-model",
        apiKey: "esc-key",
        timeout: 15000,
      }),
    ).rejects.toThrow()
    expect(mock.bodies).toHaveLength(0)
  })
})

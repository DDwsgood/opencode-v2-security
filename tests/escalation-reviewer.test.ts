import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import os from "node:os"
import path from "node:path"
import {
  RollingEscalationReviewLimiter,
  parseEscalationReviewOutput,
  reviewEscalation,
  reviewEscalationDetailed,
  type EscalationReviewRequest,
} from "../src/security/escalation-reviewer"

let tempRoot: string

beforeAll(async () => {
  tempRoot = await mkdtemp(path.join(os.tmpdir(), "opencode-escalation-reviewer-"))
})

afterAll(async () => {
  await rm(tempRoot, { recursive: true, force: true })
})

const request: EscalationReviewRequest = {
  command: "sudo apt-get install curl",
  categories: ["host", "sandbox"],
  justification: "install the missing dependency needed by the requested test",
  currentUserInput: "Test the service at https://example.test",
  recentContext: [
    { role: "user", text: "Please test the service." },
    { role: "assistant", text: "The local curl binary is missing." },
  ],
  permScope: { r: true, w: true, x: true },
}

async function fakeReviewer(source: string): Promise<string> {
  const script = path.join(tempRoot, `reviewer-${crypto.randomUUID()}.py`)
  await writeFile(script, source, { mode: 0o600 })
  return script
}

describe("escalation reviewer output protocol", () => {
  test("accepts exactly one decision and one leading think block", () => {
    expect(parseEscalationReviewOutput("allow_once\n")).toBe("allow_once")
    // Legacy wire spelling normalizes to the unattended verdict.
    expect(parseEscalationReviewOutput("<think>private reasoning</think>ask_user")).toBe("collect_evidence")
    expect(parseEscalationReviewOutput("<think>private reasoning</think>\ndeny")).toBe("deny")
  })

  test("rejects explanations, markdown, multiple blocks, and unknown words", () => {
    for (const value of [
      "allow_once because it is safe",
      "```allow_once```",
      "allow_once deny",
      "<think>one</think><think>two</think>deny",
      "<thinking>one</thinking>deny",
      "maybe",
      "<think>unfinished allow_once",
    ]) {
      expect(() => parseEscalationReviewOutput(value)).toThrow()
    }
  })
})

describe("direct Python review and fail-closed behavior", () => {
  test("runs a direct Python child and returns its one-word decision", async () => {
    const script = await fakeReviewer('import sys\nsys.stdin.buffer.read()\nsys.stdout.write("allow_once\\n")\n')
    const result = await reviewEscalation(request, {
      endpoint: "http://127.0.0.1:9",
      model: "test-model",
      apiKey: "test-key",
      python: "python3",
      auditorPath: script,
      timeout: 2_000,
      limiter: new RollingEscalationReviewLimiter({ windowMs: 20, maxRequests: 2 }),
    })
    expect(result).toBe("allow_once")
  })

  test("does not turn a non-zero child exit into an approval", async () => {
    const script = await fakeReviewer(
      'import sys\nsys.stdout.write("allow_once\\n")\nsys.stderr.write("synthetic failure")\nsys.exit(9)\n',
    )
    await expect(
      reviewEscalation(request, {
        endpoint: "http://127.0.0.1:9",
        model: "test-model",
        apiKey: "test-key",
        python: "python3",
        auditorPath: script,
        timeout: 2_000,
        limiter: new RollingEscalationReviewLimiter({ windowMs: 20, maxRequests: 2 }),
      }),
    ).rejects.toThrow(/synthetic failure|exited with code 9/)
  })

  test("does not turn malformed stdout into an approval", async () => {
    const script = await fakeReviewer('import sys\nsys.stdout.write("allow_once deny\\n")\n')
    await expect(
      reviewEscalation(request, {
        endpoint: "http://127.0.0.1:9",
        model: "test-model",
        apiKey: "test-key",
        python: "python3",
        auditorPath: script,
        timeout: 2_000,
        limiter: new RollingEscalationReviewLimiter({ windowMs: 20, maxRequests: 2 }),
      }),
    ).rejects.toThrow(/invalid decision protocol/)
  })

  test("fails explicitly when the child times out", async () => {
    const script = await fakeReviewer("import time\ntime.sleep(10)\n")
    await expect(
      reviewEscalation(request, {
        endpoint: "http://127.0.0.1:9",
        model: "test-model",
        apiKey: "test-key",
        python: "python3",
        auditorPath: script,
        timeout: 30,
        limiter: new RollingEscalationReviewLimiter({ windowMs: 20, maxRequests: 2 }),
      }),
    ).rejects.toThrow(/timed out after 30ms/)
  })
})

describe("engine routing (jev/openai)", () => {
  const jevEnvProbe =
    'import os, sys\nsys.stdin.buffer.read()\nif not os.environ.get("JEV_API_KEY"):\n    sys.exit(4)\nsys.stdout.write("allow_once\\n")\n'
  const openaiScript =
    'import os, sys\nsys.stdin.buffer.read()\nif not os.environ.get("OPENCODE_V2_SECURITY_ESCALATION_API_KEY"):\n    sys.exit(4)\nsys.stdout.write("deny\\n")\n'
  const jev = { endpoint: "http://127.0.0.1:9/jev", model: "jev-test", apiKey: "k" }
  const base = {
    endpoint: "http://127.0.0.1:9",
    model: "test-model",
    apiKey: "test-key",
    python: "python3",
    timeout: 2_000,
    limiter: new RollingEscalationReviewLimiter({ windowMs: 20, maxRequests: 8 }),
  }

  test("auto prefers jev and feeds it JEV_* env", async () => {
    const jevPath = await fakeReviewer(jevEnvProbe)
    const openaiPath = await fakeReviewer(openaiScript)
    const result = await reviewEscalationDetailed(request, {
      ...base,
      reviewer: "auto",
      jev,
      jevPath,
      auditorPath: openaiPath,
    })
    expect(result.engine).toBe("jev")
    expect(result.decision).toBe("allow_once")
    expect(result.fallback_reason).toBeUndefined()
  })

  test("auto falls back to openai on jev infra failure only", async () => {
    const jevInfra = await fakeReviewer('import sys\nsys.stderr.write("network down")\nsys.exit(5)\n')
    const openaiPath = await fakeReviewer(openaiScript)
    const result = await reviewEscalationDetailed(request, {
      ...base,
      reviewer: "auto",
      jev,
      jevPath: jevInfra,
      auditorPath: openaiPath,
    })
    expect(result.engine).toBe("openai")
    expect(result.decision).toBe("deny")
    expect(result.fallback_reason).toMatch(/network down|code 5/)
  })

  test("auto does not fall back on jev protocol errors", async () => {
    const jevProtocol = await fakeReviewer('import sys\nsys.stderr.write("bad answers")\nsys.exit(6)\n')
    const openaiPath = await fakeReviewer(openaiScript)
    await expect(
      reviewEscalationDetailed(request, {
        ...base,
        reviewer: "auto",
        jev,
        jevPath: jevProtocol,
        auditorPath: openaiPath,
      }),
    ).rejects.toThrow(/bad answers|code 6/)
  })

  test("explicit jev never falls back", async () => {
    const jevInfra = await fakeReviewer('import sys\nsys.exit(5)\n')
    const openaiPath = await fakeReviewer(openaiScript)
    await expect(
      reviewEscalationDetailed(request, {
        ...base,
        reviewer: "jev",
        jev,
        jevPath: jevInfra,
        auditorPath: openaiPath,
      }),
    ).rejects.toThrow(/code 5/)
  })

  test("openai reviewer stays the default engine", async () => {
    const openaiPath = await fakeReviewer(openaiScript)
    const result = await reviewEscalationDetailed(request, {
      ...base,
      auditorPath: openaiPath,
    })
    expect(result.engine).toBe("openai")
    expect(result.decision).toBe("deny")
  })
})

describe("rolling escalation limiter", () => {
  test("allows the first two immediately and makes the third wait for the window", async () => {
    let now = 0
    const waits: number[] = []
    const limiter = new RollingEscalationReviewLimiter({
      windowMs: 3_000,
      maxRequests: 2,
      now: () => now,
      sleep: async (milliseconds) => {
        waits.push(milliseconds)
        now += milliseconds
      },
    })

    await Promise.all([limiter.acquire(), limiter.acquire()])
    expect(now).toBe(0)
    const third = limiter.acquire()
    await third
    expect(waits).toEqual([3_000])
    expect(now).toBe(3_000)
  })

  test("reserves slots correctly when callers arrive concurrently", async () => {
    let now = 0
    const waits: number[] = []
    const limiter = new RollingEscalationReviewLimiter({
      windowMs: 30,
      maxRequests: 2,
      now: () => now,
      sleep: async (milliseconds) => {
        waits.push(milliseconds)
        now += milliseconds
      },
    })
    await Promise.all(
      Array.from({ length: 3 }, async () => {
        await limiter.acquire()
      }),
    )
    expect(waits).toEqual([30])
    expect(now).toBe(30)
  })
})

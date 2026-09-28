// Real-clock stress + isolation tests for the escalation reviewer limiter.
//
// These tests deliberately use real timers and real Python children. The fake
// children record the moment they actually start, so the assertions observe
// when a reviewer child really began rather than trusting a mocked clock.
//
// The whole file is expected to take roughly 6-7 seconds: five concurrent
// reviews against a `2 starts / 3s` window finish in ~6s, plus one fast
// isolation test.

import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import {
  RollingEscalationReviewLimiter,
  reviewEscalation,
  setEscalationReviewLimiter,
  type EscalationReviewRequest,
} from "../src/security/escalation-reviewer"
import { reviewCommandWithAuditor } from "../src/security/reviewer"

let tempRoot: string
let repoRoot: string

beforeAll(async () => {
  tempRoot = await mkdtemp(path.join(os.tmpdir(), "opencode-escalation-stress-"))
  repoRoot = path.resolve(import.meta.dir, "..")
})

afterAll(async () => {
  await rm(tempRoot, { recursive: true, force: true })
})

const escalationRequest: EscalationReviewRequest = {
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

async function writeFakeScript(source: string): Promise<string> {
  const script = path.join(tempRoot, `fake-${crypto.randomUUID()}.py`)
  await writeFile(script, source, { mode: 0o600 })
  return script
}

/** Python that atomically appends its real start time, then answers. */
function startRecordingReviewer(logPath: string): string {
  return [
    "import os, sys, time",
    `_fd = os.open(${JSON.stringify(logPath)}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)`,
    'os.write(_fd, ("%.6f\\n" % time.time()).encode("ascii"))',
    "os.close(_fd)",
    "sys.stdin.buffer.read()",
    'sys.stdout.write("allow_once\\n")',
    "",
  ].join("\n")
}

async function readStartTimes(logPath: string): Promise<number[]> {
  const raw = await readFile(logPath, "utf8")
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => Number(line) * 1_000)
    .sort((a, b) => a - b)
}

const WINDOW_MS = 3_000
/**
 * A child's recorded start time is its Python interpreter's first write, which
 * happens a little after the limiter's reservation. A later child can therefore
 * appear very slightly early relative to an earlier one. This tolerance only
 * covers that tiny scheduler/child-start skew; it must stay in the tens of
 * milliseconds, never the ~300ms that would hide a real window violation.
 */
const SCHEDULING_SLACK_MS = 50

describe("escalation reviewer limiting (real clock)", () => {
  test(
    "keeps concurrent child starts to 2 per rolling 3s and spaces the 3rd by ~3s",
    async () => {
      const logPath = path.join(tempRoot, `starts-${crypto.randomUUID()}.log`)
      const script = await writeFakeScript(startRecordingReviewer(logPath))
      const apiKey = `fake-escalation-key-${crypto.randomUUID()}`
      // Dedicated real limiter with the production window and budget.
      const limiter = new RollingEscalationReviewLimiter()
      expect(limiter.windowMs).toBe(WINDOW_MS)
      expect(limiter.maxRequests).toBe(2)

      const startedAt = Date.now()
      const decisions = await Promise.all(
        Array.from({ length: 5 }, () =>
          reviewEscalation(escalationRequest, {
            endpoint: "http://127.0.0.1:9",
            model: "stress-model",
            apiKey,
            python: "python3",
            auditorPath: script,
            timeout: 10_000,
            limiter,
          }),
        ),
      )
      const elapsed = Date.now() - startedAt

      expect(decisions).toEqual(["allow_once", "allow_once", "allow_once", "allow_once", "allow_once"])

      const starts = await readStartTimes(logPath)
      expect(starts.length).toBe(5)

      // No rolling 3s window may contain 3 starts. For sorted starts this is
      // exactly: the 3rd start is a full window after the 1st, the 4th after
      // the 2nd, and the 5th after the 3rd (starts[i+2] - starts[i]). Only the
      // tiny child-start skew above is tolerated below the 3s window.
      for (let i = 0; i + 2 < starts.length; i++) {
        expect(starts[i + 2] - starts[i]).toBeGreaterThanOrEqual(WINDOW_MS - SCHEDULING_SLACK_MS)
      }
      // Five starts at 2 per 3s take about 6s, not ~1s and not one full window
      // per call (which would be ~12s). The upper bound is deliberately loose
      // for a loaded CI; the per-triple window check above is the hard limiter
      // assertion.
      expect(elapsed).toBeGreaterThanOrEqual(5_500)
      expect(elapsed).toBeLessThan(15_000)

      // The fake API key must never reach a child-written artifact.
      const artifact = await readFile(logPath, "utf8")
      expect(artifact).not.toContain(apiKey)
      expect(artifact).not.toContain("fake-escalation-key-")
    },
    20_000,
  )
})

describe("escalation limiter abort handling and idle reset", () => {
  test("aborting a waiter that holds the lock releases the queue without spending a slot", async () => {
    const limiter = new RollingEscalationReviewLimiter({ windowMs: 200, maxRequests: 1 })
    const order: string[] = []

    const first = limiter.acquire().then(() => order.push("first"))
    const abortController = new AbortController()
    const second = limiter.acquire(abortController.signal).then(
      () => order.push("second"),
      () => order.push("second-aborted"),
    )
    const third = limiter.acquire().then(() => order.push("third"))

    // The second waiter is holding the lock and sleeping out the window.
    await new Promise((resolve) => setTimeout(resolve, 40))
    abortController.abort()
    await Promise.all([first, second, third])

    expect(order).toEqual(["first", "second-aborted", "third"])
  })

  test("aborting a still-queued waiter does not strand later callers", async () => {
    const limiter = new RollingEscalationReviewLimiter({ windowMs: 200, maxRequests: 1 })
    const order: string[] = []

    const first = limiter.acquire().then(() => order.push("first"))
    const abortController = new AbortController()
    const second = limiter.acquire(abortController.signal).then(
      () => order.push("second"),
      () => order.push("second-aborted"),
    )
    const third = limiter.acquire().then(() => order.push("third"))

    // The second waiter holds the lock here; the third is queued behind it.
    abortController.abort()
    await Promise.all([first, second, third])

    expect(order[0]).toBe("first")
    expect(order).toContain("second-aborted")
    expect(order[order.length - 1]).toBe("third")
  })

  test("reset clears reservations so an immediate start is allowed when no waiter is queued", async () => {
    // `reset()` only empties the timestamp reservation list. The production
    // plugin never calls it, and this test deliberately makes no claim about
    // resetting while callers are already queued or sleeping -- that concurrent
    // reset semantics is out of scope here.
    const limiter = new RollingEscalationReviewLimiter({ windowMs: 2_000, maxRequests: 2 })
    await Promise.all([limiter.acquire(), limiter.acquire()])
    limiter.reset()
    const startedAt = Date.now()
    await limiter.acquire()
    expect(Date.now() - startedAt).toBeLessThan(500)
  })
})

describe("escalation limiter is not shared with the ordinary reviewer", () => {
  test(
    "ordinary review completes while the escalation limiter is saturated",
    async () => {
      // The ordinary reviewer module must not even reference the escalation
      // limiter, so there is no code path that could consume its budget.
      const ordinarySource = await readFile(path.join(repoRoot, "src/security/reviewer.ts"), "utf8")
      expect(ordinarySource).not.toContain("escalation-reviewer")
      expect(ordinarySource).not.toContain("EscalationReviewLimiter")
      expect(ordinarySource).not.toContain("reviewEscalation")

      const logPath = path.join(tempRoot, `ordinary-starts-${crypto.randomUUID()}.log`)
      const script = await writeFakeScript(
        [
          "import os, sys, time",
          `_fd = os.open(${JSON.stringify(logPath)}, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)`,
          'os.write(_fd, ("%.6f\\n" % time.time()).encode("ascii"))',
          "os.close(_fd)",
          "sys.stdin.buffer.read()",
          'sys.stdout.write(\'{"decision":"ALLOW","categories":[]}\\n\')',
          "",
        ].join("\n"),
      )

      // Install and saturate the process-wide escalation limiter. Ordinary
      // reviews must be completely unaffected by it.
      const processLimiter = new RollingEscalationReviewLimiter()
      setEscalationReviewLimiter(processLimiter)
      try {
        await Promise.all([processLimiter.acquire(), processLimiter.acquire()])
        expect(processLimiter.windowMs).toBe(WINDOW_MS)

        const startedAt = Date.now()
        const results = await Promise.all(
          Array.from({ length: 3 }, () =>
            reviewCommandWithAuditor("ls -la", {
              endpoint: "http://127.0.0.1:9",
              model: "ordinary-model",
              apiKey: "fake-ordinary-key",
              maxRounds: 1,
              policy: "LOOSE",
              python: "python3",
              auditorPath: script,
              timeout: 10_000,
            }),
          ),
        )
        const elapsed = Date.now() - startedAt

        expect(results.map((result) => result.decision)).toEqual(["ALLOW", "ALLOW", "ALLOW"])
        // Three ordinary reviews ran through the same saturated window and
        // still finished far below the 3s escalation wait.
        expect(elapsed).toBeLessThan(2_000)

        const ordinaryStarts = await readStartTimes(logPath)
        expect(ordinaryStarts.length).toBe(3)
        expect(ordinaryStarts[2] - ordinaryStarts[0]).toBeLessThan(2_000)
      } finally {
        setEscalationReviewLimiter(new RollingEscalationReviewLimiter())
      }
    },
    20_000,
  )
})

import { describe, expect, test } from "bun:test"
import frozen from "../src/security/v10-8-pipeexec.json"
import {
  adjudicateEffectAnswers,
  buildEffectReviewBody,
  EffectsReviewError,
  parseEffectAnswers,
  resolveUncollectableEffects,
  reviewEffects,
  type EffectCoverage,
  type EffectFloor,
  type EffectReviewRequest,
} from "../src/security/effects-reviewer"

const request: EffectReviewRequest = {
  command: "printf hello",
  cwd: "/workspace",
  environment: "Linux; shell=/bin/bash",
  user_request: "Inspect the project; do not change external files.",
  session_context: ["user: Inspect the project; do not change external files."],
  input_facts: [],
  files: [],
  sandbox: { trigger: "none", resolved_writes: [], domain: null, error: null },
  bypass: { categories: [], custom: null },
}

function answers(overrides: Record<string, unknown> = {}): Record<string, any> {
  const values = Object.fromEntries(Object.entries(frozen.questions).map(([name, question]) => [
    name,
    question.type === "noul"
      ? { type: "noul", noul: 0 }
      : { type: "choice", choice: Object.keys((question as { criteria: Record<string, string> }).criteria)[0] },
  ]))
  return {
    ...values,
    floor: { type: "choice", choice: "no" },
    scope_coverage: { type: "choice", choice: "no_material_effects" },
    uncovered_owner: { type: "choice", choice: "none" },
    gap_reach: { type: "choice", choice: "no_blocking_gap" },
    ...overrides,
  }
}

describe("frozen effects wire contract", () => {
  test("ships exactly the frozen header, 18 questions and model", () => {
    const body = buildEffectReviewBody(request)
    expect(body.model).toBe("jev-latest")
    expect(body.questions).toEqual(frozen.questions)
    expect(Object.keys(body.questions)).toHaveLength(18)
    expect(body.state.startsWith(`${frozen.header}\n\n<review_input>\n`)).toBe(true)
    expect(body.state.endsWith("\n</review_input>\n")).toBe(true)
  })

  test("authorization is conveyed without rewriting severity questions", () => {
    const authorized = {
      ...request,
      bypass: { categories: ["filesystem" as const], custom: "可以删除 /workspace/generated" },
    }
    const body = buildEffectReviewBody(authorized)
    expect(body.questions).toEqual(frozen.questions)
    const state = JSON.parse(body.state.slice(body.state.indexOf("<review_input>\n") + 15, body.state.lastIndexOf("\n</review_input>")))
    expect(state.bypass).toEqual(authorized.bypass)
    expect(state.user_request).toBe(request.user_request)
  })

  test("request-local edits cannot mutate the frozen question bundle", () => {
    const body = buildEffectReviewBody(request)
    body.questions.floor.instructions = "test-local mutation"
    expect(buildEffectReviewBody(request).questions).toEqual(frozen.questions)
  })

  test("host/private extra fields never enter the public projection", () => {
    const body = buildEffectReviewBody({ ...request, gold: "private fixture", apiKey: "test-only-placeholder" } as EffectReviewRequest)
    expect(body.state).not.toContain("private fixture")
    expect(body.state).not.toContain("test-only-placeholder")
  })

  test("oversized requests fail instead of silently losing scope", () => {
    expect(() => buildEffectReviewBody({ ...request, user_request: "x".repeat(512 * 1024) })).toThrow(EffectsReviewError)
  })

  test("bad authorization and file facts fail closed", () => {
    expect(() => buildEffectReviewBody({ ...request, bypass: { categories: ["all"], custom: null } } as unknown as EffectReviewRequest)).toThrow()
    expect(() => buildEffectReviewBody({ ...request, files: [{ path: "/workspace/x", kind: "file", role: "write", bytes: NaN }] })).toThrow()
  })
})

describe("strict effects answers", () => {
  test("missing, extra, mismatched and invalid choice answers fail", () => {
    const missing = answers()
    delete missing.floor
    for (const bad of [
      missing,
      answers({ invented_question: { noul: 0 } }),
      answers({ floor: { type: "noul", choice: "no" } }),
      answers({ floor: { choice: "approved" } }),
    ]) expect(() => parseEffectAnswers(bad)).toThrow(EffectsReviewError)
  })

  test("nonfinite/out-of-range/non-numeric probabilities fail", () => {
    for (const noul of [NaN, Infinity, -0.1, 1.1, "0", false]) {
      expect(() => parseEffectAnswers(answers({ filesystem_severity: { noul } }))).toThrow()
    }
  })

  test("selected choices remain authoritative, not unselected probabilities", () => {
    const report = adjudicateEffectAnswers(answers({
      floor: { type: "choice", choice: "no", probabilities: { yes: 0.9, no: 0.1, unclear: 0 } },
    }))
    expect(report.floor).toBe("no")
    expect(report.decision).toBe("allow")
  })

  test("invalid probability maps fail without changing the selected choice", () => {
    expect(() => parseEffectAnswers(answers({ floor: { choice: "no", probabilities: { no: 1 } } }))).toThrow()
    expect(() => parseEffectAnswers(answers({ floor: { choice: "no", probabilities: { yes: 0, no: 1, unclear: NaN } } }))).toThrow()
  })
})

describe("frozen adjudication order", () => {
  const covered: EffectCoverage[] = ["within_request", "covered_by_bypass", "mixed_coverage"]

  test("floor yes is never covered by authorization", () => {
    for (const coverage of covered) {
      expect(adjudicateEffectAnswers(answers({ floor: { choice: "yes" }, scope_coverage: { choice: coverage } })).decision).toBe("deny")
    }
  })

  test("coverage allows material effects without altering their probabilities", () => {
    for (const coverage of covered) {
      const result = adjudicateEffectAnswers(answers({
        filesystem_severity: { noul: 1 }, scope_coverage: { choice: coverage },
      }))
      expect(result.decision).toBe("allow")
      expect(result.severity.filesystem).toBe(1)
    }
  })

  test("covered material with unclear floor collects", () => {
    expect(adjudicateEffectAnswers(answers({
      floor: { choice: "unclear" }, filesystem_severity: { noul: 1 }, scope_coverage: { choice: "within_request" },
    })).decision).toBe("collect_evidence")
  })

  test("preserves no-material early return before unclear-floor/external-gap", () => {
    expect(adjudicateEffectAnswers(answers({
      floor: { choice: "unclear" }, gap_reach: { choice: "external_unresolvable" },
    })).decision).toBe("allow")
  })

  test("single effect threshold is inclusive, indirect opacity is not material", () => {
    for (const [score, expected] of [[0.49, "allow"], [0.5, "deny"], [1, "deny"]] as const) {
      expect(adjudicateEffectAnswers(answers({ filesystem_severity: { noul: score }, scope_coverage: { choice: "uncovered" } })).decision).toBe(expected)
    }
    expect(adjudicateEffectAnswers(answers({ indirection_severity: { noul: 1 }, scope_coverage: { choice: "uncovered" } })).decision).toBe("allow")
  })

  test("does not add score summation or diagnostic-owner overrides", () => {
    expect(adjudicateEffectAnswers(answers({
      filesystem_severity: { noul: 0.4 }, host_severity: { noul: 0.4 }, scope_coverage: { choice: "uncovered" },
    })).decision).toBe("allow")
    expect(adjudicateEffectAnswers(answers({
      filesystem_severity: { noul: 1 }, scope_coverage: { choice: "uncovered" }, uncovered_owner: { choice: "filesystem" },
    })).decision).toBe("deny")
  })

  test("uncovered material denies before a collectable gap", () => {
    expect(adjudicateEffectAnswers(answers({
      filesystem_severity: { noul: 1 }, scope_coverage: { choice: "uncovered" }, gap_reach: { choice: "local_resolvable" },
    })).decision).toBe("deny")
  })

  test("exhausted collection accepts unknowns only with floor no", () => {
    for (const floor of ["no", "unclear", "yes"] as EffectFloor[]) {
      const result = adjudicateEffectAnswers(answers({ floor: { choice: floor }, scope_coverage: { choice: "external_fact_missing" } }))
      expect(resolveUncollectableEffects(result, false)).toBe(result)
      const terminal = resolveUncollectableEffects(result, true)
      expect(terminal.decision).toBe(floor === "no" ? "allow" : floor === "yes" ? "deny" : "collect_evidence")
      if (floor === "no") expect(terminal.source).toBe("accepted_unknown")
    }
  })

  test("uncovered explicit denial never becomes accepted unknown", () => {
    const denial = adjudicateEffectAnswers(answers({ filesystem_severity: { noul: 1 }, scope_coverage: { choice: "uncovered" } }))
    expect(resolveUncollectableEffects(denial, true)).toBe(denial)
  })

  test("exhausted evidence has configurable allow/deny with default allow", () => {
    const result = adjudicateEffectAnswers(answers({ scope_coverage: { choice: "external_fact_missing" } }))
    expect(resolveUncollectableEffects(result, true).decision).toBe("allow")
    expect(resolveUncollectableEffects(result, true, "allow").source).toBe("accepted_unknown")
    expect(resolveUncollectableEffects(result, true, "deny")).toMatchObject({ decision: "deny", source: "evidence_limit", floor: "no" })
    expect(resolveUncollectableEffects(result, false, "deny")).toBe(result)
    const unclear = adjudicateEffectAnswers(answers({ floor: { choice: "unclear" }, scope_coverage: { choice: "external_fact_missing" } }))
    expect(resolveUncollectableEffects(unclear, true, "allow")).toBe(unclear)
    expect(resolveUncollectableEffects(unclear, true, "deny")).toBe(unclear)
  })
})

describe("effects transport without live API requests", () => {
  function fake(response: Response): typeof fetch {
    return (async () => response) as unknown as typeof fetch
  }

  test("credentials never reach cleartext nonloopback or userinfo endpoints", async () => {
    let called = false
    const fetchFn = (async () => { called = true; return Response.json({ answers: answers() }) }) as unknown as typeof fetch
    for (const endpoint of ["http://review.invalid/systemone", "https://user:password@review.invalid/systemone", "https://review.invalid/systemone#fragment"]) {
      await expect(reviewEffects(request, { endpoint, apiKey: "fixture-only", fetch: fetchFn })).rejects.toMatchObject({ kind: "protocol" })
    }
    expect(called).toBe(false)
    expect((await reviewEffects(request, { endpoint: "http://127.0.0.1/systemone", apiKey: "fixture-only", fetch: fetchFn })).decision).toBe("allow")
  })

  test("one request with redirects disabled and frozen model", async () => {
    const calls: RequestInit[] = []
    const fetchFn = (async (_url: unknown, init: RequestInit) => {
      calls.push(init)
      return Response.json({ answers: answers() })
    }) as unknown as typeof fetch
    expect((await reviewEffects(request, { endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", fetch: fetchFn })).decision).toBe("allow")
    expect(calls).toHaveLength(1)
    expect(calls[0].redirect).toBe("error")
    expect(JSON.parse(calls[0].body as string).model).toBe("jev-latest")
  })

  test("HTTP errors remain infrastructure/protocol errors, never collect-allow", async () => {
    for (const status of [400, 401, 403, 429, 500]) {
      try {
        await reviewEffects(request, { endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", fetch: fake(new Response("do not expose provider response", { status })) })
        throw new Error("Expected error")
      } catch (error) {
        expect(error).toBeInstanceOf(EffectsReviewError)
        expect((error as EffectsReviewError).kind).toBe(status === 400 ? "protocol" : "infrastructure")
        expect((error as Error).message).not.toContain("do not expose")
      }
    }
  })

  test("missing answers and malformed JSON are protocol failures", async () => {
    for (const response of [Response.json({}), new Response("not JSON")]) {
      await expect(reviewEffects(request, { endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", fetch: fake(response) })).rejects.toMatchObject({ kind: "protocol" })
    }
  })

  test("oversized response is bounded", async () => {
    await expect(reviewEffects(request, { endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", fetch: fake(new Response("x".repeat(1024 * 1024 + 1))) })).rejects.toMatchObject({ kind: "protocol" })
  })

  test("cancellation is not a risk judgment", async () => {
    const controller = new AbortController()
    controller.abort()
    let called = false
    const fetchFn = (async () => { called = true; throw new Error("aborted") }) as unknown as typeof fetch
    await expect(reviewEffects(request, { endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", signal: controller.signal, fetch: fetchFn })).rejects.toMatchObject({ kind: "aborted" })
    expect(called).toBe(false)
  })

  test("the deadline cancels the same in-flight request without a fallback", async () => {
    let calls = 0
    let cancelled = false
    const fetchFn = ((_url: unknown, init: RequestInit) => {
      calls += 1
      return new Promise<Response>((_resolve, reject) => {
        init.signal!.addEventListener("abort", () => { cancelled = true; reject(new Error("fixture cancellation")) }, { once: true })
      })
    }) as unknown as typeof fetch
    await expect(reviewEffects(request, { endpoint: "https://review.invalid/systemone", apiKey: "fixture-only", timeoutMs: 5, fetch: fetchFn })).rejects.toMatchObject({ kind: "infrastructure", message: "Effects review timed out" })
    expect(calls).toBe(1)
    expect(cancelled).toBe(true)
  })
})

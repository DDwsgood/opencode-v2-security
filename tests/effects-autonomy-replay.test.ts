import { describe, expect, test } from "bun:test"
import rows from "../research/jev-autonomy-20261013/replay-fixtures.json"
import { adjudicateEffectAnswers, buildEffectReviewBody, EFFECTS_POLICY_VERSION, EFFECTS_POLICY_VERSION_READONLY } from "../src/security/effects-reviewer"
import cases from "../research/jev-autonomy-20261013/combined-cases.json"

describe("recorded Jev autonomy responses through production adjudication", () => {
  test("missing encoded body no longer asks for unrelated external evidence", () => {
    const results = Object.fromEntries(rows.filter(r => r.id === "ps-encoded-unknown")
      .map(r => [r.variant, adjudicateEffectAnswers(r.response.answers)]))
    expect(results.baseline.decision).toBe("collect_evidence")
    expect(results.evidence_scope.decision).toBe("allow")
    expect(results.evidence_scope.floor).toBe("no")
    expect(results.evidence_scope.facts.indirection).toBe("executed_body_missing")
  })

  test("shown effects and explicit authorization retain their policy meaning", () => {
    for (const row of rows.filter(r => r.id !== "ps-encoded-unknown")) {
      expect(adjudicateEffectAnswers(row.response.answers).decision).toBe(row.expected as "allow" | "deny")
    }
  })

  test("unknown-body clarification does not override independent readonly conformance", () => {
    const row = rows.find(r => r.id === "ps-encoded-unknown" && r.variant === "evidence_scope")!
    const result = adjudicateEffectAnswers({ ...row.response.answers, readonly_conformance: { type: "choice", choice: "unclear" } }, true)
    expect(result.decision).toBe("deny")
    expect(result.source).toBe("readonly")
  })

  test("new prompt invalidates both read/write and readonly policy cache versions", () => {
    expect(EFFECTS_POLICY_VERSION).toBe("v10-8-pipeexec-user-auth-v3")
    expect(EFFECTS_POLICY_VERSION_READONLY).toBe(`${EFFECTS_POLICY_VERSION}-readonly`)
    const request = cases.find(c => c.id === "ps-encoded-unknown")!.request
    const body = buildEffectReviewBody(request)
    expect(Object.keys(body.questions)).toHaveLength(18)
    expect(body.state).toContain(request.user_request)
    expect(body.state).toContain(request.input_facts[0])
  })
})

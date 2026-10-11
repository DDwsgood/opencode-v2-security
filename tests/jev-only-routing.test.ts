import { describe, expect, test } from "bun:test"
import { reviewCommandWithAuditor, type ReviewCommandOptions } from "../src/security/reviewer"

describe("legacy reviewer entrypoint is also JEV-only", () => {
  test("OpenAI credentials alone never enable any reviewer", async () => {
    for (const reviewer of [undefined, "openai", "auto", "jev"] as const) {
      await expect(reviewCommandWithAuditor("printf hello", {
        endpoint: "https://unused.invalid/chat/completions",
        model: "legacy-model",
        apiKey: "fixture-only",
        policy: "LOOSE",
        maxRounds: 1,
        reviewer,
      })).rejects.toMatchObject({ kind: "infra", message: "The Jev reviewer is not configured" })
    }
  })

  test("JEV-only options do not require unused OpenAI fields or fall back", async () => {
    for (const reviewer of [undefined, "openai", "auto", "jev"] as const) {
      // A nonexistent interpreter fails locally, before any HTTP request.
      const options: ReviewCommandOptions = {
        jev: { endpoint: "https://unused.invalid/systemone", model: "jev-latest", apiKey: "fixture-only" },
        reviewer,
        policy: "LOOSE",
        maxRounds: 1,
        python: "/tmp/opencode/jev-only-nonexistent-interpreter-20261008",
      }
      await expect(reviewCommandWithAuditor("printf hello", options)).rejects.toMatchObject({ code: "ENOENT" })
    }
  })
})

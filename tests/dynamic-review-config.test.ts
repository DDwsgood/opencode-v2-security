import { afterEach, describe, expect, test } from "bun:test"
import { resolvePluginConfig } from "../src/config"

// The review chain is JEV-only: availability depends solely on the jev
// settings resolving (endpoint + model + key env). Legacy OpenAI-auditor
// fields are accepted for compatibility but never enable anything.

const JEV_ENV = "JEV_API_KEY"
const FALLBACK_ENV = "OC_API_KEY"

const savedEnv: Record<string, string | undefined> = {}
function setEnv(name: string, value: string | undefined) {
  if (!(name in savedEnv)) savedEnv[name] = process.env[name]
  if (value === undefined) delete process.env[name]
  else process.env[name] = value
}

afterEach(() => {
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name]
    else process.env[name] = value
  }
})

describe("dynamicReview JEV-only resolution", () => {
  test("no dynamicReview → unavailable, reviewer jev, onUncollectable allow", () => {
    const resolved = resolvePluginConfig({})
    expect(resolved.dynamicReview.available).toBe(false)
    expect(resolved.dynamicReview.reviewer).toBe("jev")
    expect(resolved.dynamicReview.onUncollectable).toBe("allow")
    expect(resolved.reviewCommand).toBeUndefined()
  })

  test("jev object + key env → available without any OpenAI fields", () => {
    setEnv(JEV_ENV, "test-jev-key")
    setEnv(FALLBACK_ENV, undefined)
    const resolved = resolvePluginConfig({ dynamicReview: { jev: {} } })
    expect(resolved.dynamicReview.available).toBe(true)
    expect(resolved.dynamicReview.reviewer).toBe("jev")
    expect(resolved.dynamicReview.jev?.available).toBe(true)
    expect(resolved.dynamicReview.jev?.model).toBe("jev-latest")
    expect(resolved.dynamicReview.jev?.endpoint).toBe("https://opencode.ai/zen/v1/systemone")
    expect(typeof resolved.reviewCommand).toBe("function")
  })

  test("empty dynamicReview object → jev defaults, needs only the key env", () => {
    setEnv(JEV_ENV, "test-jev-key")
    const resolved = resolvePluginConfig({ dynamicReview: {} })
    expect(resolved.dynamicReview.available).toBe(true)
    expect(resolved.dynamicReview.jev?.available).toBe(true)
  })

  test("no JEV key → unavailable even with OpenAI fields present", () => {
    setEnv(JEV_ENV, undefined)
    setEnv(FALLBACK_ENV, undefined)
    const resolved = resolvePluginConfig({
      dynamicReview: {
        baseURL: "https://api.example.com",
        model: "gpt-x",
        apiKey: "sk-legacy",
      },
    })
    expect(resolved.dynamicReview.available).toBe(false)
    expect(resolved.dynamicReview.reason).toMatch(/jev api key is not configured/)
    // Legacy fields were accepted (not a hard error) but produce a warning.
    expect(resolved.dynamicReviewWarnings.length).toBeGreaterThan(0)
    expect(resolved.reviewCommand).toBeUndefined()
  })

  test("stale legacy auditorPath/pythonPath do not break a working JEV setup", () => {
    setEnv(JEV_ENV, "test-jev-key")
    const resolved = resolvePluginConfig({
      dynamicReview: {
        jev: {},
        // Nonexistent paths that the old chain would have rejected — the
        // JEV-only chain must not even validate them.
        auditorPath: "/nonexistent/old-auditor.py",
        pythonPath: "/nonexistent/python3",
      },
    })
    expect(resolved.dynamicReview.available).toBe(true)
    expect(resolved.dynamicReview.jev?.available).toBe(true)
    expect(resolved.dynamicReviewWarnings.some((w) => w.includes("auditorPath"))).toBe(true)
    expect(resolved.dynamicReviewWarnings.some((w) => w.includes("pythonPath"))).toBe(true)
  })

  test("legacy reviewer spellings coerce to jev with a warning; unknown value rejects", () => {
    setEnv(JEV_ENV, "test-jev-key")
    for (const legacy of ["openai", "auto"] as const) {
      const resolved = resolvePluginConfig({ dynamicReview: { reviewer: legacy } })
      expect(resolved.dynamicReview.reviewer).toBe("jev")
      expect(resolved.dynamicReview.available).toBe(true)
      expect(
        resolved.dynamicReviewWarnings.some((w) => w.includes(`"${legacy}"`)),
      ).toBe(true)
    }
    const bad = resolvePluginConfig({ dynamicReview: { reviewer: "claude" } })
    expect(bad.dynamicReview.available).toBe(false)
    expect(bad.dynamicReview.reason).toMatch(/dynamicReview\.reviewer must be/)
  })

  test("jev.enabled:false disables; missing key reports env name", () => {
    setEnv(JEV_ENV, "test-jev-key")
    expect(
      resolvePluginConfig({ dynamicReview: { jev: { enabled: false } } }).dynamicReview.available,
    ).toBe(false)
    setEnv(JEV_ENV, undefined)
    setEnv(FALLBACK_ENV, undefined)
    const resolved = resolvePluginConfig({ dynamicReview: { jev: { apiKeyEnv: "MY_KEY" } } })
    expect(resolved.dynamicReview.jev?.reason).toMatch(/MY_KEY or OC_API_KEY/)
  })

  test("explicit jev reviewer + missing key is unavailable (not a throw)", () => {
    setEnv(JEV_ENV, undefined)
    setEnv(FALLBACK_ENV, undefined)
    const resolved = resolvePluginConfig({ dynamicReview: { reviewer: "jev" } })
    expect(resolved.dynamicReview.available).toBe(false)
    expect(resolved.dynamicReview.reviewer).toBe("jev")
  })
})

describe("dynamicReview.onUncollectable", () => {
  test("defaults to allow on every resolution path", () => {
    expect(resolvePluginConfig({}).dynamicReview.onUncollectable).toBe("allow")
    expect(resolvePluginConfig({ dynamicReview: {} }).dynamicReview.onUncollectable).toBe("allow")
    // Unavailable paths carry the default too.
    setEnv(JEV_ENV, undefined)
    setEnv(FALLBACK_ENV, undefined)
    const resolved = resolvePluginConfig({ dynamicReview: { jev: {} } })
    expect(resolved.dynamicReview.available).toBe(false)
    expect(resolved.dynamicReview.onUncollectable).toBe("allow")
  })

  test("accepts allow and deny", () => {
    expect(
      resolvePluginConfig({ dynamicReview: { onUncollectable: "allow" } }).dynamicReview
        .onUncollectable,
    ).toBe("allow")
    expect(
      resolvePluginConfig({ dynamicReview: { onUncollectable: "deny" } }).dynamicReview
        .onUncollectable,
    ).toBe("deny")
  })

  test("invalid values are a hard config error, never a silent fallback", () => {
    for (const bad of ["yes", "allow-deny", 1, true, null]) {
      expect(() => resolvePluginConfig({ dynamicReview: { onUncollectable: bad } })).toThrow(
        /onUncollectable must be "allow" or "deny"/,
      )
    }
  })
})

describe("canonical temporary-root spelling", () => {
  test("trailing slashes normalize without turning a blocked root into an alias", () => {
    expect(resolvePluginConfig({ sandbox: { scratch: "/tmp/" } }).sandbox.scratch).toBe("/tmp")
    expect(() => resolvePluginConfig({ sandbox: { scratch: "/home/" } })).toThrow()
    expect(() => resolvePluginConfig({ sandbox: { scratch: "/tmp/a:b" } })).toThrow()
  })
})

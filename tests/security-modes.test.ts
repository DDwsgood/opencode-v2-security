import { describe, expect, test } from "bun:test"
import { resolvePluginConfig } from "../src/config"
import { isValidReviewResult } from "../src/index"
import { parsePerm, parseSecurityMode, permForMode, securityModeFor, securityModeLabel } from "../src/permissions"

describe("three public security modes", () => {
  test("read-only aliases resolve to the read-only mode", () => {
    for (const alias of ["r", "ro", "read", "readonly", "read-only", "read_only", "r--", "4", "RO"]) {
      expect(parseSecurityMode(alias)).toBe("readonly")
      expect(parsePerm(alias)).toMatchObject({ r: true, w: false })
    }
  })

  test("w/rw/auto all mean readable automatic mode, not write-only", () => {
    for (const alias of ["w", "rw", "auto", "automatic", "readwrite", "read-write", "rw-", "6"]) {
      expect(parseSecurityMode(alias)).toBe("auto")
      expect(parsePerm(alias)).toMatchObject({ r: true, w: true })
    }
  })

  test("bypass is a user mode, never an agent-writable permission bit", () => {
    for (const alias of ["bypass", "yolo", "all", "*"]) expect(parseSecurityMode(alias)).toBe("bypass")
    expect(parsePerm("bypass")).toBeUndefined()
    expect(permForMode("bypass")).toMatchObject({ r: true, w: true })
  })

  test("inherited read-only ceiling takes priority over bypass", () => {
    expect(securityModeFor(permForMode("readonly"), true)).toBe("readonly")
    expect(securityModeFor(permForMode("auto"), true)).toBe("bypass")
    expect(securityModeFor(permForMode("auto"), false)).toBe("auto")
  })

  test("labels contain only mode/categories and a custom flag", () => {
    expect(securityModeLabel("readonly", ["secret"], true)).toBe("[Read only]")
    expect(securityModeLabel("bypass", [], true)).toBe("[Bypass mode]")
    expect(securityModeLabel("auto")).toBe("[Auto mode]")
    expect(securityModeLabel("auto", ["network", "filesystem", "ALL", "network"], true))
      .toBe("[Auto mode, bypassing: filesystem,network, custom bypassing on]")
  })
})

describe("one review policy", () => {
  test("the legacy validator cannot reactivate strict bypassing checks", () => {
    const plain = { decision: "ALLOW", categories: [] }
    expect(isValidReviewResult(plain, true)).toBe(true)
    const legacy = { decision: "ALLOW", categories: [], bypassing: true }
    expect(isValidReviewResult(legacy, true)).toBe(true)
    expect(legacy).not.toHaveProperty("bypassing")
  })
  test("default and legacy LOOSE select the same single policy", () => {
    expect(resolvePluginConfig({}).strictness).toBe("LOOSE")
    expect(resolvePluginConfig({ strictness: "LOOSE" }).strictness).toBe("LOOSE")
  })

  test("removed policies cannot be selected or silently converted", () => {
    for (const strictness of ["HARD", "hard", "strict", "auto"]) {
      expect(() => resolvePluginConfig({ strictness } as never)).toThrow("single current policy")
    }
  })
})

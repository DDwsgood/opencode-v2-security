import { describe, expect, test } from "bun:test"
import {
  BYPASS_CATEGORIES,
  STATIC_BYPASS_CATEGORIES,
  expandBypassCategoryToken,
  resolvePluginConfig,
} from "../src/config"
import { ruleBypassed, ruleRequiredCategories } from "../src/security/bypass"

describe("canonical bypass categories", () => {
  test("risk and enforcement-layer categories are shared", () => {
    expect([...STATIC_BYPASS_CATEGORIES]).toEqual([
      "filesystem", "host", "privilege", "secret", "network", "remote", "indirection",
    ])
    expect([...BYPASS_CATEGORIES]).toEqual([
      "filesystem", "host", "privilege", "secret", "network", "remote", "indirection", "dynamic", "sandbox", "slow",
    ])
  })

  test("legacy names expand only at the boundary", () => {
    expect(expandBypassCategoryToken("fs")).toEqual(["filesystem"])
    expect(expandBypassCategoryToken("OS")).toEqual(["host", "privilege", "indirection"])
    expect(expandBypassCategoryToken("web")).toEqual(["network", "remote"])
    const resolved = resolvePluginConfig({ BypassClassifier: ["os", "web"] })
    expect([...resolved.bypassClassifier].sort()).toEqual(["host", "indirection", "network", "privilege", "remote"])
    expect(resolved.bypassWarnings).toHaveLength(2)
  })
})

describe("conjunctive rule requirements", () => {
  test("credential destruction is owned by secret alone (policyVersion 1.5)", () => {
    // Deleting a credential object is a secret judgment: the object's own
    // filesystem mechanics are not a second owner.
    expect(ruleRequiredCategories("data.critical-delete")).toEqual(["secret"])
    expect(ruleBypassed("data.critical-delete", new Set(["filesystem"]))).toBe(false)
    expect(ruleBypassed("data.critical-delete", new Set(["secret"]))).toBe(true)
    expect(ruleBypassed("data.critical-delete", new Set(["filesystem", "secret"]))).toBe(true)
  })

  test("credential exfiltration needs secret and network", () => {
    // Genuinely independent exfiltration keeps both owners: a credential
    // leaving the host is a secret loss AND a network egress.
    expect(ruleBypassed("exfiltration.dns", new Set(["secret"]))).toBe(false)
    expect(ruleBypassed("exfiltration.dns", new Set(["network"]))).toBe(false)
    expect(ruleBypassed("exfiltration.dns", new Set(["secret", "network"]))).toBe(true)
  })

  test("remote pipe is owned by remote alone (fetch is its intrinsic channel)", () => {
    expect(ruleRequiredCategories("execution.remote-pipe")).toEqual(["remote"])
    expect(ruleBypassed("execution.remote-pipe", new Set(["network"]))).toBe(false)
    expect(ruleBypassed("execution.remote-pipe", new Set(["remote"]))).toBe(true)
  })

  test("indirection is independent from filesystem", () => {
    expect(ruleBypassed("execution.wrapper", new Set(["filesystem"]))).toBe(false)
    expect(ruleBypassed("execution.wrapper", new Set(["indirection"]))).toBe(true)
  })

  test("the safety floor survives every category", () => {
    const all = new Set(BYPASS_CATEGORIES)
    for (const rule of [
      "filesystem.root-delete",
      "filesystem.disk-destruction",
      "execution.fork-bomb",
      "network.reverse-shell",
      "execution.literal-shell",
    ]) {
      expect(ruleRequiredCategories(rule)).toBeUndefined()
      expect(ruleBypassed(rule, all)).toBe(false)
    }
  })
})

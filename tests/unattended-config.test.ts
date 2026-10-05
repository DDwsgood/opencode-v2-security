import { describe, expect, test } from "bun:test"
import { resolvePluginConfig, type BashClassifierOptions } from "../src/config"

describe("unattended failure policies", () => {
  test("legacy fail_ask configuration becomes an automatic refusal", () => {
    const legacy = { failPolicy: "fail_ask" } as unknown as BashClassifierOptions
    expect(resolvePluginConfig(legacy).failPolicy).toBe("fail_close")
  })

  test("explicit automatic failure policies keep their meaning", () => {
    expect(resolvePluginConfig({ failPolicy: "fail_open" }).failPolicy).toBe("fail_open")
    expect(resolvePluginConfig({ failPolicy: "fail_close" }).failPolicy).toBe("fail_close")
  })

  test("unknown failure policies are not silently accepted", () => {
    const invalid = { failPolicy: "confirm" } as unknown as BashClassifierOptions
    expect(() => resolvePluginConfig(invalid)).toThrow('failPolicy must be "fail_open" or "fail_close"')
  })
})

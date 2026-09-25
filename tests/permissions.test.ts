import { describe, expect, test } from "bun:test"
import {
  DEFAULT_ACTION_PERM,
  fallbackPermBit,
  parsePerm,
  permIntersect,
  permLabel,
  PERM_FULL,
  permSubset,
  requiredPermBit,
  tightenPerm,
  type Perm,
} from "../src/permissions"

const perm = (r: boolean, w: boolean, x = false): Perm => ({ r, w, x })

describe("parsePerm (r/w MVP)", () => {
  const valid: Array<[string, Perm]> = [
    ["r", perm(true, false)],
    ["ro", perm(true, false)],
    ["read", perm(true, false)],
    ["r--", perm(true, false)],
    ["4", perm(true, false)],
    ["w", perm(false, true)],
    ["-w-", perm(false, true)],
    ["2", perm(false, true)],
    ["rw", perm(true, true)],
    ["rw-", perm(true, true)],
    ["wr", perm(true, true)],
    ["6", perm(true, true)],
    ["none", perm(false, false)],
    ["off", perm(false, false)],
    ["0", perm(false, false)],
  ]
  for (const [raw, expected] of valid) {
    test(`accepts ${JSON.stringify(raw)}`, () => {
      expect(parsePerm(raw)).toEqual(expected)
    })
  }
  test("is case/whitespace insensitive", () => {
    expect(parsePerm("  RO ")).toEqual(perm(true, false))
  })
  const xBearing = ["x", "rx", "wx", "rwx", "--x", "r-x", "-wx", "1", "3", "5", "7"]
  for (const raw of xBearing) {
    test(`rejects x-bearing ${JSON.stringify(raw)} (never silently stripped)`, () => {
      expect(parsePerm(raw)).toBeUndefined()
    })
  }
  test("rejects garbage", () => {
    expect(parsePerm("")).toBeUndefined()
    expect(parsePerm("abc")).toBeUndefined()
    expect(parsePerm("9")).toBeUndefined()
    expect(parsePerm("-")).toBeUndefined()
  })
})

describe("tighten-only semantics", () => {
  test("tighten passes through", () => {
    expect(tightenPerm(PERM_FULL, perm(true, false))).toEqual(perm(true, false))
    expect(tightenPerm(perm(true, true), perm(true, false))).toEqual(perm(true, false))
  })
  test("widening is rejected", () => {
    expect(tightenPerm(perm(true, false), perm(true, true))).toBeUndefined()
    expect(tightenPerm(perm(false, false), perm(true, false))).toBeUndefined()
  })
  test("permIntersect never widens", () => {
    expect(permIntersect(perm(true, false), PERM_FULL)).toEqual(perm(true, false))
    expect(permIntersect(perm(true, true), perm(false, true))).toEqual(perm(false, true))
  })
  test("permSubset / permLabel", () => {
    expect(permSubset(perm(true, false), PERM_FULL)).toBe(true)
    expect(permSubset(PERM_FULL, perm(true, false))).toBe(false)
    // x is always available: the label shows it set on every triple.
    expect(permLabel(perm(true, false))).toBe("r-x")
    expect(permLabel(PERM_FULL)).toBe("rwx")
    expect(permLabel(perm(false, false))).toBe("--x")
    expect(permLabel(perm(false, true))).toBe("-wx")
  })
})

describe("action gating (r/w MVP)", () => {
  test("edit requires w; read-class actions require r", () => {
    expect(DEFAULT_ACTION_PERM.edit).toBe("w")
    for (const action of [
      "read",
      "grep",
      "glob",
      "webfetch",
      "websearch",
      "skill",
      "question",
      "external_directory",
      "subagent",
    ]) {
      expect(DEFAULT_ACTION_PERM[action]).toBe("r")
    }
  })
  test("shell is absent from the map — RO keeps read-only shell usable", () => {
    expect(DEFAULT_ACTION_PERM.task).toBeUndefined()
    expect(fallbackPermBit("task")).toBe("w")
    expect(DEFAULT_ACTION_PERM.shell).toBeUndefined()
    expect(requiredPermBit("shell")).toBeUndefined()
    expect(fallbackPermBit("shell")).toBeUndefined()
  })
  test("unmapped/MCP actions fall back to the write bit", () => {
    expect(fallbackPermBit("github_create_issue")).toBe("w")
    expect(fallbackPermBit("some_future_action")).toBe("w")
  })
  test("deliberately ungated actions are exempt from the fallback", () => {
    expect(fallbackPermBit("webfetch", { ungated: new Set(["webfetch"]) })).toBeUndefined()
  })
})

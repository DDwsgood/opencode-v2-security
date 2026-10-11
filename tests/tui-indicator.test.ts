import { describe, expect, test } from "bun:test"
import { modeForState, segmentsFor, type IndicatorTheme } from "../src/indicator"

const theme: IndicatorTheme = {
  text: {
    subdued: "subdued",
    feedback: {
      success: { subdued: "green" },
      warning: { default: "orange" },
      danger: { default: "red" },
    },
  },
}

const seg = (state: Parameters<typeof segmentsFor>[0]) => segmentsFor(state, theme)[0]!

describe("three-mode badge labels", () => {
  test("read-only renders [Read only] with the success color", () => {
    expect(seg({ permission: "r-x", active: [], synced: true })).toEqual({ text: "[Read only]", fg: "green" })
  })

  test("bypass renders [Bypass mode] with the danger color", () => {
    expect(seg({ permission: "rwx", active: ["ALL"], synced: true })).toEqual({ text: "[Bypass mode]", fg: "red" })
  })

  test("plain auto renders [Auto mode] subdued", () => {
    expect(seg({ permission: "rwx", active: [], synced: true })).toEqual({ text: "[Auto mode]", fg: "subdued" })
  })

  test("auto with categories renders a sorted, comma-joined suffix", () => {
    expect(seg({ permission: "rwx", active: ["host", "filesystem"], synced: true })).toEqual({
      text: "[Auto mode, bypassing: filesystem,host]",
      fg: "orange",
    })
  })

  test("auto appends the custom flag without leaking the raw scope text", () => {
    const state = {
      permission: "rwx",
      active: ["host", "filesystem"],
      custom: true,
      synced: true,
    }
    expect(seg(state)).toEqual({
      text: "[Auto mode, bypassing: filesystem,host, custom bypassing on]",
      fg: "orange",
    })
    // Only the boolean is ever rendered; no scope text lives in the state.
    expect(JSON.stringify(state)).not.toContain("secret")
  })

  test("custom-only auto still reports the suffix", () => {
    expect(seg({ permission: "rwx", active: [], custom: true, synced: true }).text).toBe(
      "[Auto mode, custom bypassing on]",
    )
  })

  test("read-only and bypass never carry the Auto suffix", () => {
    expect(seg({ permission: "r-x", active: ["filesystem"], custom: true, synced: true }).text).toBe("[Read only]")
    expect(seg({ permission: "rwx", active: ["ALL", "filesystem"], custom: true, synced: true }).text).toBe(
      "[Bypass mode]",
    )
  })
})

describe("legacy servers without an explicit mode", () => {
  test("modeForState derives from the write bit and the ALL marker (RO wins)", () => {
    expect(modeForState({ permission: "rwx", active: [] })).toBe("auto")
    expect(modeForState({ permission: "r-x", active: [] })).toBe("readonly")
    expect(modeForState({ permission: "-w-", active: [] })).toBe("auto")
    expect(modeForState({ permission: "rwx", active: ["ALL"] })).toBe("bypass")
    // An inherited read-only ceiling outranks an armed bypass.
    expect(modeForState({ permission: "r-x", active: ["ALL"] })).toBe("readonly")
  })

  test("an explicit mode is authoritative over the legacy fields", () => {
    expect(modeForState({ permission: "r-x", active: [], mode: "auto" })).toBe("auto")
    expect(modeForState({ permission: "rwx", active: ["ALL"], mode: "readonly" })).toBe("readonly")
    expect(
      segmentsFor({ permission: "rwx", mode: "bypass", active: ["filesystem"], synced: true }, theme)[0]!.text,
    ).toBe("[Bypass mode]")
  })

  test("explicit auto still canonicalizes and sorts the category list", () => {
    expect(
      seg({ permission: "rwx", mode: "auto", active: ["host", "filesystem", "ALL"], synced: true }),
    ).toEqual({ text: "[Auto mode, bypassing: filesystem,host]", fg: "orange" })
  })
})

describe("unsynced indicator state", () => {
  // A badge that cannot prove freshness must admit it instead of asserting a
  // possibly stale state (e.g. [Bypass mode] after the lease actually expired).
  test("unsynced state renders an honest unknown label, never the stale claim", () => {
    const segs = segmentsFor({ permission: "rwx", mode: "bypass", active: ["ALL"], synced: false }, theme)
    expect(segs).toEqual([{ text: "[Security state unknown]", fg: "subdued" }])
  })

  test("entries written by older generations (no synced field) render unknown too", () => {
    expect(segmentsFor({ permission: "r-x", active: [] }, theme)[0]!.text).toBe("[Security state unknown]")
  })

  test("a synced snapshot restores normal rendering", () => {
    expect(segmentsFor({ permission: "rwx", active: ["ALL"], synced: true }, theme)[0]!.text).toBe("[Bypass mode]")
    expect(segmentsFor({ permission: "r-x", active: [], synced: true }, theme)[0]!.text).toBe("[Read only]")
  })
})

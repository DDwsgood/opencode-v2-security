import { describe, expect, test } from "bun:test"
import { permissionLabel, segmentsFor, type IndicatorTheme } from "../src/indicator"

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

describe("permission badge labels", () => {
  test("label covers every r/w bit combination", () => {
    expect(permissionLabel("rwx")).toBe("Read + Write")
    expect(permissionLabel("rw-")).toBe("Read + Write")
    expect(permissionLabel("r-x")).toBe("Read Only")
    expect(permissionLabel("r--")).toBe("Read Only")
    expect(permissionLabel("-w-")).toBe("Write Only")
    expect(permissionLabel("-wx")).toBe("Write Only")
    // Neither bit: honest fallback, never a "Read"/"Write" claim.
    expect(permissionLabel("--x")).toBe("--x")
    expect(permissionLabel("---")).toBe("---")
    expect(permissionLabel("")).toBe("none")
  })

  test("write-only ceiling renders [Write Only], not [Read + Write]", () => {
    const segs = segmentsFor({ permission: "-w-", active: [] }, theme)
    expect(segs[0]!.text).toBe("[Write Only]")
    expect(segs[0]!.fg).toBe("subdued")
  })

  test("read+write and read-only render their labels", () => {
    expect(segmentsFor({ permission: "rwx", active: [] }, theme)[0]!.text).toBe("[Read + Write]")
    expect(segmentsFor({ permission: "r-x", active: [] }, theme)[0]!.text).toBe("[Read Only]")
  })

  test("write-only stays [Write Only] inside a bypassing badge", () => {
    const segs = segmentsFor({ permission: "-w-", active: ["filesystem"] }, theme)
    expect(segs[0]!.text).toContain("Write Only")
    expect(segs[0]!.text).toContain("Bypassing Category(ies): filesystem")
  })

  test("kill switch still replaces the whole badge", () => {
    const segs = segmentsFor({ permission: "-w-", active: ["ALL"] }, theme)
    expect(segs[0]!.text).toBe("[YOLO ON, Bypassing all permissions]")
  })
})

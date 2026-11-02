import { describe, expect, test } from "bun:test"
import type { SandboxSelection } from "../src/sandbox"
import { buildWindowsSandboxSpawn, probeWindowsSandbox, type WindowsSandboxOptions } from "../src/windows-sandbox"

const sandbox: SandboxSelection = {
  enabled: true,
  mode: "auto",
  helperPath: "C:\\OpenCode\\opencode-windows-sandbox.exe",
  bwrapPath: "",
  scratch: "C:\\SandboxScratch",
  roNetwork: "off",
  rwNetwork: "off",
  workspaceNetwork: "off",
  denyRead: [],
  denyWrite: [],
  allowSudo: false,
  extraArgs: [],
  maskWslInterop: true,
  maskPrivilegedSockets: [],
  roAfUnixBlock: true,
  onUnavailable: "fail_close",
}

const options: WindowsSandboxOptions = {
  cwd: "C:\\My Workspace",
  readRoots: ["C:\\My Workspace"],
  writeRoots: ["C:\\My Workspace"],
  denyRead: ["C:\\My Workspace\\secret"],
  denyWrite: ["C:\\My Workspace\\frozen"],
  network: false,
}

describe("Windows sandbox launch contract", () => {
  test("versioned JSON preserves path boundaries and readonly drops every persistent write grant", () => {
    const workspace = buildWindowsSandboxSpawn("workspace", sandbox, options)
    const policy = JSON.parse(workspace.env.OPENCODE_WINDOWS_SANDBOX_POLICY)
    expect(policy).toEqual({ version: 1, profile: "workspace", scratch: sandbox.scratch, ...options })
    expect(workspace.env.OPENCODE_REAL_SHELL).toBeUndefined()
    expect(JSON.parse(buildWindowsSandboxSpawn("ro", sandbox, options).env.OPENCODE_WINDOWS_SANDBOX_POLICY).writeRoots).toEqual([])
    expect(() => buildWindowsSandboxSpawn("full", sandbox, options)).toThrow("Bypass")
  })

  test("rejects ambiguous paths and unauthenticated control channels before spawning", () => {
    for (const cwd of ["C:relative", "\\\\server\\share", "\\\\?\\C:\\file", "C:\\x:stream", "C:\\x\\..\\y", "C:\\x. "]) {
      expect(() => buildWindowsSandboxSpawn("workspace", sandbox, { ...options, cwd })).toThrow()
    }
    expect(() => buildWindowsSandboxSpawn("workspace", sandbox, { ...options, controlPipe: "\\\\.\\pipe\\other" })).toThrow()
    const controlled = buildWindowsSandboxSpawn("workspace", sandbox, {
      ...options, controlPipe: "\\\\.\\pipe\\opencode-security-fixture", controlToken: "a".repeat(64),
    })
    expect(controlled.env.OPENCODE_WINDOWS_CONTROL_TOKEN).toBe("a".repeat(64))
  })

  test("probe requires the native LPAC protocol and never labels it as Linux full", async () => {
    expect(await probeWindowsSandbox(sandbox, async () => JSON.stringify({ version: 1, backend: "windows-lpac", available: true })))
      .toEqual({ available: true })
    for (const output of ["not JSON", '{"available":true}', '{"version":1,"backend":"windows-lpac","available":false}']) {
      expect((await probeWindowsSandbox(sandbox, async () => output)).available).toBe(false)
    }
    expect((await probeWindowsSandbox(sandbox, async () => { throw new Error("sensitive diagnostic") })).reason)
      .not.toContain("sensitive diagnostic")
    expect(await probeWindowsSandbox(sandbox, async () => JSON.stringify({
      version: 1, backend: "windows-lpac", available: false, contractFailure: true,
    }))).toMatchObject({ available: false, contractFailure: true })
  })
})

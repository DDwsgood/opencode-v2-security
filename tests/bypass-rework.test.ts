import { describe, expect, test } from "bun:test"
import { BYPASS_CATEGORIES, resolvePluginConfig, resolveSandbox } from "../src/config"
import { buildSandboxSpawn, type SandboxSelection } from "../src/sandbox"

// Kept from the original bypass-rework suite: the pure config-level
// contracts. The plugin-harness behavioral cases (kill switch, /perm bit
// syntax, slow/sandbox routing) belonged to the pre-boundary pipeline and
// their harness predates the native tool wrapper; the current semantics are
// covered by tests/mode-command.test.ts and tests/security-modes.test.ts.

describe("config: BYPASS_CATEGORIES + BypassClassifier validation", () => {
  test("BYPASS_CATEGORIES is the canonical 10-entry list", () => {
    expect([...BYPASS_CATEGORIES]).toEqual([
      "filesystem", "host", "privilege", "secret", "network", "remote", "indirection", "dynamic", "sandbox", "slow",
    ])
  })

  test('"all"/"ALL" and "*" are rejected as permanent config entries', () => {
    expect(() => resolvePluginConfig({ BypassClassifier: ["all"] as never })).toThrow(/session-only/)
    expect(() => resolvePluginConfig({ BypassClassifier: ["ALL"] as never })).toThrow(/session-only/)
    expect(() => resolvePluginConfig({ BypassClassifier: ["*"] as never })).toThrow(/session-only/)
  })

  test("new categories are accepted as permanent config entries", () => {
    const resolved = resolvePluginConfig({ BypassClassifier: ["sandbox", "slow"] })
    expect(resolved.bypassClassifier.has("sandbox")).toBe(true)
    expect(resolved.bypassClassifier.has("slow")).toBe(true)
  })
})

describe("sandbox config keys (schema + env plumbing)", () => {
  test("new keys have the documented defaults", () => {
    const s = resolveSandbox(undefined)
    expect(s.denyWrite).toEqual([])
    expect(s.denyRead).toEqual([])
    expect(s.rwNetwork).toBe("on")
    expect(s.allowSudo).toBe(false)
    expect(s.extraArgs).toEqual([])
  })

  test("valid forms resolve and normalize", () => {
    const s = resolveSandbox({
      denyWrite: ["/etc//shadow", "/var/lib"],
      denyRead: ["/home/user/.aws", "/etc/shadow"],
      rwNetwork: "off",
      allowSudo: true,
      extraArgs: ["--tmpfs", "/run/x", "--setenv", "K", "v"],
    })
    expect(s.denyWrite).toEqual(["/etc/shadow", "/var/lib"])
    expect(s.denyRead).toEqual(["/home/user/.aws", "/etc/shadow"])
    expect(s.rwNetwork).toBe("off")
    expect(s.allowSudo).toBe(true)
    expect(s.extraArgs).toEqual(["--tmpfs", "/run/x", "--setenv", "K", "v"])
    // The same path in both lists is allowed by contract.
    expect(() => resolveSandbox({ denyWrite: ["/x"], denyRead: ["/x"] })).not.toThrow()
  })

  test("invalid entries are rejected", () => {
    const invalid: Array<Record<string, unknown>> = [
      { denyWrite: "not-array" },
      { denyWrite: ["relative/path"] },
      { denyWrite: [""] },
      { denyWrite: ["/has:colon"] },
      { denyWrite: ["/"] },
      { denyWrite: ["/tmp"] }, // default scratch
      { denyWrite: ["/a/../b"] },
      { denyRead: ["relative"] },
      { denyRead: ["/tmp/"] }, // normalizes to scratch
      { denyRead: ["/"] },
      { denyRead: ["/x/../y"] },
      { rwNetwork: "maybe" },
      { rwNetwork: true },
      { allowSudo: "yes" },
      { extraArgs: "not-array" },
      { extraArgs: [""] },
      { extraArgs: ["--bind\n--tmpfs /etc"] }, // newline breaks the env encoding
      { extraArgs: [42] },
    ]
    for (const sandbox of invalid) {
      expect(() => resolveSandbox(sandbox)).toThrow()
    }
    // Custom scratch relocates the reserved path.
    const s = resolveSandbox({ scratch: "/var/tmp/scratch", denyWrite: ["/tmp/opencode"] })
    expect(s.denyWrite).toEqual(["/tmp/opencode"])
    expect(() => resolveSandbox({ scratch: "/var/tmp/scratch", denyRead: ["/var/tmp/scratch"] })).toThrow()
  })

  test("buildSandboxSpawn emits the env contract verbatim (both profiles)", () => {
    const sel = (overrides: Partial<SandboxSelection> = {}): SandboxSelection => ({
      enabled: true,
      mode: "auto",
      bwrapPath: "/usr/bin/bwrap",
      helperPath: "/pkg/bin/opencode-sandbox",
      scratch: "/tmp/opencode",
      roNetwork: "off",
      rwNetwork: "on",
      denyWrite: [],
      denyRead: [],
      allowSudo: false,
      extraArgs: [],
      maskWslInterop: true,
      maskPrivilegedSockets: [],
      roAfUnixBlock: true,
      onUnavailable: "fail_close",
      ...overrides,
    })

    for (const profile of ["ro", "rw"] as const) {
      const spec = buildSandboxSpawn(profile, sel(), () => false)
      expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("")
      expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("")
      expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("1")
      expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
      expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("")
    }

    const spec = buildSandboxSpawn(
      "rw",
      sel({
        denyWrite: ["/a", "/b/c"],
        denyRead: ["/d"],
        rwNetwork: "off",
        allowSudo: true,
        extraArgs: ["--setenv", "K", "yes", "--tmpfs", "/t"],
      }),
      () => false,
    )
    expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("/a:/b/c")
    expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("/d")
    expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("0")
    expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
    // One argv element per line; joined verbatim (no re-quoting).
    expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("--setenv\nK\nyes\n--tmpfs\n/t")
  })
})

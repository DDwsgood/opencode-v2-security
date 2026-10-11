import { describe, expect, test } from "bun:test"
import path from "node:path"
import { resolvePluginConfig, resolveSandbox } from "../src/config"
import {
  applySandboxCreateBefore,
  assertSandboxAvailable,
  buildSandboxSpawn,
  createSandboxMarkers,
  extractSandboxMarker,
  insertSandboxMarker,
  normalizeWriteRoots,
  parseSandboxProbe,
  probeLinuxSandbox,
  profileForPerm,
  sandboxDenyCommand,
  sandboxUnavailableMessage,
  stripSandboxMarker,
  wrapShellForSandbox,
  type SandboxProbeResult,
  type SandboxSelection,
} from "../src/sandbox"
import { PERM_FULL, type Perm } from "../src/permissions"

const perm = (r: boolean, w: boolean, x = false): Perm => ({ r, w, x })

const selection = (overrides: Partial<SandboxSelection> = {}): SandboxSelection => ({
  enabled: true,
  mode: "auto",
  bwrapPath: "/usr/bin/bwrap",
  helperPath: "/pkg/bin/opencode-sandbox",
  scratch: "/tmp/opencode",
  roNetwork: "off",
  rwNetwork: "on",
  workspaceNetwork: "off",
  denyWrite: [],
  denyRead: [],
  allowSudo: false,
  extraArgs: [],
  maskWslInterop: true,
  maskPrivilegedSockets: ["/run/docker.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock"],
  roAfUnixBlock: true,
  onUnavailable: "fail_close",
  ...overrides,
})

describe("sandbox config resolution", () => {
  test("defaults match the §4.2 table", () => {
    const sandbox = resolveSandbox(undefined)
    expect(sandbox.enabled).toBe(process.platform === "linux")
    expect(sandbox.mode).toBe("auto")
    expect(sandbox.bwrapPath).toBe("/usr/bin/bwrap")
    expect(sandbox.helperPath.endsWith(path.join("bin", "opencode-sandbox"))).toBe(true)
    expect(sandbox.scratch).toBe("/tmp")
    expect(sandbox.roNetwork).toBe("off")
    expect(sandbox.maskWslInterop).toBe(true)
    expect(sandbox.maskPrivilegedSockets).toEqual([
      "/run/docker.sock",
      "/run/podman/podman.sock",
      "/run/containerd/containerd.sock",
    ])
    expect(sandbox.roAfUnixBlock).toBe(true)
    expect(sandbox.workspaceNetwork).toBe("off")
    expect(sandbox.onUnavailable).toBe("fail_close")
  })

  test("workspace mode and workspaceNetwork resolve; invalid values reject", () => {
    expect(resolveSandbox({ mode: "workspace" }).mode).toBe("workspace")
    expect(resolveSandbox({ workspaceNetwork: "on" }).workspaceNetwork).toBe("on")
    expect(resolveSandbox({ workspaceNetwork: "off" }).workspaceNetwork).toBe("off")
    expect(() => resolveSandbox({ mode: "ww" })).toThrow()
    expect(() => resolveSandbox({ workspaceNetwork: "yes" })).toThrow()
  })

  test("resolvePluginConfig surfaces sandbox and accepts the top-level key", () => {
    const resolved = resolvePluginConfig({ sandbox: { mode: "rw", onUnavailable: "degrade" } })
    expect(resolved.sandbox.mode).toBe("rw")
    expect(resolved.sandbox.onUnavailable).toBe("degrade")
    expect(resolved.sandbox.scratch).toBe("/tmp")
  })

  test("rejects unknown sandbox keys and invalid types/values", () => {
    const invalid: Array<Record<string, unknown>> = [
      { nope: true },
      { enabled: "yes" },
      { mode: "strict" },
      { mode: 4 },
      { bwrapPath: "" },
      { bwrapPath: 42 },
      { bwrapPath: "rel/dir/bwrap" },
      { helperPath: 7 },
      { scratch: "relative/path" },
      { scratch: "/" },
      { scratch: "/home" },
      { scratch: "/root" },
      { scratch: "/a/../b" },
      { scratch: 0 },
      { roNetwork: "sometimes" },
      { maskWslInterop: "true" },
      { maskPrivilegedSockets: "/run/docker.sock" },
      { maskPrivilegedSockets: ["relative.sock"] },
      { maskPrivilegedSockets: ["/ok.sock", 3] },
      { roAfUnixBlock: 1 },
      { onUnavailable: "fail_open" },
      { rwNetwork: "sometimes" },
      { allowSudo: "yes" },
      { extraArgs: "not-an-array" },
    ]
    for (const sandbox of invalid) {
      expect(() => resolveSandbox(sandbox)).toThrow()
    }
  })

  test("extraArgs rejects transport-breaking and parsing-breaking elements", () => {
    expect(() => resolveSandbox({ extraArgs: ["--setenv\nX\nY"] })).toThrow(/newline/)
    expect(() => resolveSandbox({ extraArgs: ["a\0b"] })).toThrow()
    expect(() => resolveSandbox({ extraArgs: ["--"] })).toThrow()
    expect(() => resolveSandbox({ extraArgs: [""] })).toThrow()
    expect(() => resolveSandbox({ extraArgs: ["   "] })).toThrow()
    expect(() => resolveSandbox({ extraArgs: ["x".repeat(65 * 1024)] })).toThrow(/64KB/)
    expect(() => resolveSandbox({ extraArgs: ["a".repeat(40 * 1024), "b".repeat(40 * 1024)] })).toThrow(
      /64KB/,
    )
    // valid list survives verbatim
    expect(resolveSandbox({ extraArgs: ["--tmpfs", "/x", "--setenv", "K", "V"] }).extraArgs).toEqual([
      "--tmpfs",
      "/x",
      "--setenv",
      "K",
      "V",
    ])
  })

  test("rejects non-object sandbox", () => {
    expect(() => resolveSandbox("on")).toThrow()
    expect(() => resolvePluginConfig({ sandbox: [] } as never)).toThrow()
  })

  test("accepts valid overrides incl. bare bwrap name and helper override", () => {
    const sandbox = resolveSandbox({
      enabled: false,
      mode: "full",
      bwrapPath: "bwrap",
      helperPath: "/opt/sbx",
      scratch: "/var/tmp/opencode-scratch",
      roNetwork: "on",
      maskWslInterop: false,
      maskPrivilegedSockets: [],
      roAfUnixBlock: false,
      onUnavailable: "degrade",
    })
    expect(sandbox.enabled).toBe(false)
    expect(sandbox.mode).toBe("full")
    expect(sandbox.bwrapPath).toBe("bwrap")
    expect(sandbox.helperPath).toBe("/opt/sbx")
    expect(sandbox.scratch).toBe("/var/tmp/opencode-scratch")
    expect(sandbox.roNetwork).toBe("on")
    expect(sandbox.maskWslInterop).toBe(false)
    expect(sandbox.maskPrivilegedSockets).toEqual([])
    expect(sandbox.roAfUnixBlock).toBe(false)
    expect(sandbox.onUnavailable).toBe("degrade")
  })

  test("top-level whitelist still rejects unrelated keys", () => {
    expect(() => resolvePluginConfig({ sandbox2: {} } as never)).toThrow(/unknown option/)
  })
})

describe("profileForPerm", () => {
  test("auto mode maps perm.w=false → ro, w=true → workspace", () => {
    const auto = selection()
    expect(profileForPerm(perm(true, false), auto)).toBe("ro")
    expect(profileForPerm(perm(false, false), auto)).toBe("ro")
    expect(profileForPerm(perm(true, true), auto)).toBe("workspace")
    expect(profileForPerm(PERM_FULL, auto)).toBe("workspace")
  })

  test("forced modes override the perm mapping", () => {
    expect(profileForPerm(perm(true, true), selection({ mode: "ro" }))).toBe("ro")
    expect(profileForPerm(perm(true, false), selection({ mode: "rw" }))).toBe("rw")
    expect(profileForPerm(perm(true, true), selection({ mode: "workspace" }))).toBe("workspace")
    expect(profileForPerm(perm(true, true), selection({ mode: "full" }))).toBe("full")
    expect(profileForPerm(perm(true, false), selection({ mode: "full" }))).toBe("full")
  })

  test("disabled sandbox always yields full", () => {
    expect(profileForPerm(perm(true, false), selection({ enabled: false }))).toBe("full")
    expect(profileForPerm(perm(true, true), selection({ enabled: false }))).toBe("full")
  })
})

describe("sandbox markers", () => {
  const NONCE = "0123456789abcdef0123456789abcdef"

  test("round-trips arbitrary command text", () => {
    const markers = createSandboxMarkers()
    const commands = [
      "ls -la",
      "echo 'it'\\''s $HOME'; rm -rf /tmp/x\nsecond line",
      "printf '非 ASCII 字符\\n'; echo `date` && false",
      "\n\nleading newlines",
      "",
    ]
    for (const command of commands) {
      const marked = insertSandboxMarker(markers, command, "ro", NONCE)
      expect(marked.startsWith(`: opencode-sandbox ${NONCE}\n`)).toBe(true)
      const extracted = extractSandboxMarker(markers, marked)
      expect(extracted.profile).toBe("ro")
      expect(extracted.command).toBe(command)
    }
  })

  test("marker is consumed once; replay is invalid, not bare", () => {
    const markers = createSandboxMarkers()
    const marked = insertSandboxMarker(markers, "ls", "rw", NONCE)
    expect(extractSandboxMarker(markers, marked).profile).toBe("rw")
    const replay = extractSandboxMarker(markers, marked)
    expect(replay.profile).toBeUndefined()
    expect(replay.invalid).toBe(true)
    expect(replay.command).toBe(marked)
  })

  test("unknown/stale marker is invalid (deny), command untouched", () => {
    const markers = createSandboxMarkers()
    const forged = ": opencode-sandbox deadbeefdeadbeefdeadbeefdeadbeef\nls"
    const result = extractSandboxMarker(markers, forged)
    expect(result.profile).toBeUndefined()
    expect(result.invalid).toBe(true)
    expect(result.command).toBe(forged)
  })

  test("expired marker is invalid (deny), command untouched", () => {
    const markers = createSandboxMarkers()
    const marked = insertSandboxMarker(markers, "ls", "ro", NONCE, 1000)
    const result = extractSandboxMarker(markers, marked, 1000 + 60_001)
    expect(result.profile).toBeUndefined()
    expect(result.invalid).toBe(true)
    expect(result.command).toBe(marked)
  })

  test("a marker line only counts at the very first line", () => {
    const markers = createSandboxMarkers()
    insertSandboxMarker(markers, "x", "ro", NONCE)
    // A marker-looking line after the first line is part of the command.
    const embedded = `echo hi\n: opencode-sandbox ${NONCE}\nls`
    const result = extractSandboxMarker(markers, embedded)
    expect(result.profile).toBeUndefined()
    expect(result.command).toBe(embedded)
    // The nonce was never consumed by the embedded line.
    const marked = insertSandboxMarker(markers, "ls", "ro", NONCE)
    expect(extractSandboxMarker(markers, marked).profile).toBe("ro")
  })

  test("stripSandboxMarker removes exactly one leading marker line", () => {
    expect(stripSandboxMarker(`: opencode-sandbox ${NONCE}\nls`)).toBe("ls")
    expect(stripSandboxMarker(`: opencode-sandbox ${NONCE}\n: opencode-sandbox ${NONCE}\nls`)).toBe(
      `: opencode-sandbox ${NONCE}\nls`,
    )
    expect(stripSandboxMarker("ls\n: opencode-sandbox 0123456789abcdef0123456789abcdef")).toBe(
      "ls\n: opencode-sandbox 0123456789abcdef0123456789abcdef",
    )
    expect(stripSandboxMarker("ls")).toBe("ls")
  })
})

describe("create.before authority (marker is the sole wrap source)", () => {
  const NONCE = "0123456789abcdef0123456789abcdef"
  const available: SandboxProbeResult = { available: true, path: "full" }
  const unavailable: SandboxProbeResult = { available: false, reason: "bwrap: not found" }
  const spawn = () => ({
    command: "",
    cwd: "/w",
    timeout: 0,
    shell: "/bin/bash",
    env: { PATH: "/usr/bin" } as Record<string, string | undefined>,
  })

  test("marker-less spawn (user !cmd) is left byte-identical", () => {
    const ev = spawn()
    ev.command = "rm -rf / --no-preserve-root"
    const before = { shell: ev.shell, command: ev.command, env: { ...ev.env } }
    const marked = extractSandboxMarker(createSandboxMarkers(), ev.command)
    expect(marked.profile).toBeUndefined()
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.shell).toBe(before.shell)
    expect(ev.command).toBe(before.command)
    expect(ev.env).toEqual(before.env)
  })

  test("marker-less spawn is untouched even when the probe is unavailable", () => {
    const ev = spawn()
    ev.command = "ls"
    const marked = extractSandboxMarker(createSandboxMarkers(), ev.command)
    applySandboxCreateBefore(ev, marked, selection(), unavailable)
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.command).toBe("ls")
    expect(ev.env).toEqual({ PATH: "/usr/bin" })
  })

  test("marker present → stripped and wrapped per profile", () => {
    const markers = createSandboxMarkers()
    const marked_cmd = insertSandboxMarker(markers, "make build", "rw", NONCE)
    const ev = spawn()
    ev.command = marked_cmd
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.command).toBe("make build")
    expect(ev.shell).toBe("/pkg/bin/opencode-sandbox")
    expect(ev.env.OPENCODE_REAL_BASH).toBe("/bin/bash")
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
  })

  test('explicit "full" marker → stripped, untouched (bypass carrier)', () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "deploy", "full", NONCE)
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.command).toBe("deploy")
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.env).toEqual({ PATH: "/usr/bin" })
  })

  test("TTL-expired marker is denied (exit 126), never run bare", () => {
    const markers = createSandboxMarkers()
    const marked_cmd = insertSandboxMarker(markers, "ls", "ro", NONCE, 1000)
    const ev = spawn()
    ev.command = marked_cmd
    const marked = extractSandboxMarker(markers, ev.command, 1000 + 60_001)
    expect(marked.profile).toBeUndefined()
    expect(marked.invalid).toBe(true)
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.command).toContain("exit 126")
    expect(ev.command).toContain("security authorization for this call is invalid")
  })

  test("unknown (forged) marker is denied, not run bare", () => {
    const ev = spawn()
    ev.command = `: opencode-sandbox ${"f".repeat(32)}\nls`
    const marked = extractSandboxMarker(createSandboxMarkers(), ev.command)
    expect(marked.invalid).toBe(true)
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.command).toContain("exit 126")
  })

  test("fail_close exit-126 rewrite applies only to marker-present spawns", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "make", "rw", NONCE)
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection(), unavailable)
    expect(ev.shell).toBe("/bin/bash") // no wrap
    expect(ev.command).toContain("exit 126")
    expect(ev.command).toContain("sandbox is not available")
    // State a pre-execution block without permission-elevation or manual
    // installation guidance; a native read tool remains available.
    expect(ev.command).toContain("The whole command was not run.")
    expect(ev.command).not.toContain("install bubblewrap")
    expect(ev.command).not.toContain("Install bubblewrap")
  })

  test("degrade leaves marker-present spawn untouched when unavailable", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "make", "rw", NONCE)
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection({ onUnavailable: "degrade" }), unavailable)
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.command).toBe("make")
  })

  // rw+allowSudo host-direct: the spawn still goes through the helper (which
  // owns the routing) even when the probe is unavailable — never a bare-shell
  // fallback and never the exit-126 deny.
  test("rw + allowSudo wraps host-direct even with unavailable probe", () => {
    for (const probe of [unavailable, undefined, available] as const) {
      const markers = createSandboxMarkers()
      const ev = spawn()
      ev.command = insertSandboxMarker(markers, "sudo -n true", "rw", NONCE)
      const marked = extractSandboxMarker(markers, ev.command)
      applySandboxCreateBefore(ev, marked, selection({ allowSudo: true }), probe)
      expect(ev.shell).toBe("/pkg/bin/opencode-sandbox")
      expect(ev.command).toBe("sudo -n true")
      expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
      expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
      expect(ev.env.OPENCODE_REAL_BASH).toBe("/bin/bash")
    }
  })

  test("ro + allowSudo keeps the fail_close deny; helper not bypassed", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "ls", "ro", NONCE)
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection({ allowSudo: true }), unavailable)
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.command).toContain("exit 126")
  })

  test("workspace marker wraps with WRITE_ROOTS and WORKSPACE_NETWORK env", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "make build", "workspace", NONCE, undefined, {
      writeRoots: ["/repo/app", "/repo/app/sub/"], // subsumed entry dropped
    })
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.command).toBe("make build")
    expect(ev.shell).toBe("/pkg/bin/opencode-sandbox")
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("workspace")
    expect(ev.env.OPENCODE_SANDBOX_WRITE_ROOTS).toBe("/repo/app")
    expect(ev.env.OPENCODE_SANDBOX_WORKSPACE_NETWORK).toBe("0")
    expect(ev.env.OPENCODE_SANDBOX_MASK_WSL_INTEROP).toBe("1")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
    expect(ev.env.OPENCODE_SANDBOX_RO_NETWORK).toBeUndefined()
    expect(ev.env.OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK).toBeUndefined()
  })

  test("workspace: per-call network capability sets WORKSPACE_NETWORK=1", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "npm install", "workspace", NONCE, undefined, {
      network: true,
    })
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection(), available)
    expect(ev.env.OPENCODE_SANDBOX_WORKSPACE_NETWORK).toBe("1")
  })

  test("workspace: config workspaceNetwork=on also grants network", () => {
    const spec = buildSandboxSpawn("workspace", selection({ workspaceNetwork: "on" }), () => true)
    expect(spec.env.OPENCODE_SANDBOX_WORKSPACE_NETWORK).toBe("1")
  })

  test("workspace: hostDirect marker does not take the host-direct route", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "sudo -n true", "workspace", NONCE, undefined, {
      hostDirect: true,
    })
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(ev, marked, selection({ allowSudo: false }), available)
    // Still wrapped through the helper as a normal workspace spawn — never
    // host-direct, never ALLOW_SUDO.
    expect(ev.shell).toBe("/pkg/bin/opencode-sandbox")
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("workspace")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
  })

  test("workspace + landlock-only probe is refused (exit 126) regardless of degrade", () => {
    for (const onUnavailable of ["fail_close", "degrade"] as const) {
      const markers = createSandboxMarkers()
      const ev = spawn()
      ev.command = insertSandboxMarker(markers, "make", "workspace", NONCE)
      const marked = extractSandboxMarker(markers, ev.command)
      applySandboxCreateBefore(
        ev,
        marked,
        selection({ onUnavailable }),
        { available: true, path: "landlock-only", landlockAbi: 5 },
      )
      expect(ev.shell).toBe("/bin/bash")
      expect(ev.command).toContain("exit 126")
      expect(ev.command).toContain("available OS sandbox backend cannot enforce")
      expect(ev.command).toContain("The whole command was not run.")
    }
  })

  test("workspace + unavailable probe is denied even under degrade", () => {
    for (const onUnavailable of ["fail_close", "degrade"] as const) {
      const markers = createSandboxMarkers()
      const ev = spawn()
      ev.command = insertSandboxMarker(markers, "make", "workspace", NONCE)
      const marked = extractSandboxMarker(markers, ev.command)
      applySandboxCreateBefore(ev, marked, selection({ onUnavailable }), unavailable)
      expect(ev.shell).toBe("/bin/bash")
      expect(ev.command).toContain("exit 126")
      expect(ev.command).toContain("sandbox is not available")
    }
  })

  test("workspace refuses a configured extraArgs (could shadow the floor)", () => {
    const markers = createSandboxMarkers()
    const ev = spawn()
    ev.command = insertSandboxMarker(markers, "make", "workspace", NONCE)
    const marked = extractSandboxMarker(markers, ev.command)
    applySandboxCreateBefore(
      ev,
      marked,
      selection({ extraArgs: ["--bind", "/x", "/x"] }),
      available,
    )
    expect(ev.shell).toBe("/bin/bash")
    expect(ev.command).toContain("exit 126")
    expect(ev.command).toContain("configured extra sandbox options are not supported")
    expect(ev.command).toContain("The whole command was not run.")
  })

  test("workspace + full/bwrap-only probe wraps normally", () => {
    for (const path of ["full", "bwrap-only"] as const) {
      const markers = createSandboxMarkers()
      const ev = spawn()
      ev.command = insertSandboxMarker(markers, "make", "workspace", NONCE)
      const marked = extractSandboxMarker(markers, ev.command)
      applySandboxCreateBefore(ev, marked, selection(), { available: true, path })
      expect(ev.shell).toBe("/pkg/bin/opencode-sandbox")
      expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("workspace")
    }
  })
})

describe("spawn env construction (helper contract)", () => {
  test("RO sets mode=ro plus the RO-only toggles and socket masks", () => {
    const spec = buildSandboxSpawn("ro", selection(), () => true)
    expect(spec.helperPath).toBe("/pkg/bin/opencode-sandbox")
    expect(spec.env.OPENCODE_SANDBOX_MODE).toBe("ro")
    expect(spec.env.OPENCODE_SANDBOX_SCRATCH).toBe("/tmp/opencode")
    expect(spec.env.OPENCODE_SANDBOX_BWRAP).toBe("/usr/bin/bwrap")
    expect(spec.env.OPENCODE_SANDBOX_HELPER).toBe("/pkg/bin/opencode-sandbox")
    expect(spec.env.OPENCODE_SANDBOX_RO_NETWORK).toBe("off")
    expect(spec.env.OPENCODE_SANDBOX_MASK_WSL_INTEROP).toBe("1")
    expect(spec.env.OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK).toBe("1")
    expect(spec.env.OPENCODE_SANDBOX_MASK_SOCKETS).toBe(
      "/run/docker.sock:/run/podman/podman.sock:/run/containerd/containerd.sock",
    )
    expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("")
    expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("")
    expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("1")
    expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
    expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("")
  })

  test("RW sets mode=rw and none of the RO-only toggles", () => {
    const spec = buildSandboxSpawn("rw", selection(), () => true)
    expect(spec.env.OPENCODE_SANDBOX_MODE).toBe("rw")
    expect(spec.env.OPENCODE_SANDBOX_RO_NETWORK).toBeUndefined()
    expect(spec.env.OPENCODE_SANDBOX_MASK_WSL_INTEROP).toBeUndefined()
    expect(spec.env.OPENCODE_SANDBOX_RO_AF_UNIX_BLOCK).toBeUndefined()
    expect(spec.env.OPENCODE_SANDBOX_MASK_SOCKETS).toContain("/run/docker.sock")
    expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("")
    expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("")
    expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("1")
    expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
    expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("")
  })

  test("deny lists colon-join; rwNetwork/allowSudo map to 1/0; extraArgs newline-join", () => {
    const spec = buildSandboxSpawn(
      "rw",
      selection({
        denyWrite: ["/etc/secrets", "/var/db"],
        denyRead: ["/home/x/.gnupg"],
        rwNetwork: "off",
        allowSudo: true,
        extraArgs: ["--tmpfs", "/tmp/private", "--ro-bind", "/a", "/a"],
      }),
      () => true,
    )
    expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("/etc/secrets:/var/db")
    expect(spec.env.OPENCODE_SANDBOX_DENY_READ).toBe("/home/x/.gnupg")
    expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("0")
    expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
    expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("--tmpfs\n/tmp/private\n--ro-bind\n/a\n/a")
  })

  test("roNetwork=on propagates; socket masks drop nonexistent paths", () => {
    const spec = buildSandboxSpawn(
      "ro",
      selection({ roNetwork: "on" }),
      (p) => p === "/run/docker.sock",
    )
    expect(spec.env.OPENCODE_SANDBOX_RO_NETWORK).toBe("on")
    expect(spec.env.OPENCODE_SANDBOX_MASK_SOCKETS).toBe("/run/docker.sock")
    expect(spec.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("")
    expect(spec.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("1")
    expect(spec.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
    expect(spec.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("")
  })

  test("wrapShellForSandbox rewrites shell and captures the real shell", () => {
    const ev = { shell: "/bin/bash", env: { PATH: "/usr/bin" } as Record<string, string | undefined> }
    wrapShellForSandbox(ev, "rw", selection(), () => true)
    expect(ev.shell).toBe("/pkg/bin/opencode-sandbox")
    expect(ev.env.OPENCODE_REAL_BASH).toBe("/bin/bash")
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
    expect(ev.env.PATH).toBe("/usr/bin")
    expect(ev.env.OPENCODE_SANDBOX_DENY_WRITE).toBe("")
    expect(ev.env.OPENCODE_SANDBOX_DENY_READ).toBe("")
    expect(ev.env.OPENCODE_SANDBOX_RW_NETWORK).toBe("1")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("0")
    expect(ev.env.OPENCODE_SANDBOX_EXTRA_ARGS).toBe("")
  })

  test("wrapShellForSandbox leaves full profiles untouched", () => {
    const ev = { shell: "/bin/bash", env: {} as Record<string, string | undefined> }
    wrapShellForSandbox(ev, "full", selection())
    expect(ev.shell).toBe("/bin/bash")
    expect(Object.keys(ev.env)).toEqual([])
  })

  test("normalizeWriteRoots: validation, subsumption, dir-intent slash", () => {
    expect(normalizeWriteRoots(undefined, "/tmp")).toEqual([])
    expect(normalizeWriteRoots(["/a", "/a/b", "/tmp/x", "/a/"], "/tmp")).toEqual(["/a"])
    expect(normalizeWriteRoots(["/newdir/"], "/tmp")).toEqual(["/newdir/"])
    expect(() => normalizeWriteRoots(["/f/../f2"], "/tmp")).toThrow()
    expect(() => normalizeWriteRoots(["/"], "/tmp")).toThrow()
    expect(() => normalizeWriteRoots(["relative"], "/tmp")).toThrow()
    expect(() => normalizeWriteRoots(["/a:b"], "/tmp")).toThrow()
    expect(() => normalizeWriteRoots(["/a\nb"], "/tmp")).toThrow()
    expect(() => normalizeWriteRoots([""], "/tmp")).toThrow()
    expect(() =>
      normalizeWriteRoots(Array.from({ length: 65 }, (_, i) => `/r${i}`), "/tmp"),
    ).toThrow(/at most/)
  })
})

describe("probe decision table (§3.4)", () => {
  const probeOutput = (bwrap: string, userns: string, abi: number, path: string) =>
    `bwrap: ${bwrap}\nuserns: ${userns}\nlandlock_abi: ${abi}\nsandbox_path: ${path}\nmode: rw  scratch: /tmp/opencode  real_bash: /bin/bash\n`

  test("full route: bwrap + userns + ABI >= 3", () => {
    const parsed = parseSandboxProbe(probeOutput("/usr/bin/bwrap", "yes", 7, "full"))
    expect(parsed.path).toBe("full")
    expect(parsed.bwrap).toBe("/usr/bin/bwrap")
    expect(parsed.userns).toBe(true)
    expect(parsed.landlockAbi).toBe(7)
    expect(parsed.reason).toBeUndefined()
  })

  test("bwrap-only route: bwrap + userns, no Landlock", () => {
    const parsed = parseSandboxProbe(probeOutput("/usr/bin/bwrap", "yes", 0, "bwrap-only"))
    expect(parsed.path).toBe("bwrap-only")
    expect(parsed.reason).toBeUndefined()
  })

  test("landlock-only route: no bwrap/userns, ABI >= 3", () => {
    const parsed = parseSandboxProbe(probeOutput("not found", "no", 5, "landlock-only"))
    expect(parsed.path).toBe("landlock-only")
    expect(parsed.bwrap).toBeUndefined()
    expect(parsed.userns).toBe(false)
  })

  test("unavailable route reports a sanitized reason", () => {
    const parsed = parseSandboxProbe(probeOutput("not found", "no", 0, "unavailable"))
    expect(parsed.path).toBe("unavailable")
    expect(parsed.reason).toMatch(/bwrap: not found/)
    expect(parsed.reason).toMatch(/Landlock: unavailable/)
  })

  test("garbage output reports unavailable", () => {
    const parsed = parseSandboxProbe("not a probe\n")
    expect(parsed.path).toBeUndefined()
    expect(parsed.reason).toMatch(/bwrap: not found/)
  })

  test("probeLinuxSandbox maps probe output to availability", async () => {
    const result = await probeLinuxSandbox(selection(), async () =>
      probeOutput("/usr/bin/bwrap", "yes", 7, "full"),
    )
    expect(result.available).toBe(true)
    expect(result.path).toBe("full")

    const unavailable = await probeLinuxSandbox(selection(), async () =>
      probeOutput("not found", "no", 0, "unavailable"),
    )
    expect(unavailable.available).toBe(false)
    expect(unavailable.reason).toBeDefined()

    const spawnError = await probeLinuxSandbox(selection(), async () => {
      throw new Error("spawn /missing ENOENT")
    })
    expect(spawnError.available).toBe(false)
    expect(spawnError.reason).toMatch(/helper probe failed/)
  })
})

describe("assertSandboxAvailable", () => {
  const unavailable = { available: false, reason: "bwrap: not found, Landlock: unavailable" }
  const available = { available: true as const, path: "full" as const }

  test("full profile never gates", () => {
    expect(assertSandboxAvailable("full", unavailable, "fail_close")).toBe("ok")
    expect(assertSandboxAvailable("full", undefined, "fail_close")).toBe("ok")
  })

  test("available probe passes ro/rw", () => {
    expect(assertSandboxAvailable("ro", available, "fail_close")).toBe("ok")
    expect(assertSandboxAvailable("rw", available, "degrade")).toBe("ok")
  })

  test("fail_close throws the §4.3 message; degrade reports degraded", () => {
    expect(() => assertSandboxAvailable("ro", unavailable, "fail_close")).toThrow(
      /Command blocked:.*sandbox is not available.*The whole command was not run/,
    )
    expect(assertSandboxAvailable("ro", unavailable, "degrade")).toBe("degraded")
    expect(() => assertSandboxAvailable("rw", undefined, "fail_close")).toThrow(/sandbox is not available/)
  })

  // rw+allowSudo selects the helper's host-direct route, which needs no
  // bwrap/Landlock: the availability gate must not deny it when the probe is
  // unavailable. RO ignores allowSudo and stays fail-close.
  test("rw + allowSudo is ok without a usable probe (host-direct route)", () => {
    expect(assertSandboxAvailable("rw", unavailable, "fail_close", true)).toBe("ok")
    expect(assertSandboxAvailable("rw", undefined, "fail_close", true)).toBe("ok")
    expect(assertSandboxAvailable("rw", available, "fail_close", true)).toBe("ok")
  })

  test("ro + allowSudo still fail-closes; rw + !allowSudo unaffected", () => {
    expect(() => assertSandboxAvailable("ro", unavailable, "fail_close", true)).toThrow(
      /sandbox is not available/,
    )
    expect(() => assertSandboxAvailable("ro", undefined, "fail_close", true)).toThrow(
      /sandbox is not available/,
    )
    expect(() => assertSandboxAvailable("rw", unavailable, "fail_close", false)).toThrow(
      /sandbox is not available/,
    )
    expect(() => assertSandboxAvailable("rw", unavailable, "fail_close")).toThrow(/sandbox is not available/)
  })

  test("workspace: landlock-only probe throws even under degrade; bwrap paths pass", () => {
    const landlockOnly = { available: true as const, path: "landlock-only" as const }
    expect(() => assertSandboxAvailable("workspace", landlockOnly, "fail_close")).toThrow(
      /requested OS sandbox profile cannot be enforced/,
    )
    expect(() => assertSandboxAvailable("workspace", landlockOnly, "degrade")).toThrow(
      /requested OS sandbox profile cannot be enforced/,
    )
    expect(assertSandboxAvailable("workspace", available, "fail_close")).toBe("ok")
    expect(
      assertSandboxAvailable("workspace", { available: true, path: "bwrap-only" }, "fail_close"),
    ).toBe("ok")
    // An unavailable probe must not degrade to a bare spawn either.
    expect(() => assertSandboxAvailable("workspace", unavailable, "degrade")).toThrow(
      /sandbox is not available/,
    )
    expect(() => assertSandboxAvailable("workspace", undefined, "degrade")).toThrow(
      /sandbox is not available/,
    )
  })
})

describe("fail modes", () => {
  test("§4.3 message shape", () => {
    const message = sandboxUnavailableMessage("bwrap: not found, Landlock: unavailable")
    expect(message).toStartWith("Command blocked:")
    expect(message).toContain("sandbox is not available")
    expect(message).toContain("The whole command was not run.")
    expect(message).toContain("Native file read tools still work.")
    expect(message).not.toContain("sandbox.onUnavailable")
    expect(message).not.toContain("install bubblewrap")
  })

  test("deny command exits 126 and prints the exact message (embedded quotes survive)", () => {
    const message = sandboxUnavailableMessage("x")
    const command = sandboxDenyCommand(message)
    expect(command).toContain("exit 126")
    // Semantic check, not quoting trivia: run it in a real bash.
    const result = Bun.spawnSync(["bash", "-c", command])
    expect(result.exitCode).toBe(126)
    expect(result.stderr.toString().trim()).toBe(message)
  })
})

describe("runtime watch deferred-hook refusal (spawn boundary)", () => {
  const probe: SandboxProbeResult = { available: true, path: "full" }
  const watch = {
    helperPath: "/pkg/bin/opencode-boundary-watch",
    socketPath: "/tmp/opencode/rt.sock",
    token: "ab".repeat(32),
    roots: ["/w"],
    denyRead: [],
    denyWrite: [],
    readonly: false,
  }
  const spawn = (env: Record<string, string | undefined>) => ({
    command: "touch /tmp/opencode/PAYLOAD-MARKER",
    shell: "/bin/bash",
    env,
  })
  const marked = {
    command: "touch /tmp/opencode/PAYLOAD-MARKER",
    profile: "workspace" as const,
    runtimeWatch: watch,
  }

  test("all 8 storage slots occupied -> refuse, neutralize LD_*, keep user env", () => {
    const env: Record<string, string> = {
      BASH_ENV: "/tmp/opencode/hook.sh",
      LD_PRELOAD: "/tmp/opencode/sentinel-preload.so",
      LD_AUDIT: "/tmp/opencode/sentinel-audit.so",
      KEEP_ME: "user-value",
    }
    for (let i = 0; i < 8; i++)
      env[i === 0 ? "OPENCODE_DEFER_BASH_ENV" : `OPENCODE_DEFER${i + 1}_BASH_ENV`] = `user-slot-${i}`
    const ev = spawn(env)
    const result = applySandboxCreateBefore(ev, { ...marked }, selection(), probe)
    // Refused before the payload exists: the deny text replaces the whole
    // command — the payload marker must not appear in it at all.
    expect(result).toBeUndefined()
    expect(ev.command).toContain("exit 126")
    expect(ev.command).toContain("could not be placed into supervised storage")
    expect(ev.command).not.toContain("PAYLOAD-MARKER")
    expect(ev.command).not.toContain("exec ")
    // The refusal pins /bin/sh (dash ignores BASH_ENV) AND still empties
    // every hook name: /bin/sh is dynamically linked, so a live LD_* would
    // load unmonitored code even in the denial shell.
    expect(ev.shell).toBe("/bin/sh")
    expect(ev.env.BASH_ENV).toBe("")
    expect(ev.env.LD_PRELOAD).toBe("")
    expect(ev.env.LD_AUDIT).toBe("")
    // User-owned env is not the payload's problem: same-prefix user vars
    // and unrelated values pass through the refusal untouched.
    expect(ev.env.KEEP_ME).toBe("user-value")
    expect(ev.env.OPENCODE_DEFER_BASH_ENV).toBe("user-slot-0")
    expect(ev.env.OPENCODE_DEFER8_BASH_ENV).toBe("user-slot-7")
  })

  test("more than 256 defer pairs -> same refusal, same neutralization", () => {
    const env: Record<string, string> = { KEEP_ME: "user-value" }
    for (let i = 0; i < 260; i++) env[`LD_HOOK_${i}`] = `sentinel-${i}`
    const ev = spawn(env)
    const result = applySandboxCreateBefore(ev, { ...marked }, selection(), probe)
    expect(result).toBeUndefined()
    expect(ev.command).toContain("exit 126")
    expect(ev.command).toContain("could not be placed into supervised storage")
    expect(ev.command).not.toContain("PAYLOAD-MARKER")
    expect(ev.shell).toBe("/bin/sh")
    for (let i = 0; i < 260; i++) expect(ev.env[`LD_HOOK_${i}`]).toBe("")
    expect(ev.env.KEEP_ME).toBe("user-value")
    // Nothing was deferred onto OPENCODE_DEFER_* storage names: the refusal
    // path mutates nothing but the hook names themselves.
    expect(Object.keys(ev.env).filter((key) => key.startsWith("OPENCODE_DEFER"))).toEqual([])
  })
})

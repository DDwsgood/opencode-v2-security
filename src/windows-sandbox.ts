import { execFile } from "node:child_process"
import path from "node:path"
import type { SandboxProbeResult, SandboxProfile, SandboxSelection } from "./sandbox"

export type WindowsSandboxOptions = {
  cwd: string
  readRoots: readonly string[]
  writeRoots: readonly string[]
  denyRead: readonly string[]
  denyWrite: readonly string[]
  network: boolean
  controlPipe?: string
  controlToken?: string
}

export type WindowsSandboxProbeResult = SandboxProbeResult & {
  /** An unsatisfied security contract is not an availability fail-open case. */
  contractFailure?: boolean
}

function windowsPath(value: string): string {
  // UNC, device namespaces, ADS, drive-relative names and ambiguous Win32
  // components are deliberately not part of the native ACL contract.
  if (!/^[a-z]:[\\/]/i.test(value) || /[\0-\x1f<>"|?*]/.test(value) || value.slice(2).includes(":")) {
    throw new Error("Windows sandbox requires an unambiguous local drive path")
  }
  const components = value.slice(3).split(/[\\/]/).filter(Boolean)
  if (components.some((part) => part === "." || part === ".." || /[. ]$/.test(part))) {
    throw new Error("Windows sandbox rejects ambiguous path components")
  }
  return path.win32.normalize(value)
}

/** Versioned JSON avoids delimiter ambiguity in drive letters and filenames.
 * The native helper validates it again; this is not the security boundary. */
export function buildWindowsSandboxSpawn(
  profile: SandboxProfile,
  sandbox: SandboxSelection,
  options: WindowsSandboxOptions,
): { helperPath: string; env: Record<string, string> } {
  if (profile === "full") throw new Error("Full/Bypass must not invoke the Windows sandbox")
  if (sandbox.extraArgs.length) throw new Error("Windows sandbox does not accept raw helper arguments")
  const policy = {
    version: 1,
    profile: profile === "ro" ? "ro" : "workspace",
    cwd: windowsPath(options.cwd),
    scratch: windowsPath(sandbox.scratch),
    readRoots: [...new Set(options.readRoots.map(windowsPath))],
    writeRoots: profile === "ro" ? [] : [...new Set(options.writeRoots.map(windowsPath))],
    denyRead: [...new Set([...sandbox.denyRead, ...options.denyRead].map(windowsPath))],
    denyWrite: [...new Set([...sandbox.denyWrite, ...options.denyWrite].map(windowsPath))],
    network: options.network,
  }
  const encoded = JSON.stringify(policy)
  if (encoded.length > 24_000) throw new Error("Windows sandbox policy exceeds the environment limit")
  const env: Record<string, string> = { OPENCODE_WINDOWS_SANDBOX_POLICY: encoded }
  if (options.controlPipe !== undefined || options.controlToken !== undefined) {
    if (!options.controlPipe?.startsWith("\\\\.\\pipe\\opencode-security-") || /[\r\n\0]/.test(options.controlPipe)
      || !options.controlToken || !/^[a-zA-Z0-9_-]{32,256}$/.test(options.controlToken)) {
      throw new Error("Windows sandbox control pipe/token are invalid")
    }
    env.OPENCODE_WINDOWS_CONTROL_PIPE = options.controlPipe
    env.OPENCODE_WINDOWS_CONTROL_TOKEN = options.controlToken
  }
  return { helperPath: sandbox.helperPath, env }
}

function runProbe(helperPath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(helperPath, ["--probe"], { timeout: 20_000, maxBuffer: 16_384, windowsHide: true }, (error, stdout) => {
      if (error) reject(new Error("Windows sandbox helper probe could not complete"))
      else resolve(stdout)
    })
  })
}

export async function probeWindowsSandbox(
  sandbox: Pick<SandboxSelection, "helperPath">,
  run: (helperPath: string) => Promise<string> = runProbe,
): Promise<WindowsSandboxProbeResult> {
  try {
    const result = JSON.parse(await run(sandbox.helperPath))
    if (result?.version !== 1 || result?.backend !== "windows-lpac" || typeof result.available !== "boolean") {
      return { available: false, reason: "Windows sandbox helper returned an incompatible probe" }
    }
    if (result.available !== true) {
      if (result.contractFailure === true) {
        return {
          available: false,
          contractFailure: true,
          reason: "Windows sandbox security contract failed; isolated execution is disabled",
        }
      }
      return { available: false, reason: "Windows LPAC sandbox prerequisites are unavailable" }
    }
    return { available: true }
  } catch {
    return { available: false, reason: "Windows sandbox helper probe failed" }
  }
}

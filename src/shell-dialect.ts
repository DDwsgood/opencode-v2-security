import { existsSync, statSync } from "node:fs"
import path from "node:path"

function executableOnPath(name: string) {
  if (path.isAbsolute(name) || name.includes("/") || name.includes("\\")) {
    return existsSync(name) ? name : undefined
  }

  const extensions =
    process.platform === "win32" ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";") : [""]
  const directories = (process.env.PATH ?? "").split(path.delimiter)
  const hasExtension = path.extname(name).length > 0

  for (const directory of directories) {
    if (!directory) continue
    const candidates = hasExtension ? [name] : extensions.map((extension) => name + extension.toLowerCase())
    for (const candidate of candidates) {
      const file = path.join(directory, candidate)
      try {
        if (statSync(file).isFile()) return file
      } catch {
        // Continue searching PATH.
      }
    }
  }
}

export function resolveClassifierShell(configured?: string) {
  const candidates =
    process.platform === "win32"
      ? [configured, process.env.SHELL, "pwsh", "powershell", process.env.ComSpec, process.env.COMSPEC, "cmd.exe"]
      : [configured, process.env.SHELL, "/bin/bash", "/bin/sh"]

  for (const candidate of candidates) {
    if (!candidate) continue
    const resolved = executableOnPath(candidate)
    if (resolved) return resolved
  }

  return configured ?? (process.platform === "win32" ? "powershell" : "/bin/bash")
}

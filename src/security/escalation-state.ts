export type EscalationContextMessage = { role: "user" | "assistant"; text: string }

export type FailedEscalationRecord = {
  command: string
  categories: readonly string[]
  justification: string
  decision: "ask_user" | "deny"
}

const MAX_CONTEXT_MESSAGES = 16
const MAX_CONTEXT_MESSAGE_CHARS = 4000
const MAX_CONTEXT_TOTAL_CHARS = 24000
const MAX_USER_INPUT_CHARS = 8000
const MAX_RECENT_USER_INPUTS = 5

function clippedText(value: unknown, limit = MAX_CONTEXT_MESSAGE_CHARS): string | undefined {
  if (typeof value !== "string") return undefined
  const text = value.replace(/\0/g, "").trim()
  if (!text) return undefined
  if (text.length <= limit) return text
  // Preserve trailing restrictions as well as the task at the beginning.
  const marker = "\n…[context truncated]…\n"
  const headLength = Math.floor((limit - marker.length) / 2)
  return text.slice(0, headLength) + marker + text.slice(-(limit - marker.length - headLength))
}

/** Extract only human/model prose from the durable session context. Tool
 * inputs, outputs, reasoning, synthetic plugin notices, files, and metadata
 * are intentionally excluded. */
export function escalationContextFromMessages(messages: readonly unknown[]): {
  currentUserInput: string
  recentContext: EscalationContextMessage[]
  recentUserInputs: string[]
} {
  const candidates: EscalationContextMessage[] = []
  const userInputs: string[] = []
  for (const value of messages) {
    if (!value || typeof value !== "object" || Array.isArray(value)) continue
    const message = value as Record<string, unknown>
    if (message.type === "user") {
      const text = clippedText(message.text)
      if (text) candidates.push({ role: "user", text })
      const userText = clippedText(message.text, MAX_USER_INPUT_CHARS)
      if (userText) userInputs.push(userText)
      continue
    }
    if (message.type !== "assistant" || !Array.isArray(message.content)) continue
    const parts: string[] = []
    for (const item of message.content) {
      if (!item || typeof item !== "object" || Array.isArray(item)) continue
      const part = item as Record<string, unknown>
      if (part.type !== "text") continue
      const text = clippedText(part.text)
      if (text) parts.push(text)
    }
    const text = clippedText(parts.join("\n"))
    if (text) candidates.push({ role: "assistant", text })
  }

  const recent: EscalationContextMessage[] = []
  let used = 0
  for (const item of candidates.slice(-MAX_CONTEXT_MESSAGES).reverse()) {
    const remaining = MAX_CONTEXT_TOTAL_CHARS - used
    if (remaining <= 0) break
    const text = item.text.slice(0, remaining)
    recent.push({ role: item.role, text })
    used += text.length
  }
  recent.reverse()
  const currentUserInput = userInputs.at(-1) ?? ""
  // Keep the last five user messages independently of the mixed-context window:
  // one denial may span multiple user turns, and the immediately-preceding
  // message is not always the request being executed.
  const recentUserInputs = userInputs.slice(-MAX_RECENT_USER_INPUTS)
  return { currentUserInput, recentContext: recent, recentUserInputs }
}

const TOKEN_ALIASES: Readonly<Record<string, string>> = {
  "apt-get": "apt",
  aptitude: "apt",
  dnf: "pkg",
  yum: "pkg",
  pacman: "pkg",
  zypper: "pkg",
  apk: "pkg",
  brew: "pkg",
  wget: "curl",
  "remove-item": "rm",
  del: "rm",
  erase: "rm",
  unlink: "rm",
  pkill: "kill",
  killall: "kill",
  "stop-process": "kill",
  pwsh: "powershell",
  "powershell.exe": "powershell",
}

const IGNORED_TOKENS = new Set(["sudo", "doas", "pkexec", "runas", "command", "env", "nohup"])

export function normalizedEscalationTokens(command: string): string[] {
  const tokens = command
    .toLowerCase()
    .replace(/\\\r?\n/g, " ")
    .match(/[a-z0-9_./:@+-]+/g) ?? []
  return tokens
    .map((token) => TOKEN_ALIASES[token] ?? token)
    .filter((token) => !IGNORED_TOKENS.has(token) && !/^-+[a-z0-9-]+$/.test(token))
}

function commandFamily(tokens: readonly string[]): string | undefined {
  const joined = ` ${tokens.join(" ")} `
  if (/\s(?:rm|rmdir|shred|wipe|find)\s/.test(joined) || joined.includes(" -delete ")) return "delete"
  if (/\s(?:apt|pkg)\s+(?:install|remove|purge|upgrade|update)\s/.test(joined)) return "package-state"
  if (/\s(?:kill|taskkill)\s/.test(joined)) return "process-control"
  if (/\s(?:systemctl|service|launchctl|sc)\s/.test(joined)) return "service-control"
  if (/\s(?:chmod|chown|setfacl|icacls)\s/.test(joined)) return "permission-change"
  if (/\s(?:mount|umount|diskpart|mkfs|wipefs)\s/.test(joined)) return "storage-state"
  if (/\s(?:curl|ssh|scp|rsync|nc|ncat|socat)\s/.test(joined)) return "network-transfer"
  if (/\sgit\s+(?:push|filter-branch|filter-repo|reset|rebase)\s/.test(joined)) return "git-state"
  if (/\s(?:kubectl|helm|terraform|aws|gcloud|az|docker|podman)\s/.test(joined)) return "remote-infrastructure"
  if (/\s(?:psql|mysql|sqlite3|mongosh|redis-cli)\s/.test(joined)) return "database-state"
  if (/\s(?:bash|sh|zsh|powershell|python|python3|node|bun|deno)\s/.test(joined)) return "indirect-execution"
  return undefined
}

function jaccard(a: readonly string[], b: readonly string[]): number {
  const left = new Set(a)
  const right = new Set(b)
  if (left.size === 0 || right.size === 0) return 0
  let intersection = 0
  for (const token of left) if (right.has(token)) intersection++
  return intersection / (left.size + right.size - intersection)
}

/** Conservative retry-family check. It normalizes common privilege wrappers,
 * package-manager aliases, flags, and equivalent executable names so trivial
 * rewrites cannot evade a failed escalation. */
export function escalationCommandsAreSimilar(a: string, b: string): boolean {
  const left = normalizedEscalationTokens(a)
  const right = normalizedEscalationTokens(b)
  if (left.length === 0 || right.length === 0) return false
  if (left.join(" ") === right.join(" ")) return true
  const score = jaccard(left, right)
  const leftFamily = commandFamily(left)
  const rightFamily = commandFamily(right)
  if (leftFamily && leftFamily === rightFamily && score >= 0.3) return true
  return left[0] === right[0] && score >= 0.55
}

/** Conservative retry-family check over COMMAND TOKENS ONLY — categories are
 * deliberately not part of command similarity. The `categories` argument
 * adds one exemption on top: a retry that strictly widens the failed
 * request's declared set (every earlier category kept, plus at least one
 * new one) is a different ask, not a disguised retry — e.g. the coverage
 * retry a "Risk categories: …" hint points at. Such a retry must reach the
 * reviewer; an identical or narrowed category set is still a similar
 * request and stays denied. */
export function findSimilarFailedEscalation(
  command: string,
  failures: readonly FailedEscalationRecord[],
  categories?: readonly string[],
): FailedEscalationRecord | undefined {
  return failures.find((failure) => {
    if (!escalationCommandsAreSimilar(command, failure.command)) return false
    if (categories !== undefined) {
      const widened =
        failure.categories.every((category) => categories.includes(category)) &&
        categories.some((category) => !failure.categories.includes(category))
      if (widened) return false
    }
    return true
  })
}

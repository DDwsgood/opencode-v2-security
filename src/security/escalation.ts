// Strict escalation-header parser.
//
// An escalation request is ONLY recognized when a command text begins, from
// its very first byte, with these three header lines in this exact order:
//
//   # - REQUIRE_ESCALATION
//   # - CATEGORY: <comma-separated categories>
//   # - JUSTIFICATION: <single-line reason>
//
// Everything from byte zero of line 4 onward is the real command and is
// preserved verbatim.
//
// The parser deliberately distinguishes three outcomes so callers can
// fail-closed:
//
//   - "none"      no escalation marker at all (plain command)
//   - "malformed" the text starts with the reserved prefix `# - REQUIRE_` or
//                 with the exact first header line, but the structure is
//                 wrong (missing/misspelled header, bad categories, empty
//                 justification, missing command, ...)
//   - "valid"     a well-formed escalation request
//
// LF and CRLF line endings are both accepted.

/** Exact, mandatory first header line. */
export const ESCALATION_MARKER = "# - REQUIRE_ESCALATION"

/** Reserved prefix: anything starting with this is treated as an attempted
 * escalation header and must parse cleanly, otherwise it is `malformed`. */
export const ESCALATION_RESERVED_PREFIX = "# - REQUIRE_"

/** Exact prefix of the mandatory second header line. */
export const CATEGORY_HEADER_PREFIX = "# - CATEGORY:"

/** Exact prefix of the mandatory third header line. */
export const JUSTIFICATION_HEADER_PREFIX = "# - JUSTIFICATION:"

/** Upper bound (in characters) applied to the trimmed justification. */
export const MAX_JUSTIFICATION_LENGTH = 1000

/** Category spellings that are always rejected, case-insensitively where
 * meaningful, so a caller can never be tricked into "arm everything". */
const FORBIDDEN_CATEGORY_ITEMS = [ "all", "*" ]

/** Short format description suitable for handing to an agent/model. */
export const ESCALATION_FORMAT_GUIDE =
  `To request escalation, start the command with these three lines exactly:\n` +
  `${ESCALATION_MARKER}\n` +
  `${CATEGORY_HEADER_PREFIX} <category>[,<category>...]\n` +
  `${JUSTIFICATION_HEADER_PREFIX} <one-line reason>\n` +
  `<real command starting on line 4>`

export type EscalationStatus = "none" | "malformed" | "valid"

export type EscalationFailureCode =
  | "bad-first-line"
  | "missing-category-line"
  | "missing-justification-line"
  | "bad-category-header"
  | "bad-justification-header"
  | "empty-category"
  | "duplicate-category"
  | "unknown-category"
  | "forbidden-category"
  | "empty-justification"
  | "justification-too-long"
  | "missing-command"

export interface EscalationRequest {
  /** Trimmed, validated categories in the order written. Never empty. */
  readonly categories: readonly string[]
  /** Trimmed, non-empty, single-line justification. */
  readonly justification: string
  /** The real command (line 4 onward), preserved verbatim. */
  readonly command: string
}

export type EscalationParseResult =
  | { readonly status: "none"; readonly command: string }
  | {
      readonly status: "malformed"
      readonly code: EscalationFailureCode
      readonly reason: string
      readonly command: string
    }
  | { readonly status: "valid"; readonly request: EscalationRequest }

interface Line {
  /** Line content with a single trailing CR removed (LF/CRLF aware). */
  readonly content: string
  /** Byte offset immediately after this line's terminator (start of next). */
  readonly next: number
}

function splitLines(text: string): Line[] {
  const lines: Line[] = []
  let start = 0
  for (;;) {
    const nl = text.indexOf("\n", start)
    const end = nl === -1 ? text.length : nl
    let content = text.slice(start, end)
    if (content.endsWith("\r")) content = content.slice(0, -1)
    lines.push({ content, next: nl === -1 ? text.length : nl + 1 })
    if (nl === -1) break
    start = nl + 1
  }
  return lines
}

function malformed(
  code: EscalationFailureCode,
  reason: string,
  command: string,
): EscalationParseResult {
  return { status: "malformed", code, reason, command }
}

/**
 * Parse `text` as a possibly-escalation-marked command.
 *
 * @param text       the raw command text (may span multiple lines)
 * @param categories the complete set of categories the caller accepts; any
 *                   category outside it is rejected as unknown
 */
export function parseEscalation(
  text: string,
  categories: readonly string[],
): EscalationParseResult {
  // No marker whatsoever: only recognize the exact first line or the reserved
  // prefix at byte zero. Anything else is a plain command.
  if (!text.startsWith(ESCALATION_MARKER) && !text.startsWith(ESCALATION_RESERVED_PREFIX)) {
    return { status: "none", command: text }
  }

  const allowed = new Set(categories)

  const lines = splitLines(text)
  const first = lines[0]?.content ?? ""

  // Reserved-prefix misspelling (e.g. `# - REQUIRE_ESCALATION_X`, or the bare
  // `# - REQUIRE_`): fail closed.
  if (first !== ESCALATION_MARKER) {
    return malformed(
      "bad-first-line",
      `first line must be exactly ${JSON.stringify(ESCALATION_MARKER)}`,
      text,
    )
  }

  const categoryLine = lines[1]
  if (categoryLine === undefined) {
    return malformed("missing-category-line", "missing category header line", text)
  }
  if (!categoryLine.content.startsWith(CATEGORY_HEADER_PREFIX)) {
    return malformed(
      "bad-category-header",
      `line 2 must start with ${JSON.stringify(CATEGORY_HEADER_PREFIX)}`,
      text,
    )
  }

  const rawCategories = categoryLine.content.slice(CATEGORY_HEADER_PREFIX.length).trim()
  if (rawCategories.length === 0) {
    return malformed("empty-category", "category list is empty", text)
  }

  const seen = new Set<string>()
  const parsedCategories: string[] = []
  for (const raw of rawCategories.split(",")) {
    const item = raw.trim()
    if (item.length === 0) {
      return malformed("empty-category", "category list contains an empty item", text)
    }
    const lowered = item.toLowerCase()
    if (FORBIDDEN_CATEGORY_ITEMS.includes(lowered)) {
      return malformed(
        "forbidden-category",
        `category ${JSON.stringify(item)} is not allowed`,
        text,
      )
    }
    if (seen.has(item)) {
      return malformed("duplicate-category", `duplicate category ${JSON.stringify(item)}`, text)
    }
    seen.add(item)
    if (!allowed.has(item)) {
      return malformed(
        "unknown-category",
        `category ${JSON.stringify(item)} is not grantable; accepted categories: ${categories.join(", ")}`,
        text,
      )
    }
    parsedCategories.push(item)
  }

  const justificationLine = lines[2]
  if (justificationLine === undefined) {
    return malformed("missing-justification-line", "missing justification header line", text)
  }
  if (!justificationLine.content.startsWith(JUSTIFICATION_HEADER_PREFIX)) {
    return malformed(
      "bad-justification-header",
      `line 3 must start with ${JSON.stringify(JUSTIFICATION_HEADER_PREFIX)}`,
      text,
    )
  }

  const justification = justificationLine.content.slice(JUSTIFICATION_HEADER_PREFIX.length).trim()
  if (justification.length === 0) {
    return malformed("empty-justification", "justification is empty", text)
  }
  if (justification.length > MAX_JUSTIFICATION_LENGTH) {
    return malformed(
      "justification-too-long",
      `justification exceeds ${MAX_JUSTIFICATION_LENGTH} characters`,
      text,
    )
  }

  const command = text.slice(justificationLine.next)
  if (command.trim().length === 0) {
    return malformed("missing-command", "no command follows the header block", text)
  }

  return {
    status: "valid",
    request: {
      categories: parsedCategories,
      justification,
      command,
    },
  }
}

import { describe, expect, test } from "bun:test"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_FORMAT_GUIDE,
  ESCALATION_MARKER,
  ESCALATION_RESERVED_PREFIX,
  JUSTIFICATION_HEADER_PREFIX,
  MAX_JUSTIFICATION_LENGTH,
  parseEscalation,
  type EscalationParseResult,
  type EscalationRequest,
} from "../src/security/escalation"

const CATEGORIES = ["filesystem", "host", "secret", "network", "remote", "indirection", "slow"] as const

const M = ESCALATION_MARKER
const C = "# - CATEGORY:"
const J = "# - JUSTIFICATION:"

function expectValid(result: EscalationParseResult): EscalationRequest {
  if (result.status !== "valid") {
    throw new Error(`expected valid, got ${result.status}`)
  }
  return result.request
}

function expectMalformed(result: EscalationParseResult, code: string): void {
  expect(result.status).toBe("malformed")
  if (result.status === "malformed") {
    expect(result.code).toBe(code)
    expect(result.reason.length).toBeGreaterThan(0)
  }
}

describe("constants", () => {
  test("headers are the exact contractual strings", () => {
    expect(ESCALATION_MARKER).toBe("# - REQUIRE_ESCALATION")
    expect(ESCALATION_RESERVED_PREFIX).toBe("# - REQUIRE_")
    expect(CATEGORY_HEADER_PREFIX).toBe("# - CATEGORY:")
    expect(JUSTIFICATION_HEADER_PREFIX).toBe("# - JUSTIFICATION:")
    expect(MAX_JUSTIFICATION_LENGTH).toBe(1000)
  })

  test("format guide describes the three-line header", () => {
    expect(ESCALATION_FORMAT_GUIDE).toContain(ESCALATION_MARKER)
    expect(ESCALATION_FORMAT_GUIDE).toContain(CATEGORY_HEADER_PREFIX)
    expect(ESCALATION_FORMAT_GUIDE).toContain(JUSTIFICATION_HEADER_PREFIX)
  })
})

describe("valid requests", () => {
  test("strict three-line header then command", () => {
    const text = [M, `${C} filesystem`, `${J} fix ownership`, "chown -R root:root /srv/app"].join(
      "\n",
    )
    const request = expectValid(parseEscalation(text, CATEGORIES))
    expect(request.categories).toEqual(["filesystem"])
    expect(request.justification).toBe("fix ownership")
    expect(request.command).toBe("chown -R root:root /srv/app")
  })

  test("multi-line command is preserved verbatim", () => {
    const command = "umount /mnt/data\nmount -o remount,rw /mnt/data"
    const text = [M, `${C} filesystem`, `${J} recover mount`, command].join("\n")
    expect(expectValid(parseEscalation(text, CATEGORIES)).command).toBe(command)
  })

  test("CRLF line endings are accepted", () => {
    const text = [
      M,
      `${C} filesystem,host`,
      `${J} needs root`,
      "systemctl restart nginx",
    ].join("\r\n")
    const request = expectValid(parseEscalation(text, CATEGORIES))
    expect(request.categories).toEqual(["filesystem", "host"])
    expect(request.justification).toBe("needs root")
    expect(request.command).toBe("systemctl restart nginx")
  })

  test("CRLF inside the command is preserved", () => {
    const text = `${M}\r\n${C} filesystem\r\n${J} x\r\necho a\r\necho b`
    expect(expectValid(parseEscalation(text, CATEGORIES)).command).toBe("echo a\r\necho b")
  })

  test("trailing newline after the command is preserved", () => {
    const text = `${M}\n${C} filesystem\n${J} x\necho hi\n`
    expect(expectValid(parseEscalation(text, CATEGORIES)).command).toBe("echo hi\n")
  })

  test("multiple categories in written order", () => {
    const text = [M, `${C} secret, network ,slow`, `${J} yes`, "cat /etc/shadow"].join("\n")
    expect(expectValid(parseEscalation(text, CATEGORIES)).categories).toEqual([
      "secret",
      "network",
      "slow",
    ])
  })

  test("category and justification values are trimmed", () => {
    const text = [M, `${C}   filesystem  `, `${J}   spaced reason  `, "echo ok"].join("\n")
    const request = expectValid(parseEscalation(text, CATEGORIES))
    expect(request.categories).toEqual(["filesystem"])
    expect(request.justification).toBe("spaced reason")
  })

  test("justification of exactly the max length is accepted", () => {
    const text = [M, `${C} filesystem`, `${J} ${"x".repeat(MAX_JUSTIFICATION_LENGTH)}`, "echo ok"].join(
      "\n",
    )
    expect(expectValid(parseEscalation(text, CATEGORIES)).justification.length).toBe(
      MAX_JUSTIFICATION_LENGTH,
    )
  })
})

describe("none (no escalation marker)", () => {
  const cases: Array<[string, string]> = [
    ["empty text", ""],
    ["plain command", "ls -la"],
    ["comment-only command", "# just a comment"],
    ["category line alone", `${C} filesystem`],
    ["justification line alone", `${J} reason`],
    ["header words mid-command", "echo '# - REQUIRE_ESCALATION'"],
  ]
  for (const [name, text] of cases) {
    test(`${name} is none`, () => {
      const result = parseEscalation(text, CATEGORIES)
      expect(result.status).toBe("none")
      expect(result.command).toBe(text)
    })
  }

  test("leading whitespace before the marker is none", () => {
    const text = ` ${M}\n${C} filesystem\n${J} x\necho hi`
    expect(parseEscalation(text, CATEGORIES).status).toBe("none")
  })

  test("leading newline before the marker is none", () => {
    const text = `\n${M}\n${C} filesystem\n${J} x\necho hi`
    expect(parseEscalation(text, CATEGORIES).status).toBe("none")
  })

  test("BOM before the marker is none", () => {
    const text = `\uFEFF${M}\n${C} filesystem\n${J} x\necho hi`
    expect(parseEscalation(text, CATEGORIES).status).toBe("none")
  })

  test("lowercase marker is none (not a reserved prefix)", () => {
    const text = `# - require_escalation\n${C} filesystem\n${J} x\necho hi`
    expect(parseEscalation(text, CATEGORIES).status).toBe("none")
  })
})

describe("malformed headers fail closed", () => {
  test("misspelled first line with reserved prefix", () => {
    const text = "# - REQUIRE_ESCALATION_X\n# - CATEGORY: filesystem\n# - JUSTIFICATION: x\necho hi"
    expectMalformed(parseEscalation(text, CATEGORIES), "bad-first-line")
  })

  test("bare reserved prefix", () => {
    expectMalformed(parseEscalation("# - REQUIRE_", CATEGORIES), "bad-first-line")
  })

  test("reserved prefix then junk", () => {
    expectMalformed(parseEscalation("# - REQUIRE_CATEGORY: filesystem", CATEGORIES), "bad-first-line")
  })

  test("trailing whitespace on the marker line", () => {
    const text = `${M} \n${C} filesystem\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "bad-first-line")
  })

  test("missing category line", () => {
    expectMalformed(parseEscalation(M, CATEGORIES), "missing-category-line")
  })

  test("misspelled category header", () => {
    const text = `${M}\n# - CATEGORIES: filesystem\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "bad-category-header")
  })

  test("headers swapped", () => {
    const text = `${M}\n${J} x\n${C} filesystem\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "bad-category-header")
  })

  test("missing justification line", () => {
    expectMalformed(parseEscalation(`${M}\n${C} filesystem`, CATEGORIES), "missing-justification-line")
  })

  test("misspelled justification header", () => {
    const text = `${M}\n${C} filesystem\n# - WHY: x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "bad-justification-header")
  })

  test("empty category list", () => {
    const text = `${M}\n${C}\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "empty-category")
  })

  test("whitespace-only category list", () => {
    const text = `${M}\n${C}    \n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "empty-category")
  })

  test("trailing comma yields an empty item", () => {
    const text = `${M}\n${C} filesystem,\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "empty-category")
  })

  test("consecutive commas yield an empty item", () => {
    const text = `${M}\n${C} filesystem,,host\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "empty-category")
  })

  test("duplicate category", () => {
    const text = `${M}\n${C} host, host\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "duplicate-category")
  })

  test("unknown category", () => {
    const text = `${M}\n${C} filesystem,unsupported\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "unknown-category")
  })

  test("category case must match the caller set exactly", () => {
    const text = `${M}\n${C} FileSystem\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "unknown-category")
  })

  for (const alias of ["all", "ALL", "All", "aLl", "*"]) {
    test(`wildcard alias ${JSON.stringify(alias)} is forbidden`, () => {
      const text = `${M}\n${C} filesystem,${alias}\n${J} x\necho hi`
      expectMalformed(parseEscalation(text, CATEGORIES), "forbidden-category")
    })
  }

  test("bare wildcard as sole category is forbidden", () => {
    const text = `${M}\n${C} *\n${J} x\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "forbidden-category")
  })

  test("empty justification", () => {
    const text = `${M}\n${C} filesystem\n${J}\necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "empty-justification")
  })

  test("whitespace-only justification", () => {
    const text = `${M}\n${C} filesystem\n${J}     \necho hi`
    expectMalformed(parseEscalation(text, CATEGORIES), "empty-justification")
  })

  test("over-long justification", () => {
    const text = [M, `${C} filesystem`, `${J} ${"x".repeat(MAX_JUSTIFICATION_LENGTH + 1)}`, "echo hi"].join(
      "\n",
    )
    expectMalformed(parseEscalation(text, CATEGORIES), "justification-too-long")
  })

  test("missing command after a complete header", () => {
    expectMalformed(parseEscalation(`${M}\n${C} filesystem\n${J} x`, CATEGORIES), "missing-command")
  })

  test("only a trailing newline after a complete header", () => {
    expectMalformed(parseEscalation(`${M}\n${C} filesystem\n${J} x\n`, CATEGORIES), "missing-command")
  })

  test("blank line where the command should be", () => {
    const text = `${M}\n${C} filesystem\n${J} x\n   \n`
    expectMalformed(parseEscalation(text, CATEGORIES), "missing-command")
  })

  test("malformed results keep the original text for diagnostics", () => {
    const text = `${M}\r\n${C} filesystem\r\n${J} x`
    const result = parseEscalation(text, CATEGORIES)
    expect(result.status).toBe("malformed")
    expect(result.command).toBe(text)
  })
})

describe("real command preservation", () => {
  test("leading indentation is preserved", () => {
    const text = `${M}\n${C} filesystem\n${J} x\n   echo hi`
    expect(expectValid(parseEscalation(text, CATEGORIES)).command).toBe("   echo hi")
  })

  test("header-like lines inside the command body are not reparsed", () => {
    const command = "cat <<'EOF'\n# - REQUIRE_ESCALATION\nEOF"
    const text = [M, `${C} filesystem`, `${J} heredoc`, command].join("\n")
    const request = expectValid(parseEscalation(text, CATEGORIES))
    expect(request.command).toBe(command)
    expect(request.justification).toBe("heredoc")
  })

  test("quotes, substitutions and pipes survive untouched", () => {
    const command = `bash -c "$(cat '/etc/app/conf.d' | grep -v '^#'); echo done"`
    const text = [M, `${C} filesystem`, `${J} quoted`, command].join("\n")
    expect(expectValid(parseEscalation(text, CATEGORIES)).command).toBe(command)
  })

  test("a command line that itself looks like a header is preserved", () => {
    const command = `# - CATEGORY: bogus\necho hi`
    const text = [M, `${C} filesystem`, `${J} x`, command].join("\n")
    expect(expectValid(parseEscalation(text, CATEGORIES)).command).toBe(command)
  })
})

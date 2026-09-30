import { describe, expect, test } from "bun:test"
import { classifyShellCommand } from "../src/security/classifier"
import type { Strictness } from "../src/security/classifier"

// Round-3 regression coverage (DECISION.md A–E): comment-aware splitting,
// opaque unresolved handling, semantic git argv, the executor gate, bounded
// proven-data masking, and data-heredoc visibility.

const root = "/tmp/opencode"
type Input = Parameters<typeof classifyShellCommand>[0]
const classify = (script: string, strictness: Strictness, extra: Partial<Input> = {}) =>
  classifyShellCommand({ script, cwd: root, worktree: root, shell: "/bin/bash", strictness, ...extra })
const verdict = (script: string, strictness: Strictness, extra: Partial<Input> = {}) =>
  classify(script, strictness, extra).then((d) => d.verdict)
const rules = (script: string, strictness: Strictness, extra: Partial<Input> = {}) =>
  classify(script, strictness, extra).then((d) => d.rules)

const RO_KERNEL: Partial<Input> = { permScope: { r: true, w: false, x: true }, roKernelEnforced: true }

describe("A: comment-aware splitting closes the trailing-quote chain hide", () => {
  const denied = [
    "ls; chmod -R 777 / #'",
    "git status; sudo reboot #'",
    "cat f; git push --force origin main #'",
    "ls; dd if=/dev/zero of=/dev/sda #'",
    "ls; rm -rf ~/work #'",
    "ls; rm -rf ~/work #",
  ]
  for (const script of denied) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: ${script}`, async () => {
        expect(await verdict(script, mode)).toBe("DENY")
      })
    }
  }
  test("LOOSE: secret read in a comment-hidden tail is still caught", async () => {
    expect(await verdict("ls; cat ~/.ssh/id_rsa #'", "LOOSE")).toBe("ASK")
    expect(await verdict("ls; cat ~/.ssh/id_rsa #'", "HARD")).toBe("DENY")
  })
  for (const script of [
    "ls # rm -rf /",
    "echo hi # comment",
    "echo a && # mid\nls",
    "echo x#y",
    "echo \\#x",
    "echo '#x'",
    "cat <<'EOF'\n# not a comment\nrm -rf /\nEOF",
  ]) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: comment/data stays benign — ${JSON.stringify(script)}`, async () => {
        expect(await verdict(script, mode)).toBe("ALLOW")
      })
    }
  }
  test("unresolved splits are never allowed", async () => {
    expect(await verdict("echo hi '", "LOOSE")).toBe("ASK")
    expect(await verdict("echo hi '", "HARD")).toBe("DENY")
    expect(await verdict("echo `x`", "LOOSE")).toBe("ASK")
  })
})

describe("B: semantic git push argv", () => {
  for (const script of [
    'git push "--force" origin main',
    "git push '-f' origin main",
    'git push origin "+main"',
    'git push --fo"rce" origin main',
    "git push '-'f origin main",
    'git push origin ":main"',
    "git push --force-with-lease origin main",
    "git push --delete origin main",
    "git push --mirror origin",
    "git -C /tmp push --force origin main",
    "git -c x=y push -f",
    "git --git-dir=/tmp/.git push -f",
    "sudo git push -f",
    "env FOO=1 git push -f",
    "timeout 10 git push -f",
    "ssh host git push -f",
    "git push $'--force' origin main",
  ]) {
    test(`denied: ${script}`, async () => {
      for (const mode of ["LOOSE", "HARD"] as const) {
        expect(await verdict(script, mode)).toBe("DENY")
      }
    })
  }
  for (const script of [
    "git push",
    "git push --tags",
    "git push --prune origin main",
    "git push --set-upstream origin main",
    "git push origin main",
    "grep 'git push --force' notes.txt",
    "git commit -m 'git push --force steps'",
  ]) {
    test(`allowed: ${script}`, async () => {
      expect(await verdict(script, "LOOSE")).toBe("ALLOW")
    })
  }
  test("dynamic push args are unresolved, not silently allowed", async () => {
    expect(await verdict("git push $F origin main", "LOOSE")).not.toBe("ALLOW")
  })
})

describe("C: executor invocations never ride known-safe/read-only", () => {
  test("destructive executor payloads deny", async () => {
    for (const script of [
      "sed 'e rm -rf ~/work' f",
      "sed 's/x/rm -rf ~\\/work/e' f",
      "git grep -O'rm -rf ~/work' x",
      "rg --pre 'rm -rf ~/work' x .",
    ]) {
      for (const mode of ["LOOSE", "HARD"] as const) {
        expect(await verdict(script, mode)).toBe("DENY")
      }
      expect(await verdict(script, "LOOSE", RO_KERNEL)).toBe("DENY")
    }
  })
  test("benign executor payloads still review (LOOSE) and deny in RO", async () => {
    for (const script of ["sed 'e id' f", "rg --pre=id x .", "git grep -Oid x", "sed -f script.sed f"]) {
      expect(await verdict(script, "LOOSE")).toBe("ASK")
      expect(await verdict(script, "LOOSE", RO_KERNEL)).toBe("DENY")
    }
  })
  test("harmless text filters keep ALLOW", async () => {
    for (const script of [
      "sed -n '1,10p' f",
      "sed 's/a/b/' f",
      "sed '/x/d' f",
      "rg pattern src/",
      "rg --pre-glob '*.ts' x .",
      "git grep pattern",
    ]) {
      expect(await verdict(script, "LOOSE")).toBe("ALLOW")
      expect(await verdict(script, "LOOSE", RO_KERNEL)).toBe("ALLOW")
    }
  })
})

describe("D: proven quoted data does not trip destructive rules", () => {
  for (const script of [
    "grep 'rm -rf /' src/log.txt",
    "grep -rn 'sudo reboot' src/",
    "rg 'rm -rf /' src/",
    "git commit -m 'remove rm -rf / mention'",
    "git commit -am 'cleanup notes: rm -rf /'",
  ]) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: ${script}`, async () => {
        expect(await verdict(script, mode)).toBe("ALLOW")
      })
    }
  }
  test("negative gates stay denied or reviewed", async () => {
    for (const script of [
      "rm -rf /",
      "grep 'x'; rm -rf /",
      "grep $(rm -rf /) f",
      'grep $"$(rm -rf /)" f',
      "sh -c 'rm -rf /'",
      "sudo grep 'rm -rf /' f",
      "alias g=grep; g 'rm -rf /' f",
    ]) {
      expect(await verdict(script, "LOOSE")).toBe("DENY")
    }
    for (const script of ["grep 'rm -rf /' f | sh", "grep `rm -rf /` f"]) {
      expect(await verdict(script, "LOOSE")).not.toBe("ALLOW")
    }
  })
})

describe("E2: data heredocs masked only when proven inert", () => {
  test("quoted/expansion-free data heredocs allow", async () => {
    for (const script of [
      "cat <<'EOF'\nrm -rf /\nEOF",
      "cat <<EOF\nplain text\nEOF",
      "cat <<'EOF' | wc -l\nrm -rf /\nEOF",
      "cat <<'EOF' | grep x | wc\nrm -rf /\nEOF",
    ]) {
      for (const mode of ["LOOSE", "HARD"] as const) {
        expect(await verdict(script, mode)).toBe("ALLOW")
      }
    }
  })
  test("code-consumer and pipe-to-code bodies stay visible", async () => {
    expect(await rules("cat <<'EOF' | sh\nrm -rf ~/work\nEOF", "LOOSE")).toContain("filesystem.forced-recursive-delete")
    expect(await verdict("cat <<'EOF' | sh\nrm -rf ~/work\nEOF", "LOOSE")).toBe("DENY")
    expect(await verdict("cat <<'EOF' | tee f | sh\nrm -rf ~/work\nEOF", "LOOSE")).toBe("DENY")
    // An unrecognized downstream consumer is ambiguous payload text: the
    // dynamic reviewer decides (ASK) instead of the static floor (DENY).
    expect(await rules("cat <<'EOF' | unknowncmd\nrm -rf ~/work\nEOF", "LOOSE")).toContain("execution.ambiguous-heredoc")
    expect(await verdict("cat <<'EOF' | unknowncmd\nrm -rf ~/work\nEOF", "LOOSE")).toBe("ASK")
    expect(await verdict("cat <<'EOF' | unknowncmd | sh\nrm -rf ~/work\nEOF", "LOOSE")).toBe("DENY")
    expect(await verdict("sh <<'EOF'\nrm -rf ~/work\nEOF", "LOOSE")).toBe("DENY")
    expect(await verdict("cat <<EOF\n$(rm -rf /)\nEOF", "LOOSE")).toBe("DENY")
    expect(await verdict("cat <<EOF\n`id`\nEOF", "LOOSE")).not.toBe("ALLOW")
  })
  test("write-then-execute correlation still inspects original bodies", async () => {
    expect(await verdict("cat > /tmp/opencode/x.sh <<'EOF'\nls\nEOF\nsh /tmp/opencode/x.sh", "LOOSE")).toBe("ASK")
  })
})

import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { classifyShellCommand, type Strictness } from "../src/security/classifier"

// Regression tests for the post-audit taxonomy fixes (round 1: T1–T6,
// round 2: D3/D4). The fixture root deliberately lives OUTSIDE /tmp
// (mirrors static-regressions.test.ts): a /tmp root would make every
// temp-confined case look like an in-worktree operation and mask the
// fail-open this suite covers.
let root: string
let tempArea: string
beforeAll(async () => {
  root = await mkdtemp(path.join(os.homedir(), ".taxonomy-fixes-"))
  await mkdir(path.join(root, "config"))
  await writeFile(path.join(root, "config/.env"), "SECRET=1\n")
  await writeFile(path.join(root, ".env"), "SECRET=1\n")
  await writeFile(path.join(root, "id_rsa"), "PRIVATE KEY\n")
  tempArea = await mkdtemp(path.join("/tmp/opencode/", "taxonomy-fixes-"))
  await mkdir(path.join(tempArea, "config"), { recursive: true })
  await writeFile(path.join(tempArea, ".env"), "SECRET=1\n")
  await writeFile(path.join(tempArea, "id_rsa"), "PRIVATE KEY\n")
})
afterAll(async () => {
  const { rm } = await import("node:fs/promises")
  await rm(root, { recursive: true, force: true })
  await rm(tempArea, { recursive: true, force: true })
})

type Input = Parameters<typeof classifyShellCommand>[0]
const classify = (script: string, strictness: Strictness, extra: Partial<Input> = {}) =>
  classifyShellCommand({ script, cwd: root, worktree: root, shell: "/bin/bash", strictness, ...extra })

const armed = (...categories: string[]) =>
  ({ bypassedCategories: new Set(categories as never) }) as Partial<Input>

// --- T1: temp confinement must not defeat credential-delete -------------------
describe("T1: credential deletion stays data.critical-delete under temp roots", () => {
  const credentialDeletes = [
    "rm .env",
    "rm id_rsa",
    "rm -rf .ssh",
    "rm -f ./config/.env",
    "rm .env id_rsa",
  ]
  for (const script of credentialDeletes) {
    for (const mode of ["LOOSE", "HARD"] as const) {
      test(`${mode}: temp-confined ${script} denies with data.critical-delete`, async () => {
        const d = await classify(script, mode, { cwd: tempArea, worktree: tempArea })
        expect(d.verdict).toBe("DENY")
        expect(d.rules).toContain("data.critical-delete")
      })
      test(`${mode}: normal-root ${script} denies identically`, async () => {
        // The normal root may catch `rm -rf` shapes with the forced-recursive
        // policy first — the T1 property is that the temp root never ends up
        // MORE permissive than the normal root.
        const d = await classify(script, mode)
        expect(d.verdict).toBe("DENY")
      })
    }
  }

  test("LOOSE: arming filesystem alone (the relaxation that unmasked the bug) keeps the deny", async () => {
    const d = await classify("rm .env", "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("filesystem") })
    expect(d.verdict).toBe("DENY")
    expect(d.rules).toContain("data.critical-delete")
  })

  test("LOOSE: arming filesystem+secret clears the data rule (conjunctive map)", async () => {
    const d = await classify("rm .env", "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("filesystem", "secret") })
    expect(d.rules).not.toContain("data.critical-delete")
  })

  for (const mode of ["LOOSE", "HARD"] as const) {
    test(`${mode}: ordinary temp cleanup still allows after the fix`, async () => {
      const d = await classify("rm -rf some_dir", mode, { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ALLOW")
      expect(d.rules).toContain("cleanup.temp-confined")
    })
    test(`${mode}: disposable build cleanup still allows`, async () => {
      const d = await classify("rm -rf build", mode, { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ALLOW")
    })
  }
})

// --- T2: RO kernel-enforced gate keys privilege launchers to privilege ------
describe("T2/T3: privilege launchers gate on the privilege category in both paths", () => {
  const RO = { permScope: { r: true, w: false, x: true }, roKernelEnforced: true, roWritableRoots: ["/tmp"] }
  const roClassify = (script: string, arm: string[]) =>
    classify(script, "LOOSE", {
      cwd: tempArea,
      worktree: tempArea,
      ...(arm.length ? armed(...arm) : {}),
      ...RO,
    })

  // `sudo systemctl restart nginx` reaches the RO non-write gate; armed host
  // must NOT clear it (the pre-fix inverted behavior), armed privilege must.
  test("RO gate: privilege launchers key to privilege, not host", async () => {
    for (const script of ["sudo systemctl restart nginx", "sudo apt install unzip"]) {
      const none = await roClassify(script, [])
      expect(none.verdict).toBe("ASK")
      const host = await roClassify(script, ["host"])
      expect(host.verdict).toBe("ASK")
      const privilege = await roClassify(script, ["privilege"])
      expect(privilege.verdict).toBe("ALLOW")
      expect(privilege.rules).toContain("operation.kernel-enforced")
    }
  })

  test("RO gate: process killers keep the host category", async () => {
    for (const script of ["pkill nginx", "killall nginx"]) {
      const host = await roClassify(script, ["host"])
      expect(host.verdict).toBe("ALLOW")
      expect(host.rules).toContain("operation.kernel-enforced")
      const privilege = await roClassify(script, ["privilege"])
      expect(privilege.verdict).toBe("ASK")
    }
  })

  // The mimo probe surface: a code-consumer heredoc body launching sudo.
  test("RO gate: sudo inside a heredoc body asks, cleared by privilege", async () => {
    const script = "bash <<EOF\nsudo some-unknown-tool\nEOF"
    const none = await roClassify(script, [])
    expect(none.verdict).toBe("ASK")
    const host = await roClassify(script, ["host"])
    expect(host.verdict).toBe("ASK")
    const privilege = await roClassify(script, ["privilege"])
    expect(privilege.verdict).toBe("ALLOW")
  })
})

// --- T3: rw privilege trigger covers the full launcher set --------------------
describe("T3: rw privilege trigger covers sudo/sudoedit/doas/pkexec/su/runas", () => {
  const launchers = ["doas id", "pkexec bash", "su -", "sudoedit /etc/sudoers", "runas /user:admin cmd"]
  for (const script of launchers) {
    test(`launcher ASKs and only privilege clears it: ${script}`, async () => {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("operation.context-required")
      // Any single unrelated armed category must not clear the gate.
      for (const other of ["host", "filesystem", "network"]) {
        const armedDecision = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed(other) })
        expect(armedDecision.verdict).toBe("ASK")
        expect(armedDecision.rules).toContain("operation.context-required")
      }
      const cleared = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("privilege") })
      expect(cleared.rules).not.toContain("operation.context-required")
    })
  }

  test("prefix wrappers keep the launcher in command position", async () => {
    for (const script of ["env VAR=1 sudo id", "FOO=1 sudo id", "sudo su -", "echo hi | sudo tee /etc/x"]) {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("operation.context-required")
    }
  })

  // Ownership/mount/namespace mutators follow the privilege category too.
  describe("ownership and mount mutators gate on privilege", () => {
    for (const script of [
      "chown root:root /etc/app.conf",
      "chgrp wheel /etc/app.conf",
      "setcap cap_net_raw+ep /bin/ping",
      "setfacl -m u:daemon:rwx /etc/app.conf",
      "mount /dev/sdb1 /mnt",
      "umount /mnt",
      "unshare -Ur bash",
      "chroot /mnt /bin/sh",
    ]) {
      test(`${script} asks with a privilege-keyed rule`, async () => {
        const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
        expect(d.verdict).toBe("ASK")
        // The gate rides operation.context-required (privilege virtual rule)
        // or a privilege-family signal like namespace.escape.
        expect(
          d.rules.some((rule) => rule === "operation.context-required" || rule === "namespace.escape"),
        ).toBe(true)
      })
      test(`${script} is not cleared by host, only by privilege`, async () => {
        const hostArmed = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("host") })
        expect(hostArmed.verdict).toBe("ASK")
        expect(
          hostArmed.rules.some((rule) => rule === "operation.context-required" || rule === "namespace.escape"),
        ).toBe(true)
        const cleared = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("privilege") })
        expect(
          cleared.rules.some((rule) => rule === "operation.context-required" || rule === "namespace.escape"),
        ).toBe(false)
      })
    }
  })

  // Negative cases: words in strings, args, comments, and commit messages
  // must not trigger the privilege gate.
  describe("sudo/su words outside command position do not trigger", () => {
    const negatives = [
      "grep sudo README.md",
      "grep -C2 su README.md",
      "echo 'sudo x'",
      'git commit -m "use sudo to install"',
      "cat summit.txt",
      "ls su-dir",
    ]
    for (const script of negatives) {
      for (const mode of ["LOOSE", "HARD"] as const) {
        test(`${mode}: stays allowed: ${script}`, async () => {
          expect(await classify(script, mode, { cwd: tempArea, worktree: tempArea }).then((d) => d.verdict)).toBe("ALLOW")
        })
      }
    }
  })
})

// --- T4: /proc/sys writes are kernel sysctl questions, not secret ones -------
describe("T4: write-direction /proc/sys access emits kernel.sysctl-write", () => {
  const writeCommands = [
    "echo 1 > /proc/sys/net/ipv4/ip_forward",
    "tee /proc/sys/kernel/printk",
    "dd if=/dev/zero of=/proc/sys/vm/swappiness count=1",
    "mkdir /proc/sys/x",
  ]
  for (const script of writeCommands) {
    test(`LOOSE: ${script} asks with kernel.sysctl-write`, async () => {
      const d = await classify(script, "LOOSE")
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("kernel.sysctl-write")
    })
    test(`HARD: ${script} denies with kernel.sysctl-write`, async () => {
      const d = await classify(script, "HARD")
      expect(d.verdict).toBe("DENY")
      expect(d.rules).toContain("kernel.sysctl-write")
    })
    test(`LOOSE: arming privilege clears the ${script.split(" ")[0]} ask, secret does not`, async () => {
      expect((await classify(script, "LOOSE", armed("privilege"))).rules).not.toContain("kernel.sysctl-write")
      expect((await classify(script, "LOOSE", armed("secret"))).rules).toContain("kernel.sysctl-write")
    })
  }

  test("sysctl -w keeps its kernel.sysctl-write signal", async () => {
    const d = await classify("sysctl -w vm.swappiness=10", "LOOSE")
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("kernel.sysctl-write")
  })

  // Reads of /proc/sys keep their sensitive-path classification.
  test("reads of /proc/sys keep the credentials path", async () => {
    const d = await classify("cat /proc/sys/net/ipv4/ip_forward", "LOOSE")
    expect(d.verdict).toBe("ASK")
    expect(d.rules).toContain("credentials.sensitive-access")
    const hard = await classify("cat /proc/sys/net/ipv4/ip_forward", "HARD")
    expect(hard.verdict).toBe("DENY")
    expect(hard.rules).toContain("data.critical-read")
  })
})

// --- T5: force push is remote-only; irrecoverable-change is local-only -------
describe("T5: git push --force gates on remote alone", () => {
  test("force push denies with git.remote-history-rewrite", async () => {
    for (const script of ["git push --force origin main", "git push -f origin main", "git push --mirror origin"]) {
      const d = await classify(script, "LOOSE")
      expect(d.verdict).toBe("DENY")
      expect(d.rules).toContain("git.remote-history-rewrite")
      expect(d.rules).not.toContain("git.irrecoverable-change")
    }
  })

  test("arming remote clears the force-push deny (dynamic reviewer decides)", async () => {
    for (const script of ["git push --force origin main", "git push -f origin main"]) {
      const d = await classify(script, "LOOSE", armed("remote"))
      expect(d.rules).not.toContain("git.remote-history-rewrite")
      expect(d.rules).not.toContain("git.irrecoverable-change")
    }
  })

  test("arming filesystem alone does not clear the force-push deny", async () => {
    const d = await classify("git push --force origin main", "LOOSE", armed("filesystem"))
    expect(d.verdict).toBe("DENY")
    expect(d.rules).toContain("git.remote-history-rewrite")
  })

  test("ordinary push stays allowed", async () => {
    const d = await classify("git push origin main", "LOOSE")
    expect(d.verdict).toBe("ALLOW")
  })

  // --force-with-lease is a remote history rewrite too: the semantic argv
  // check (fix B) denies it outright instead of leaving it a review signal.
  test("--force-with-lease is denied as remote-history-rewrite", async () => {
    const d = await classify("git push --force-with-lease origin main", "LOOSE")
    expect(d.verdict).toBe("DENY")
    expect(d.rules).toContain("git.remote-history-rewrite")
  })

  // Local-worktree loss keeps its filesystem-keyed review signal.
  describe("git.irrecoverable-change keeps covering local worktree loss", () => {
    for (const script of [
      "git reset --hard HEAD~3",
      "git clean -fdx",
      "git checkout -- .",
      "git restore .",
      "git branch -D main",
    ]) {
      test(`${script} asks with git.irrecoverable-change`, async () => {
        const d = await classify(script, "LOOSE")
        expect(d.verdict).toBe("ASK")
        expect(d.rules).toContain("git.irrecoverable-change")
      })
      test(`${script} is cleared by filesystem`, async () => {
        const d = await classify(script, "LOOSE", armed("filesystem"))
        expect(d.rules).not.toContain("git.irrecoverable-change")
      })
    }

    // Selective/non-destructive git operations stay out of the rule.
    test("lowercase -d branch delete and selective checkout do not fire", async () => {
      for (const script of ["git branch -d merged-feature", "git checkout -b new-branch", "git checkout main"]) {
        const d = await classify(script, "LOOSE")
        expect(d.rules).not.toContain("git.irrecoverable-change")
      }
    })
  })
})

// --- T6: world-writable chmod forms and unshare short flags -------------------
describe("T6: permissions.world-writable covers non-777 world-write grants", () => {
  const worldWritable = [
    "chmod 666 /etc/shadow",
    "chmod 0666 /etc/shadow",
    "chmod 767 x",
    "chmod o+w /etc/shadow",
    "chmod a+w x",
    "chmod go+w x",
    "chmod +w x",
  ]
  for (const script of worldWritable) {
    test(`${script} asks with permissions.world-writable`, async () => {
      const d = await classify(script, "LOOSE")
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("permissions.world-writable")
    })
  }

  // Owner/group-only grants and safe modes stay out of the rule.
  const notWorldWritable = ["chmod 644 x", "chmod 750 x", "chmod 664 x", "chmod u+w x", "chmod g+w x"]
  for (const script of notWorldWritable) {
    test(`${script} does not fire world-writable`, async () => {
      const d = await classify(script, "LOOSE")
      expect(d.rules).not.toContain("permissions.world-writable")
    })
  }

  test("setuid chmod keeps its own rule", async () => {
    const d = await classify("chmod 4755 x", "LOOSE")
    expect(d.rules).toContain("permissions.setuid")
    expect(d.rules).not.toContain("permissions.world-writable")
  })
})

describe("T6: namespace.escape covers unshare short user flags", () => {
  for (const script of ["unshare -Ur bash", "unshare -U bash", "unshare --user bash", "nsenter -t 1 sh"]) {
    test(`${script} asks with namespace.escape (privilege category)`, async () => {
      const d = await classify(script, "LOOSE")
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("namespace.escape")
      const cleared = await classify(script, "LOOSE", armed("privilege"))
      expect(cleared.rules).not.toContain("namespace.escape")
      const hostArmed = await classify(script, "LOOSE", armed("host"))
      expect(hostArmed.rules).toContain("namespace.escape")
    })
  }

  test("unshare without a user/pid/mount namespace stays out", async () => {
    const d = await classify("unshare --fork bash", "LOOSE")
    expect(d.rules).not.toContain("namespace.escape")
  })
})

// --- D3 (round 2): launcher words fire only on executable surfaces -------------
describe("D3: launcher words outside command position never trigger (non-known-safe)", () => {
  // These commands are NOT known-safe, so they reach the trigger families
  // and would catch a launcher word if the scan still ran over plain text.
  const negatives = [
    "some-unknown-tool --label doas",
    "some-unknown-tool x # pkexec id",
    "mytool --user su",
    'git commit -m "use doas"',
  ]
  for (const script of negatives) {
    test(`no privilege finding: ${script}`, async () => {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.rules).not.toContain("operation.context-required")
      expect(d.rules).not.toContain("namespace.escape")
    })
  }

  // Wrapper payloads that are themselves executed keep the privilege gate.
  const positives = [
    "sh -c 'doas id'",
    'eval "pkexec id"',
    "echo $(sudo id)",
    "xargs sudo chown root x",
    "find . -exec sudo chown root x {} +",
  ]
  for (const script of positives) {
    test(`executable surface keeps the privilege gate: ${script}`, async () => {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("operation.context-required")
      const hostArmed = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("host") })
      expect(hostArmed.rules).toContain("operation.context-required")
      const cleared = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("privilege") })
      expect(cleared.verdict).toBe("ASK") // the wrapper/indirection review remains
      expect(cleared.rules).not.toContain("operation.context-required")
    })
  }
})

// --- D4 static (round 2): heredoc body decisions are kept ----------------------
describe("D4: shell heredoc bodies carry non-ALLOW findings", () => {
  const sudoHeredocs = [
    ["unquoted", "bash <<EOF\nsudo id\nEOF"],
    ["quoted", "bash <<'EOF'\nsudo id\nEOF"],
  ] as const
  for (const [label, script] of sudoHeredocs) {
    test(`${label} heredoc body carries the privilege finding`, async () => {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("operation.context-required")
      expect(d.rules).toContain("execution.local-script")
      // Arming privilege clears the privilege finding; the generic
      // local-script review question legitimately remains.
      const cleared = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("privilege") })
      expect(cleared.rules).not.toContain("operation.context-required")
      expect(cleared.rules).toContain("execution.local-script")
    })
  }

  // Benign heredocs must not newly DENY (reviewer-required negatives).
  test("data heredoc stays an inert write", async () => {
    const d = await classify("cat <<EOF\nhello world\nEOF", "LOOSE", { cwd: tempArea, worktree: tempArea })
    expect(d.verdict).toBe("ALLOW")
    expect(d.rules).toContain("operation.heredoc")
  })
  for (const [label, script] of [
    ["lang heredoc", "python3 <<EOF\nprint(1)\nEOF"],
    ["shell heredoc of ls", "bash <<'EOF'\nls\nEOF"],
    ["shell heredoc of echo", "bash <<EOF\necho hi\nEOF"],
  ] as const) {
    test(`${label} keeps its review ask, never a deny`, async () => {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).not.toBe("DENY")
      expect(d.rules).toContain("execution.local-script")
      expect(d.rules).not.toContain("operation.context-required")
    })
  }
})

// --- Consistency (round 2): account/identity tools gate on privilege ---------
describe("account and identity tools gate on the privilege category", () => {
  const accountTools = [
    "useradd bob",
    "usermod -aG wheel bob",
    "userdel bob",
    "passwd root",
    "chpasswd",
    "visudo",
    "runuser -u root -- id",
    "setpriv --reuid=0 id",
    "capsh --print",
  ]
  for (const script of accountTools) {
    test(`${script} asks with a privilege-keyed gate`, async () => {
      const d = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea })
      expect(d.verdict).toBe("ASK")
      expect(d.rules).toContain("operation.context-required")
      const hostArmed = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("host") })
      expect(hostArmed.rules).toContain("operation.context-required")
      const cleared = await classify(script, "LOOSE", { cwd: tempArea, worktree: tempArea, ...armed("privilege") })
      expect(cleared.rules).not.toContain("operation.context-required")
    })
  }
})
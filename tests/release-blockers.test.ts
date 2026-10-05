import { afterAll, beforeEach, describe, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { mkdtemp, writeFile, symlink, mkdir } from "node:fs/promises"
import { cleanupTestArtifacts as rm } from "./artifacts"
import path from "node:path"
import { Cause, Effect, Exit, Option, Scope, Stream } from "effect"
import plugin from "../src/index"
import { collectBoundedEvidence } from "../src/security/automatic"
import {
  CATEGORY_HEADER_PREFIX,
  ESCALATION_MARKER,
  JUSTIFICATION_HEADER_PREFIX,
} from "../src/security/escalation"
import { resetEscalationReviewLimiter } from "../src/security/escalation-reviewer"

// Release-blocker regression tests (1.5.0 gate):
//   * session partitioning — a report produced by session A never admits a
//     call in session B (report keys embed sessionID; get() re-checks it);
//   * one_time admission is never cached/replayed;
//   * allow_once binds to the P0-reviewed facts — a script mutated between
//     verdict and admission must not ride the stale approval;
//   * tiered static DENY — terminal/floor deny instantly, ordinary DENY
//     completes a P0 report through ONE review, a residual rule after a
//     grant names the uncovered kind;
//   * collect_evidence only triggers on the explicit decision word — a raw
//     ALLOW carrying needsEvidence diagnostics is still an agreement;
//   * collector hardening — resolved-path sensitive-name guard (symlink to
//     .env), byte-bounded descriptor reads, oversized subjects reported
//     missing, subject bound + resolved-path dedupe.
//
// All reviewer traffic is mocked; no fixture command is executed and no real
// secret file is ever touched (fake .env values only).

let workdir: string | undefined
const scopes: Scope.Closeable[] = []
const servers: Server[] = []

async function ensureWorkdir() {
  if (!workdir) workdir = await mkdtemp(path.join("/tmp/opencode/", "release-blockers-"))
  return workdir
}

beforeEach(() => resetEscalationReviewLimiter())

afterAll(async () => {
  for (const scope of scopes) {
    await Effect.runPromise(Scope.close(scope, undefined as never)).catch(() => {})
  }
  for (const server of servers) {
    await new Promise<void>((resolve) => server.close(() => resolve()))
  }
  if (workdir) await rm(workdir, { recursive: true, force: true })
})

type CapturedRequest = { body: Record<string, unknown>; authorization: string | undefined }
type Responder = (body: Record<string, unknown>) => { status?: number; content?: string } | Promise<{ status?: number; content?: string }>

async function startReviewer(responder: Responder) {
  const requests: CapturedRequest[] = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on("data", (chunk: Buffer) => chunks.push(chunk))
    req.on("end", async () => {
      let body: Record<string, unknown> = {}
      try {
        body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>
      } catch { /* assertion side reports */ }
      requests.push({ body, authorization: req.headers.authorization })
      const answer = await responder(body)
      const status = answer.status ?? 200
      const payload =
        status === 200
          ? JSON.stringify({ choices: [{ message: { role: "assistant", content: answer.content ?? "deny" } }] })
          : JSON.stringify({ error: "mock reviewer error" })
      res.writeHead(status, { "Content-Type": "application/json" })
      res.end(payload)
    })
  })
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  servers.push(server)
  const port = (server.address() as AddressInfo).port
  return { endpoint: `http://127.0.0.1:${port}/v1`, requests }
}

type DynamicReviewResult = {
  decision: "ALLOW" | "DENY" | string
  categories: string[]
  secondary_categories?: string[]
  bypassing?: boolean
  assessment?: Record<string, unknown>
}
type DynamicCall = { command: string; userBypass?: string[] }
type CommandExec = (input: { sessionID: string; prompt: { text: string } }) => Effect.Effect<void, unknown>
type HookCb = (ev: never) => Effect.Effect<void, unknown>

type Harness = {
  executeBefore: HookCb
  commands: Map<string, CommandExec>
  synthetic: Array<{ sessionID: string; text: string; description?: string }>
  dynamicCalls: DynamicCall[]
  notice: (sessionID: string) => Promise<string>
}

async function failureMessage(effect: Effect.Effect<unknown, unknown>): Promise<string | undefined> {
  const exit = await Effect.runPromise(Effect.exit(effect))
  if (!Exit.isFailure(exit)) return undefined
  const found = Cause.findErrorOption(exit.cause)
  const error = Option.isSome(found) ? found.value : undefined
  return error instanceof Error ? error.message : String(error)
}

const escalation = (categories: string, justification: string, command: string) =>
  [ESCALATION_MARKER, `${CATEGORY_HEADER_PREFIX} ${categories}`, `${JUSTIFICATION_HEADER_PREFIX} ${justification}`, command].join("\n")

async function startPlugin(
  options: Record<string, unknown>,
  mock: { endpoint: string; requests: CapturedRequest[] },
  review: (request: { command?: string; userBypass?: string[] }) => DynamicReviewResult,
): Promise<Harness> {
  const directory = await ensureWorkdir()
  const collected: Partial<Record<string, HookCb>> = {}
  const commands = new Map<string, CommandExec>()
  const synthetic: Harness["synthetic"] = []
  const dynamicCalls: DynamicCall[] = []
  let contextCb:
    | ((ev: { sessionID: string; system: Array<{ type: string; text: string }> }) => Effect.Effect<void>)
    | undefined

  let h!: Harness
  const reviewCommand = async (request: { command?: string; userBypass?: string[] }) => {
    h.dynamicCalls.push({ command: request.command ?? "", userBypass: request.userBypass })
    return review(request)
  }

  const ctx = {
    options: {
      failPolicy: "fail_close",
      logReviewerTrace: false,
      sandbox: { enabled: false },
      dynamicReview: {
        baseURL: mock.endpoint,
        model: "release-blocker-model",
        apiKey: "release-blocker-key",
        timeoutMs: 15000,
        maxRounds: 1,
      },
      reviewCommand,
      ...options,
    },
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
      get: () => Effect.succeed({ location: { directory } }),
      interrupt: () => Effect.void,
      context: () => Effect.succeed([{ type: "user", text: "run the task's build" }]),
      synthetic: (input: { sessionID: string; text: string; description?: string }) =>
        Effect.sync(() => {
          synthetic.push(input)
        }),
      hook: (name: string, cb: (ev: { sessionID: string; system: Array<{ type: string; text: string }> }) => Effect.Effect<void>) => {
        if (name === "context") contextCb = cb
        return Effect.void
      },
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

  h = {
    executeBefore: collected["execute.before"]!,
    commands,
    synthetic,
    dynamicCalls,
    notice: async (sessionID: string) => {
      const event = { sessionID, system: [{ type: "text", text: "base" }] }
      if (contextCb) await Effect.runPromise(contextCb(event as never))
      return event.system.map((p) => p.text).join("\n")
    },
  }
  return h
}

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

const decision = (word: "allow_once" | "deny" | "collect_evidence"): Responder => () => ({ content: word })

/** Parse the billed risk set from a block message's `Risk categories:` line —
 *  exact set equality, never a whole-message substring match (the guide text
 *  lists every category name, so `toContain` alone proves nothing). */
function billedCategories(message: string | undefined): Set<string> {
  const match = /Risk categories: ([a-z, ]+?) — /.exec(message ?? "")
  if (!match) return new Set()
  return new Set(
    match[1]
      .split(",")
      .map((category) => category.trim())
      .filter(Boolean),
  )
}

// ---------------------------------------------------------------------------

describe("report cache session partitioning", () => {
  test("an allow report from session A never replays for session B", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))
    const cmd = "cat secrets.txt && cp secrets.txt /tmp/out.txt"

    // Session A earns the cached allow; an identical call replays it.
    expect(await runBefore(h, "sA", { command: cmd })).toBeUndefined()
    expect(await runBefore(h, "sA", { command: cmd })).toBeUndefined()
    expect(h.dynamicCalls).toHaveLength(1)

    // Session B issues the identical command — same cwd/perm/bypass — and
    // must get a FRESH review, never session A's judgment.
    expect(await runBefore(h, "sB", { command: cmd })).toBeUndefined()
    expect(h.dynamicCalls).toHaveLength(2)
    // And B's own replay is now cached under B's partition.
    expect(await runBefore(h, "sB", { command: cmd })).toBeUndefined()
    expect(h.dynamicCalls).toHaveLength(2)
    expect(mock.requests).toHaveLength(0) // dynamic review is injected, no HTTP
  })

  test("a one_time escalation admission is consumed by its call and never replays", async () => {
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))
    const cmd = "echo x > /etc/app.conf"
    const esc = () => ({ command: escalation("filesystem", "write the config once", cmd) })

    // First escalation admits…
    expect(await runBefore(h, "sA", esc())).toBeUndefined()
    expect(mock.requests).toHaveLength(1)

    // …the identical second escalation must go back through the reviewer —
    // allow_once consumed the report; it is never replayed from cache.
    expect(await runBefore(h, "sA", esc())).toBeUndefined()
    expect(mock.requests).toHaveLength(2)
  })
})

describe("allow_once fact binding", () => {
  test("a script mutated between the verdict and admission is denied, not admitted", async () => {
    const dir = await ensureWorkdir()
    const scriptPath = path.join(dir, "helper.py")
    await writeFile(scriptPath, "print('v1')\n")

    let mutate = false
    const mock = await startReviewer(async () => {
      // The responder flips the target between verdict and admission —
      // AWAITED, so the reply only goes out after the swap lands. The write
      // is same-length: size checks pass, only the true fingerprint
      // (mtime/content identity) can distinguish v2 from v1. Every other
      // fact (path set, cwd, perm, reviewContext) stays identical.
      if (mutate) await writeFile(scriptPath, "print('v2')\n")
      return { content: "allow_once" }
    })
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))
    const esc = () => ({ command: escalation("host", "run the checked helper", "python3 helper.py") })

    // Control: unchanged facts admit.
    expect(await runBefore(h, "sA", esc())).toBeUndefined()
    expect(mock.requests).toHaveLength(1)

    // Mutated facts: the t0 reviewed snapshot no longer holds at admission.
    mutate = true
    const denied = await runBefore(h, "sA", esc())
    expect(denied).toBeDefined()
    expect(denied).toContain("changed after")
    expect(denied).not.toContain("Blocked by dynamic")
  })
})

describe("tiered static DENY", () => {
  test("a compound ordinary DENY reports the full footprint — not the first segment's rules only", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      // The model completes the P0 picture; the verdict stays static DENY.
      return { decision: "ALLOW", categories: [] }
    })

    // .env delete fires data.critical-delete (secret owner); the model's
    // primary set completes the picture — the billed set is the union of
    // rule owners and model primaries.
    const denied = await runBefore(h, "s1", {
      command: "rm -f .env && rm -rf /tmp/scratch-docs",
    })
    expect(denied).toBeDefined()
    expect(denied).toContain("Blocked by static classifier")
    expect(denied).toContain("filesystem")
    expect(denied).toContain("secret")
    expect(calls).toBe(1) // exactly ONE P0 review completed the report
  })

  test("a credential delete bills secret only — a secret-only approval admits, no residual filesystem kind", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return { decision: "ALLOW", categories: [] }
    })

    // P0: data.critical-delete owns secret alone (policyVersion 1.5 owner
    // semantics) — the first report bills only `secret`, not the object's
    // mechanical filesystem side-effect.
    const denied = await runBefore(h, "s1", { command: "rm -f .env" })
    expect(denied).toBeDefined()
    expect(denied).toContain("Blocked by static classifier")
    // Billed owner set is exactly {secret} — the credential's mechanical
    // filesystem side-effect is not a second kind.
    expect(billedCategories(denied)).toEqual(new Set(["secret"]))
    expect(calls).toBe(1)

    // P1: the secret-only approval IS sufficient coverage — the call is
    // admitted, no second review, no residual filesystem kind appears.
    const escalated = { command: escalation("secret", "remove the stale env file", "rm -f .env") }
    expect(await runBefore(h, "s1", escalated)).toBeUndefined()
    expect(mock.requests).toHaveLength(1)
    expect(calls).toBe(1)
  })

  test("a filesystem-only approval must not smuggle in the uncovered secret kind", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))

    // The report approved filesystem — but the residual secret kind in
    // data.critical-delete was never part of that approval.
    const denied = await runBefore(h, "s1", {
      command: escalation("filesystem", "remove the stale env file", "rm -f .env"),
    })
    expect(denied).toBeDefined()
    expect(denied).toContain("Blocked by static classifier")
    expect(denied).toContain("secret")
    expect(mock.requests).toHaveLength(1)
  })

  test("a compound needs the union of owners: secret-only denies on the uncovered filesystem segment, full approval admits", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return { decision: "ALLOW", categories: [] }
    })
    // The independent filesystem target is a REAL existing directory — an
    // existing referenced path stays out of the collector's missing list and
    // the forced-recursive rule needs no unverifiable `~` expansion.
    const docsDir = path.join(dir, "docs-target")
    await mkdir(docsDir)
    const cmd = `rm -f .env && rm -rf ${path.join(dir, "docs-target")}`

    // P0: combine-aggregated rules bill the FULL known set — credential
    // delete owns secret, the independent forced-delete segment owns
    // filesystem. Even a model that only names `secret` cannot shrink it:
    // the billed union keeps the rule owners.
    const first = await runBefore(h, "s1", { command: cmd })
    expect(first).toBeDefined()
    expect(billedCategories(first)).toEqual(new Set(["secret", "filesystem"]))
    expect(calls).toBe(1)

    // P1 secret-only: the independent filesystem segment's kind was never
    // approved. The escalation reviewer's coverage gate sees the recorded
    // {secret, filesystem} denial vs the {secret} request and refuses BEFORE
    // any approval — the call is denied, never admitted on a partial grant.
    const partial = await runBefore(h, "s1", {
      command: escalation("secret", "clean up", cmd),
    })
    expect(partial).toBeDefined()
    expect(partial).toMatch(/Escalation could not be authorized|denied|Blocked/)

    // P1 full approval: both kinds covered — the call admits.
    const full = await runBefore(h, "s1", {
      command: escalation("secret,filesystem", "clean up", cmd),
    })
    expect(full).toBeUndefined()
  })

  test("weakening a credential's protection bills secret only — no privilege kind on the same object", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({ decision: "ALLOW", categories: [] }))

    // chmod 777 .env fires the credential rules; the generic world-writable
    // privilege kind on the SAME object is suppressed — secret-only admits.
    const escalated = { command: escalation("secret", "fix permissions", "chmod 777 .env") }
    expect(await runBefore(h, "s1", escalated)).toBeUndefined()
    expect(mock.requests).toHaveLength(1)
  })

  test("a genuine privilege segment keeps its own owner alongside secret", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return { decision: "ALLOW", categories: [] }
    })

    // rm -f .env owns secret; chmod u+s owns privilege — the compound's P0
    // report must bill BOTH from the statically identified segments: the
    // credential delete denies, the setuid segment's privilege kind is part
    // of the combined rule set, not a hidden kind admitted silently.
    const denied = await runBefore(h, "s1", { command: "rm -f .env && chmod u+s helper.bin" })
    expect(denied).toBeDefined()
    expect(denied).toContain("Blocked by static classifier")
    expect(billedCategories(denied)).toEqual(new Set(["secret", "privilege"]))
    expect(calls).toBe(1)
  })

  test("the P0 footprint bills rule owners AND the model's independent kinds — three independent sources", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    await writeFile(path.join(dir, "ordinary.json"), "{}\n")
    const mock = await startReviewer(decision("allow_once"))
    const h = await startPlugin({}, mock, () => ({
      // The model's primary set is {secret, network}: an independent egress
      // kind it judged real. The statically identified rule owners join —
      // secret from the credential delete AND filesystem from the ordinary
      // file's own delete rule — so the billed set is the full known
      // footprint {secret, filesystem, network}, three independent sources.
      decision: "ALLOW",
      categories: ["secret", "network"],
    }))

    const denied = await runBefore(h, "s1", {
      command: "rm -f .env && rm -f ordinary.json",
    })
    expect(denied).toBeDefined()
    expect(denied).toContain("Blocked by static classifier")
    expect(billedCategories(denied)).toEqual(new Set(["secret", "filesystem", "network"]))
  })

  test("a floor that only appears under the armed shape still denies instantly", async () => {
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return { decision: "ALLOW", categories: [] }
    })
    // Root delete hides behind a bypassable first segment — the armed-shape
    // check still finds the floor and refuses before any reviewer.
    const denied = await runBefore(h, "s1", {
      command: "rm -f .env ; rm -rf /",
    })
    expect(denied).toBeDefined()
    expect(calls).toBe(0)
    expect(mock.requests).toHaveLength(0)
  })
})

describe("verdict priority — raw agreement is never vetoed by diagnostics", () => {
  test("ALLOW with needsEvidence diagnostics admits without a second review", async () => {
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return {
        decision: "ALLOW",
        categories: [],
        assessment: {
          categories: [],
          strongReasons: [],
          needsEvidence: ["uninspected binary blob"],
          decisionSource: "model",
        },
      }
    })
    const cmd = "cat secrets.txt && cp secrets.txt /tmp/out.txt"
    expect(await runBefore(h, "s1", { command: cmd })).toBeUndefined()
    expect(calls).toBe(1) // no evidence pass, no resubmit — raw agree stands
  })

  test("DENY with needsEvidence diagnostics denies once — no fake second review", async () => {
    const mock = await startReviewer(decision("allow_once"))
    let calls = 0
    const h = await startPlugin({}, mock, () => {
      calls += 1
      return {
        decision: "DENY",
        categories: ["filesystem"],
        assessment: {
          categories: ["filesystem"],
          strongReasons: [],
          needsEvidence: ["script hash unavailable"],
          decisionSource: "model",
        },
      }
    })
    const denied = await runBefore(h, "s1", { command: "cat secrets.txt && cp secrets.txt /tmp/out.txt" })
    expect(denied).toBeDefined()
    expect(denied).toContain("Blocked by dynamic classifier")
    expect(calls).toBe(1)
  })
})

// ---------------------------------------------------------------------------

describe("bounded evidence collector", () => {
  test("a symlink alias to a sensitive name is never collected", async () => {
    const dir = await ensureWorkdir()
    const fake = path.join(dir, "linked.env")
    await writeFile(fake, "TOKEN=fake-fixture-not-real\n")
    const alias = path.join(dir, "script.py")
    await symlink(fake, alias)

    const { evidence, missing } = await collectBoundedEvidence(
      [{ subject: "script.py" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(0)
    expect(missing).toContain("script.py")
    expect(JSON.stringify(evidence)).not.toContain("fake-fixture")
  })

  test("a direct sensitive name is missing even inside the worktree", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, ".env"), "TOKEN=fake-fixture-not-real\n")
    const { evidence, missing } = await collectBoundedEvidence(
      [{ subject: ".env" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(0)
    expect(missing).toContain(".env")
  })

  test("oversized files report missing — a prefix is not treated as evidence", async () => {
    const dir = await ensureWorkdir()
    const big = path.join(dir, "huge.py")
    await writeFile(big, "x".repeat(80 * 1024))
    const { evidence, missing } = await collectBoundedEvidence(
      [{ subject: "huge.py" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(0)
    expect(missing.some((m) => m.includes("huge.py"))).toBe(true)
  })

  test("resolved-path dedupe reads a file once; subject bound is enforced", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, "a.py"), "print('a')\n")
    const subjects = [
      { subject: "a.py" },
      { subject: "./a.py" },
      { subject: "sub/../a.py" },
    ]
    await mkdir(path.join(dir, "sub"))
    const { evidence } = await collectBoundedEvidence(subjects, { cwd: dir, worktree: dir })
    expect(evidence).toHaveLength(1)

    const over = Array.from({ length: 20 }, (_, i) => ({ subject: `missing-${i}.py` }))
    const result = await collectBoundedEvidence(over, { cwd: dir, worktree: dir })
    // Subjects past the bound are named missing, not silently dropped.
    expect(result.missing.length).toBe(20)
    expect(result.missing.some((m) => m.includes("bound"))).toBe(true)
  })

  test("directory listings stream with a real cap — truncation is detected without reading the whole tree", async () => {
    const dir = await ensureWorkdir()
    const big = path.join(dir, "many")
    await mkdir(big)
    for (let i = 0; i < 140; i++) {
      await writeFile(path.join(big, `f${String(i).padStart(3, "0")}.txt`), "x")
    }
    const { evidence } = await collectBoundedEvidence(
      [{ subject: "many" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(1)
    expect(evidence[0].kind).toBe("directory")
    expect(evidence[0].truncated).toBe(true)
    expect(evidence[0].excerpt.split("\n").length).toBe(128)
    // Evidence carries an identity the admission path can re-verify.
    expect(evidence[0].identity?.resolvedPath).toBe(big)
  })

  test("script evidence carries the read-time object identity", async () => {
    const dir = await ensureWorkdir()
    await writeFile(path.join(dir, "a.py"), "print('a')\n")
    const { evidence } = await collectBoundedEvidence(
      [{ subject: "a.py" }],
      { cwd: dir, worktree: dir },
    )
    expect(evidence).toHaveLength(1)
    expect(evidence[0].identity).toBeDefined()
    expect(evidence[0].identity!.ino).toBeGreaterThan(0)
    expect(evidence[0].identity!.resolvedPath).toBe(path.join(dir, "a.py"))
  })

  test("outside-worktree subjects stay missing until the reader boundary widens", async () => {
    const dir = await ensureWorkdir()
    const outside = await mkdtemp(path.join("/tmp/opencode/", "collector-out-"))
    try {
      await writeFile(path.join(outside, "ext.py"), "print('ext')\n")
      const confined = await collectBoundedEvidence(
        [{ subject: path.join(outside, "ext.py") }],
        { cwd: dir, worktree: dir },
      )
      expect(confined.evidence).toHaveLength(0)
      const widened = await collectBoundedEvidence(
        [{ subject: path.join(outside, "ext.py") }],
        { cwd: dir, worktree: dir, allowFullReadAccess: true },
      )
      expect(widened.evidence).toHaveLength(1)
      expect(widened.evidence[0].excerpt).toContain("ext")
    } finally {
      await rm(outside, { recursive: true, force: true })
    }
  })
})

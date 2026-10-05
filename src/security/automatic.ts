// automatic.ts — unattended decision flow for the assessment host.
//
// The plugin is fully automatic: there is no agent-facing "ask the user"
// path anywhere. A reviewer outcome is one of exactly three automatic
// sources, and every one is resolved without human interaction:
//
//   automatic_approval  — the model allowed (dynamic ALLOW / escalation
//                         allow_once). Raw allowance is honored verbatim; no
//                         secondary probability or weak-hint veto re-judges
//                         it.
//   collect_evidence    — the reviewer asked for more context. The host
//                         collects bounded evidence ONCE, resubmits ONCE,
//                         and denies with a named limitation when the bound
//                         or a still-missing request is reached. A legacy
//                         "ask_user" decision rides the same path: needing
//                         human judgment is treated as needing more evidence,
//                         and when nothing collectable remains the denial
//                         names the limitation instead of waiting on a human.
//   deny                — the model denied. The reason and complete minimal
//                         category set are reported; the denial may still be
//                         self-authorized by resubmitting the command under
//                         the REQUIRE_ESCALATION header (agent-initiated
//                         authorization request), never by asking a human.
//
// Program stops keep their own source labels (see AssessmentSource) and are
// never reported as "the model denied".

import { constants } from "node:fs"
import { lstat, open, opendir, readlink, realpath, stat } from "node:fs/promises"
// `readdir` is deliberately not used: directory evidence streams through
// `opendir` with a cap+1 bound instead of materializing huge listings.
import path from "node:path"
import type { AssessmentSource, CollectedEvidence } from "./assessment"

// ---------------------------------------------------------------------------
// Decision shapes
// ---------------------------------------------------------------------------

/** Raw reviewer decisions the host understands. `ask_user` is the legacy
 *  spelling of "the reviewer cannot decide automatically"; `collect_evidence`
 *  is the upgraded contract name. Neither waits on a human. */
export type RawReviewerDecision =
  | "ALLOW"
  | "DENY"
  | "allow_once"
  | "ask_user"
  | "collect_evidence"
  | "deny"

export interface EvidenceRequest {
  /** What the reviewer asked for (path or logical subject). */
  subject: string
  /** Preferred evidence kind when known. */
  kind?: CollectedEvidence["kind"]
}

export interface AutomaticOutcome {
  kind: "admit" | "recollect" | "deny"
  /** True when the outcome came from a real model answer. */
  modelRaw: boolean
  /** Program/source label for traces and reports. */
  source: AssessmentSource
  /** For recollect: what could not be obtained (drives named-limit deny). */
  missing?: string[]
  /** For deny: agent-facing limitation when the denial is evidence-bounded. */
  limitation?: string
}

/** Map a raw reviewer decision to the automatic outcome. The mapping is
 *  total: every contract value resolves without user interaction. */
export function automaticOutcome(decision: RawReviewerDecision): AutomaticOutcome {
  switch (decision) {
    case "ALLOW":
    case "allow_once":
      return { kind: "admit", modelRaw: true, source: "model_decision" }
    case "collect_evidence":
    case "ask_user":
      // Legacy ask_user = "I cannot decide" — resolve it by evidence, not by
      // involving a human.
      return { kind: "recollect", modelRaw: true, source: "model_decision" }
    case "DENY":
    case "deny":
      return { kind: "deny", modelRaw: true, source: "model_decision" }
  }
}

// ---------------------------------------------------------------------------
// Bounded evidence collection
// ---------------------------------------------------------------------------

export const EVIDENCE_MAX_SCRIPT_BYTES = 64 * 1024
export const EVIDENCE_MAX_SCRIPTS = 8
export const EVIDENCE_MAX_DIR_ENTRIES = 128
export const EVIDENCE_MAX_SUBJECTS = 16

/** Names that must never be collected into a review payload, mirroring the
 *  classifier's own guards (`isCriticalOriginalPath` / fingerprint rejection
 *  treat `*env`, `.netrc`, `.npmrc`, key files and credential dirs the same).
 *  Applied to the subject AND to the resolved canonical path's basename —
 *  a `helper.py` symlink pointing at `.env` must not leak secrets.
 *  Leaf names only: a `docs/` subject or `envoy.yaml`-like unrelated words
 *  are not blanket-blocked. */
const NEVER_COLLECT_PATH =
  /(?:^|[\\/])(?:\.aws|\.ssh|\.gnupg|\.docker|\.kube)(?:[\\/]|$)|(?:^|[\\/])(?:\.netrc|\.npmrc|\.pgpass)$|(?:^|[\\/])id_(?:rsa|dsa|ecdsa|ed25519)(?:\.|$)/i
const NEVER_COLLECT_LEAF =
  /(?:^|\.)env(?:\.|$)|^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.|$)|^\.(?:netrc|npmrc|pgpass)$/i

function isNeverCollectPath(target: string): boolean {
  return NEVER_COLLECT_PATH.test(target) || NEVER_COLLECT_LEAF.test(path.basename(target))
}

/** Collect bounded evidence for the subjects the reviewer asked about.
 *  Subjects outside the worktree, unreadable, non-regular, oversized, or
 *  matching the sensitive-name guard (checked on the resolved path) are not
 *  collected — they are returned in `missing` so the denial can name the
 *  limitation. File reads are byte-bounded at the descriptor level (never a
 *  whole-file read then slice); an oversized file reports `missing`, not a
 *  misleadingly "complete" prefix. No hashing, no writes, read-only. */
export async function collectBoundedEvidence(
  subjects: readonly EvidenceRequest[],
  opts: {
    cwd: string
    worktree: string
    /** Explicit reader boundary: `allowFullReadAccess` (dynamicReview
     *  config) widens collection beyond the worktree — matching the boundary
     *  the reviewer itself was granted. The default stays worktree-confined;
     *  the sensitive-name guard is absolute in both modes. */
    allowFullReadAccess?: boolean
  },
): Promise<{ evidence: CollectedEvidence[]; missing: string[] }> {
  const evidence: CollectedEvidence[] = []
  const missing: string[] = []
  const seen = new Set<string>()
  let scriptsRead = 0
  const root = await realpath(opts.worktree).catch(() => opts.worktree)
  const insideRoot = (p: string) =>
    p === root || p.startsWith(root.endsWith(path.sep) ? root : root + path.sep)
  for (const request of subjects.slice(0, EVIDENCE_MAX_SUBJECTS)) {
    const subject = request.subject
    if (isNeverCollectPath(subject)) {
      missing.push(subject)
      continue
    }
    const expanded = subject.replace(/^~(?=$|[\\/])/, process.env.HOME ?? "~")
    const absolute = path.isAbsolute(expanded) ? expanded : path.resolve(opts.cwd, expanded)
    let canonical: string
    try {
      canonical = await realpath(absolute)
    } catch {
      missing.push(subject)
      continue
    }
    // Dedupe on the RESOLVED path so `a.py`, `./a.py` and a symlink alias
    // never read the same content twice.
    if (seen.has(canonical)) continue
    seen.add(canonical)
    // Sensitive-name guard on the resolved basename (symlinked `.env`
    // aliases land here even when the subject looked harmless).
    if (isNeverCollectPath(canonical)) {
      missing.push(subject)
      continue
    }
    if (!opts.allowFullReadAccess && !insideRoot(canonical)) {
      missing.push(subject)
      continue
    }
    try {
      const info = await stat(canonical)
      if (info.isDirectory()) {
        // Bounded streaming: iterate at most cap+1 entries so the truncation
        // flag is real — never a full readdir-then-slice on a huge tree.
        const entries: string[] = []
        let truncated = false
        const dirHandle = await opendir(canonical)
        for await (const entry of dirHandle) {
          if (entries.length >= EVIDENCE_MAX_DIR_ENTRIES) {
            truncated = true
            break
          }
          entries.push(
            `${entry.name}${entry.isDirectory() ? "/" : entry.isSymbolicLink() ? "@" : ""}`,
          )
        }
        entries.sort()
        evidence.push({
          kind: "directory",
          subject,
          excerpt: entries.join("\n"),
          truncated,
          identity: {
            resolvedPath: canonical,
            dev: info.dev,
            ino: info.ino,
            size: info.size,
            mtimeMs: info.mtimeMs,
          },
        })
      } else if (scriptsRead < EVIDENCE_MAX_SCRIPTS) {
        // Byte-bounded descriptor read with identity verification:
        //   1. O_NOFOLLOW where the platform offers it — the fd opens the
        //      leaf object itself, not a symlink swapped in after realpath.
        //   2. fstat confirms a REGULAR file inside the byte bound.
        //   3. A post-open lstat of the licensed canonical path must match
        //      the fd's dev+ino: the file we resolved and the file we opened
        //      are the same object — the realpath→open gap cannot substitute
        //      a different one.
        //   4. Linux /proc/self/fd readlink names the actual backing object;
        //      it must equal the canonical path (deleted-suffix stripped).
        // An oversized or identity-mismatched subject is `missing`, never a
        // misleadingly "complete" excerpt.
        const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)
        const handle = await open(canonical, flags)
        try {
          const fileInfo = await handle.stat()
          if (!fileInfo.isFile()) {
            missing.push(subject)
            continue
          }
          const licensed = await lstat(canonical).catch(() => undefined)
          if (
            !licensed ||
            licensed.dev !== fileInfo.dev ||
            licensed.ino !== fileInfo.ino
          ) {
            missing.push(subject)
            continue
          }
          const fdTarget = await readlink(`/proc/self/fd/${handle.fd}`).catch(() => undefined)
          if (fdTarget !== undefined && fdTarget.replace(/ \(deleted\)$/, "") !== canonical) {
            missing.push(subject)
            continue
          }
          if (fileInfo.size > EVIDENCE_MAX_SCRIPT_BYTES) {
            missing.push(`${subject} (exceeds ${EVIDENCE_MAX_SCRIPT_BYTES}-byte evidence bound)`)
            continue
          }
          const buffer = Buffer.alloc(Math.min(fileInfo.size, EVIDENCE_MAX_SCRIPT_BYTES))
          const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
          evidence.push({
            kind: "script",
            subject,
            excerpt: buffer.subarray(0, bytesRead).toString("utf8"),
            truncated: bytesRead < fileInfo.size,
            identity: {
              resolvedPath: canonical,
              dev: fileInfo.dev,
              ino: fileInfo.ino,
              size: fileInfo.size,
              mtimeMs: fileInfo.mtimeMs,
            },
          })
          scriptsRead += 1
        } finally {
          await handle.close()
        }
      } else {
        missing.push(subject)
      }
    } catch {
      missing.push(subject)
    }
  }
  for (const request of subjects.slice(EVIDENCE_MAX_SUBJECTS)) {
    missing.push(`${request.subject} (evidence subject bound reached)`)
  }
  return { evidence, missing }
}

// ---------------------------------------------------------------------------
// Agent-facing phrasing (no human-confirmation paths)
// ---------------------------------------------------------------------------

/** Terminal outcome text: names the remaining automatic route without ever
 *  telling the agent to ask a human. Authorization surfaces (/bypass, /perm)
 *  are the user's to invoke — the agent's own route is REQUIRE_ESCALATION or
 *  skipping the step. */
export function terminalOutcomeText(kind: "floor" | "denied" | "evidence"): string {
  switch (kind) {
    case "floor":
      return (
        "This outcome is terminal for the session: do not reach the same effect through other " +
        "commands, wrappers, or scripts. Skip the step if it is not required."
      )
    case "evidence":
      return (
        "The review could not obtain the evidence it requires, and automatic collection is " +
        "exhausted — the denial names that limitation, not a risk judgment. Do not retry the " +
        "same command; skip the step or retry with the required inputs made inspectable."
      )
    case "denied":
      return (
        "Do not retry the same command unchanged and do not route around the denial through " +
        "wrappers or scripts. To self-authorize a different posture, resubmit once with the " +
        "REQUIRE_ESCALATION header and the exact categories the command needs."
      )
  }
}

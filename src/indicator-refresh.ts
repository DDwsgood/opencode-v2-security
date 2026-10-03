// Refresh coordination for the TUI permission/bypass indicator, split out of
// tui.tsx so the ordering rules can be unit-tested without the solid-js /
// @opentui runtime.
//
// The indicator is fed by two channels with different freshness semantics:
//
// - RPC events (`changed`, `permission`) are ephemeral pushes. When one
//   arrives it is the newest known state and applies immediately.
// - The `status` RPC method is an authoritative snapshot, but it is async: a
//   reply started before a newer event must never overwrite it.
//
// StatusRevisions encodes that ordering with two per-session counters. An
// event bumps the event counter; a pull records the event counter at start.
// The reply applies only while it is still the newest pull AND no event
// arrived after it started.

/** Ticket returned by `beginPull`; pass it to `mayApply` when the RPC resolves. */
export type PullTicket = {
  /** Lifecycle generation: bumped by `drop`, so a ticket minted before a
   *  session was dropped can never match the restarted counters. */
  readonly gen: number
  /** Revision of this pull among all pulls for the session. */
  readonly pull: number
  /** Event revision observed when the pull started. */
  readonly event: number
}

export class StatusRevisions {
  private events = new Map<string, number>()
  private pulls = new Map<string, number>()
  private gens = new Map<string, number>()

  /** A live RPC event for this session just applied newer state: every pull
   *  already in flight is now stale. */
  markEvent(sessionID: string): void {
    this.events.set(sessionID, (this.events.get(sessionID) ?? 0) + 1)
  }

  /** Begin a status pull for the session. */
  beginPull(sessionID: string): PullTicket {
    const pull = (this.pulls.get(sessionID) ?? 0) + 1
    this.pulls.set(sessionID, pull)
    return { gen: this.gens.get(sessionID) ?? 0, pull, event: this.events.get(sessionID) ?? 0 }
  }

  /** Whether the pull that produced `ticket` may still write its result:
   *  only while no newer pull started and no event arrived after it began. */
  mayApply(sessionID: string, ticket: PullTicket): boolean {
    return (
      (this.gens.get(sessionID) ?? 0) === ticket.gen &&
      this.pulls.get(sessionID) === ticket.pull &&
      (this.events.get(sessionID) ?? 0) === ticket.event
    )
  }

  /** Forget a session entirely (session.deleted, plugin teardown). Bumping
   *  the generation — rather than only clearing the counters — keeps a
   *  pre-drop ticket stale even if a new pull reuses its pull/event numbers. */
  drop(sessionID: string): void {
    this.gens.set(sessionID, (this.gens.get(sessionID) ?? 0) + 1)
    this.events.delete(sessionID)
    this.pulls.delete(sessionID)
  }
}

/** Sessions worth re-pulling after an RPC state event for `sourceID`.
 *
 * The server emits `changed`/`permission` only for the session that was
 * mutated, but descendants silently inherit the change through their parent
 * chain (bypass leases and the permission ceiling both propagate). Rather
 * than guessing which members moved, the TUI re-pulls a snapshot for every
 * other member of the source's family; the source itself is skipped because
 * the event payload is already authoritative. `family` may be empty or miss
 * the source — both degrade to "nothing extra to pull". */
export function sessionsToRefresh(sourceID: string, family: readonly string[]): string[] {
  const out: string[] = []
  for (const id of family) {
    if (id !== sourceID && !out.includes(id)) out.push(id)
  }
  return out
}

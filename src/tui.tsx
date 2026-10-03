/** @jsxImportSource @opentui/solid */
// TUI companion for opencode-v2-security.
//
// User-facing half of the notification design: the server plugin cannot
// publish toasts (its context has only `event.subscribe`), and it must not
// report state through a session message because every message type is
// model-visible. Instead the server emits ephemeral RPC events
// (`src/bypass-rpc.ts`); this companion turns them into toasts and keeps a
// persistent permission/bypass indicator right above the composer.
//
// Still build-free: the TUI host compiles this .tsx at load time (runtime
// solid transform). The published package declares the Solid/OpenTUI runtime
// as peers so the npm loader installs them alongside this plugin.
//
// Freshness model — the server snapshot is authoritative:
//
// - The RPC events are ephemeral and pushed only for the session that was
//   mutated; descendants that inherit the change through their parent chain
//   (bypass leases and the permission ceiling both propagate) get no event
//   of their own. Every event therefore also triggers a `status` pull for
//   the rest of the session's family.
// - `rpc.events.on` rides the shared event stream: when that stream restarts
//   (server reconnect, stalled-stream watchdog, subscription overflow) the
//   subscription's async iterator finishes and the handler silently stops
//   firing. `data.on("server.connected")` is published by the host's own
//   reconnect loop, so it is used to re-subscribe the RPC handlers and to
//   re-pull every tracked session.
// - Lifecycle events re-pull too: `session.compaction.ended` (the visible
//   session may be showing pre-compaction state), `session.created` /
//   `session.forked` (a child inherits the parent's bypass/permission),
//   `session.moved` (the session's location — and therefore the owning
//   plugin instance — changed), and `session.deleted` (drop the entry).
// - A `status` reply applies only while it is the newest pull and no event
//   arrived after it started, so a stale reply can never overwrite fresher
//   event state (`src/indicator-refresh.ts`).
import { createEffect, For, Show } from "solid-js"
import type { Plugin } from "@opencode-ai/plugin/tui"
import { BypassRpc, type BypassChangedData, type BypassStatusData } from "./bypass-rpc"
import {
  allIsOff,
  segmentsFor,
  type IndicatorState,
  type IndicatorTheme,
} from "./indicator"
import { StatusRevisions, sessionsToRefresh } from "./indicator-refresh"

type Context = Plugin.Context

type Location = { directory: string; workspaceID?: string }

/** Structural slice of the lifecycle events consumed below, verified against
 *  the generated V2Event union (@opencode/client): SessionCreated carries
 *  `data.location`, SessionForked carries top-level `location` only, and
 *  SessionMoved carries `data.location`; all carry `data.sessionID`, and
 *  `server.connected`/`session.compaction.ended`/`session.deleted` follow
 *  the same envelope. */
type SessionLifecycleEvent = {
  readonly data?: {
    readonly sessionID?: string
    readonly location?: Location
  }
  readonly location?: Location
}

type Toast = { title: string; message: string; variant: "info" | "success" | "warning" | "error"; duration: number }

/** Compact human duration for toast copy ("in 90s", "in 2m", "in 1h"). */
function formatDuration(ms: number): string {
  const sec = Math.round(ms / 1000)
  if (sec < 90) return `${sec}s`
  const min = Math.round(sec / 60)
  if (min < 90) return `${min}m`
  const hr = Math.round(min / 60)
  return `${hr}h`
}

function toastFor(data: BypassChangedData): Toast {
  const active = data.active.length > 0 ? data.active.join(", ") : "none"
  const temporary = data.temporary.length > 0 ? data.temporary.join(", ") : "none"
  // Lease deadlines are absolute (activity never extends them); the payload
  // carries the effective expiry so the toast can state the real deadline.
  const expiry =
    data.expiresAt === null
      ? "never expires until /bypass off"
      : typeof data.expiresAt === "number"
        ? `expires in ${formatDuration(Math.max(0, data.expiresAt - Date.now()))}`
        : "expires on its own schedule"
  // Kill-switch transitions get their own loud error toast: "armed" with
  // "ALL" in the active list means every plugin enforcement layer is off.
  if (allIsOff(data.active) && (data.reason === "armed" || data.reason === "updated")) {
    return {
      title: "ALL plugin enforcement OFF",
      message:
        `Static/dynamic classification, slow-command checks, injection detection, sandbox wrapping, and permission gates are all disabled for this session (${expiry}). /bypass off restores them.`,
      variant: "error",
      duration: 10000,
    }
  }
  switch (data.reason) {
    case "armed":
      return {
        title: "Classifier bypass armed",
        message: `Active: ${active}. Protections relaxed for this session; ${expiry}. Run /bypass for details.`,
        variant: "warning",
        duration: 8000,
      }
    case "updated":
      return {
        title: "Classifier bypass updated",
        message: `Active: ${active} (temporary: ${temporary}; ${expiry}).`,
        variant: "warning",
        duration: 6000,
      }
    case "expired":
      return {
        title: "Classifier bypass expired",
        message: "Normal command-safety checks are active again.",
        variant: "info",
        duration: 8000,
      }
    case "cleared":
      return {
        title: "Classifier bypass cleared",
        message: "Normal command-safety checks are active again.",
        variant: "info",
        duration: 6000,
      }
    default:
      return {
        title: "Classifier bypass status",
        message: `Active: ${active} (temporary: ${temporary}; permanent: ${data.permanent.length > 0 ? data.permanent.join(", ") : "none"}).`,
        variant: "info",
        duration: 6000,
      }
  }
}

const plugin: Plugin.Definition = {
  id: "opencode-v2-security",
  setup(context: Context) {
    const cleanups: Array<() => void> = []
    // Set on teardown before any unsubscribe runs: storage.memory survives a
    // plugin hot reload, so a status reply still in flight for THIS
    // generation must not write after disposal — it would overwrite the
    // next generation's fresher state in the shared store.
    let disposed = false
    const runCleanups = () => {
      disposed = true
      for (const fn of cleanups) fn()
    }

    const client = context.client as Context["client"] & {
      rpc?: (definition: unknown) => {
        events: {
          on: (name: string, handler: (event: { data: unknown; location?: unknown }) => void) => () => void
        }
        status?: (
          input: { sessionID: string },
          options: { location: { directory: string; workspaceID?: string } },
        ) => Promise<BypassStatusData>
      }
    }
    if (!client?.rpc) return () => {}

    const revisions = new StatusRevisions()

    // The server RPC event is not location-scoped, so a host with several
    // locations would deliver all of them. Only filter when the reliable
    // identity (workspaceID) is present on both sides and actually differs;
    // never drop on a directory spelling/timing mismatch. `context.location`
    // is a live getter: read it per event, not once at setup.
    const sameWorkspace = (event: { location?: unknown }) => {
      const here = context.location as { workspaceID?: string } | undefined
      const there = event.location as { workspaceID?: string } | undefined
      return !(
        here?.workspaceID !== undefined &&
        there?.workspaceID !== undefined &&
        here.workspaceID !== there.workspaceID
      )
    }

    const rpc = client.rpc(BypassRpc)

    // Persistent indicator state: ephemeral store keyed by sessionID (the
    // store survives plugin hot reloads, so entries may predate this setup —
    // lifecycle pulls below re-verify them against the server).
    const memory = context.storage?.memory
    const [indicator, mutateIndicator] = memory
      ? memory("opencode-v2-security.indicator", {
          initial: {} as Record<string, IndicatorState>,
        })
      : [undefined, undefined]
    const writeIndicator =
      mutateIndicator === undefined
        ? undefined
        : (sessionID: string, patch: Partial<IndicatorState>) =>
            mutateIndicator((draft) => {
              const current = draft[sessionID] ?? { permission: "rwx", active: [] }
              draft[sessionID] = { ...current, ...patch }
            })

    // The session's own location is required: RPCs without an explicit
    // location go to the service's cwd instance, which may not own this
    // session's bypass lease or permission baseline (the 1.1.1 fix). A host
    // without session data answers undefined — never fall back to the TUI's
    // own location, which could display another instance's state.
    const locationOf = (sessionID: string): Location | undefined => {
      try {
        return context.data.session.get(sessionID)?.location as Location | undefined
      } catch {
        return undefined
      }
    }

    // Late attach / session switch / any refresh trigger: pull the full
    // state so the indicator can never go stale. Older hosts without RPC
    // methods degrade to event-only updates. Every failure — including a
    // missing location or a rejected RPC — degrades to event-only updates.
    const pullStatus = async (sessionID: string, location?: Location) => {
      try {
        if (disposed) return
        const target = location ?? locationOf(sessionID)
        if (!target) return
        const ticket = revisions.beginPull(sessionID)
        const data = await rpc.status?.({ sessionID }, { location: target })
        if (
          !disposed &&
          data &&
          data.sessionID === sessionID &&
          revisions.mayApply(sessionID, ticket)
        ) {
          writeIndicator?.(data.sessionID, {
            permission: data.permission,
            active: [...data.active],
          })
        }
      } catch {
        /* event-only fallback */
      }
    }
    const pullFamily = (sourceID: string) => {
      let family: readonly string[] = []
      try {
        family = context.data.session.family(sourceID)
      } catch {
        /* hosts without family() simply skip descendant refresh */
      }
      for (const id of sessionsToRefresh(sourceID, family)) void pullStatus(id)
    }

    // rpc.events.on subscriptions finish silently when the shared event
    // stream restarts, so both handlers live behind subscribeRpc() which can
    // re-register them; a generation stamp keeps a not-yet-collected stale
    // handler from double-processing during the swap.
    const rpcStops: Array<() => void> = []
    let rpcGeneration = 0
    const subscribeRpc = () => {
      for (const stop of rpcStops.splice(0)) {
        try {
          stop()
        } catch {
          /* already finished */
        }
      }
      const generation = ++rpcGeneration
      const live = () => generation === rpcGeneration
      try {
        rpcStops.push(
          rpc.events.on("changed", (event) => {
            try {
              if (!live() || !sameWorkspace(event)) return
              const data = event.data as BypassChangedData
              revisions.markEvent(data.sessionID)
              writeIndicator?.(data.sessionID, { active: [...data.active] })
              // Descendants inherit the change but get no event of their own.
              pullFamily(data.sessionID)
              context.ui.toast.show(toastFor(data))
            } catch (error) {
              console.error("[opencode-v2-security] bypass toast failed", error)
            }
          }),
        )
        rpcStops.push(
          rpc.events.on("permission", (event) => {
            // A throwing handler rejects the event pump's async loop and
            // silently kills the subscription — keep the body fault-free.
            try {
              if (!live() || !sameWorkspace(event)) return
              const data = event.data as { sessionID: string; permission: string }
              revisions.markEvent(data.sessionID)
              writeIndicator?.(data.sessionID, { permission: data.permission })
              pullFamily(data.sessionID)
            } catch (error) {
              console.error("[opencode-v2-security] permission indicator update failed", error)
            }
          }),
        )
      } catch (error) {
        console.error("[opencode-v2-security] bypass notification setup failed", error)
      }
    }
    subscribeRpc()

    // Refresh triggers on the host-managed event bus (`data.on` survives the
    // reconnects that kill the RPC subscriptions above). Each subscription is
    // isolated: a host that rejects an unknown event type must not take down
    // the rest of the plugin.
    const on = context.data?.on?.bind(context.data)
    const listen = (type: string, handler: (event: SessionLifecycleEvent) => void) => {
      if (!on) return
      try {
        cleanups.push(on(type as never, handler))
      } catch (error) {
        console.error(`[opencode-v2-security] data.on(${type}) failed`, error)
      }
    }
    // (Re)connect: the old event stream is gone — every RPC subscription was
    // silently finished and any events published meanwhile are lost.
    // Re-subscribe and re-pull every session we already track.
    listen("server.connected", () => {
      subscribeRpc()
      if (!indicator) return
      for (const sessionID of Object.keys(indicator)) void pullStatus(sessionID)
    })
    // A completed compaction is a natural desync point for the visible
    // badge; re-pull the session's authoritative state. Handlers guard the
    // payload: a throw here would propagate into the host's event dispatch.
    // Lifecycle events also re-subscribe the RPC handlers opportunistically:
    // a subscription can die WITHOUT a connection restart (e.g. the shared
    // stream's per-subscriber queue overflow finishes only our iterator while
    // the host's subscriber keeps the connection alive — no server.connected
    // fires in that case), so these events double as revival points.
    listen("session.compaction.ended", (event) => {
      subscribeRpc()
      const sessionID = event.data?.sessionID
      if (typeof sessionID === "string") void pullStatus(sessionID)
    })
    // New sessions inherit the parent's bypass lease and permission ceiling,
    // so a child may start out restricted before the user ever opens it.
    const pullNewSession = (sessionID: string | undefined, location: Location | undefined) => {
      if (typeof sessionID === "string") void pullStatus(sessionID, location ?? locationOf(sessionID))
    }
    listen("session.created", (event) => {
      subscribeRpc()
      pullNewSession(event.data?.sessionID, event.data?.location)
    })
    listen("session.forked", (event) => {
      subscribeRpc()
      pullNewSession(event.data?.sessionID, event.location)
    })
    // The session moved to another location — pull from the new instance.
    listen("session.moved", (event) => {
      subscribeRpc()
      pullNewSession(event.data?.sessionID, event.data?.location)
    })
    listen("session.deleted", (event) => {
      const sessionID = event.data?.sessionID
      if (typeof sessionID !== "string") return
      revisions.drop(sessionID)
      mutateIndicator?.((draft) => {
        delete draft[sessionID]
      })
    })

    // Persistent indicator slot right above the composer.
    if (indicator && context.ui?.slot) {
      try {
        cleanups.push(
          context.ui.slot({
            append: "session.composer.top",
            render: (input: { sessionID: string }) => {
              // The host keeps session info and the slot input reactive. Wait
              // for the authoritative session location before pulling; the
              // currently selected TUI location may be a different instance.
              createEffect(() => {
                const sessionID = input.sessionID
                if (locationOf(sessionID)) void pullStatus(sessionID)
              })
              return (
                <Show when={indicator[input.sessionID]}>
                  {(state) => (
                    <box flexDirection="row" paddingX={1}>
                      <For each={segmentsFor(state(), context.theme as unknown as IndicatorTheme)}>
                        {(segment) => <text fg={segment.fg}>{segment.text}</text>}
                      </For>
                    </box>
                  )}
                </Show>
              )
            },
          }),
        )
      } catch (error) {
        console.error("[opencode-v2-security] indicator slot failed", error)
      }
    }

    cleanups.push(() => {
      rpcGeneration++
      for (const stop of rpcStops.splice(0)) {
        try {
          stop()
        } catch {
          /* already finished */
        }
      }
    })

    return runCleanups
  },
}

export default plugin

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
// The RPC events are ephemeral (live-only), so the companion also pulls the
// full state via the `status` method whenever the visible session changes: a
// reconnected or freshly mounted TUI can never show a stale ceiling — a
// stale indicator would be worse than none at all.
import { createEffect, For, Show } from "solid-js"
import type { Plugin } from "@opencode-ai/plugin/tui"
import { BypassRpc, type BypassChangedData, type BypassStatusData } from "./bypass-rpc"
import {
  allIsOff,
  segmentsFor,
  type IndicatorState,
  type IndicatorTheme,
} from "./indicator"

type Context = Plugin.Context

type Toast = { title: string; message: string; variant: "info" | "success" | "warning" | "error"; duration: number }

function toastFor(data: BypassChangedData): Toast {
  const active = data.active.length > 0 ? data.active.join(", ") : "none"
  const temporary = data.temporary.length > 0 ? data.temporary.join(", ") : "none"
  // Kill-switch transitions get their own loud error toast: "armed" with
  // "ALL" in the active list means every plugin enforcement layer is off.
  if (allIsOff(data.active) && (data.reason === "armed" || data.reason === "updated")) {
    return {
      title: "ALL plugin enforcement OFF",
      message:
        "Static/dynamic classification, slow-command checks, injection detection, sandbox wrapping, and permission gates are all disabled for this session. /bypass off restores them.",
      variant: "error",
      duration: 10000,
    }
  }
  switch (data.reason) {
    case "armed":
      return {
        title: "Classifier bypass armed",
        message: `Active: ${active}. Protections relaxed for this session; expires after inactivity. Run /bypass for details.`,
        variant: "warning",
        duration: 8000,
      }
    case "updated":
      return {
        title: "Classifier bypass updated",
        message: `Active: ${active} (temporary: ${temporary}).`,
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
    const runCleanups = () => {
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

    // Ignore status responses started before a more recent bypass/permission
    // event. A late reply must not replace the state the TUI just displayed.
    const eventRevision = new Map<string, number>()
    const statusRevision = new Map<string, number>()
    const markEvent = (sessionID: string) =>
      eventRevision.set(sessionID, (eventRevision.get(sessionID) ?? 0) + 1)

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

    // Bypass category transitions: user toast (unchanged) + indicator store.
    try {
      cleanups.push(
        rpc.events.on("changed", (event) => {
          try {
            if (!sameWorkspace(event)) return
            const data = event.data as BypassChangedData
            markEvent(data.sessionID)
            if (context.storage?.memory) {
              const [, mutateIndicator] = context.storage.memory("opencode-v2-security.indicator", {
                initial: {} as Record<string, IndicatorState>,
              })
              mutateIndicator((draft) => {
                const current = draft[data.sessionID] ?? { permission: "rwx", active: [] }
                draft[data.sessionID] = { ...current, active: [...data.active] }
              })
            }
            context.ui.toast.show(toastFor(data))
          } catch (error) {
            console.error("[opencode-v2-security] bypass toast failed", error)
          }
        }),
      )
    } catch (error) {
      console.error("[opencode-v2-security] bypass notification setup failed", error)
    }

    // Persistent indicator: ephemeral store keyed by sessionID, fed by the
    // permission event, bypass events and the status pull below.
    if (context.storage?.memory && context.ui?.slot) {
      try {
        const [indicator, mutateIndicator] = context.storage.memory("opencode-v2-security.indicator", {
          initial: {} as Record<string, IndicatorState>,
        })
        const writeIndicator = (sessionID: string, patch: Partial<IndicatorState>) =>
          mutateIndicator((draft) => {
            const current = draft[sessionID] ?? { permission: "rwx", active: [] }
            draft[sessionID] = { ...current, ...patch }
          })

        try {
          cleanups.push(
            rpc.events.on("permission", (event) => {
              if (!sameWorkspace(event)) return
              const data = event.data as { sessionID: string; permission: string }
              markEvent(data.sessionID)
              writeIndicator(data.sessionID, { permission: data.permission })
            }),
          )
        } catch (error) {
          console.error("[opencode-v2-security] permission indicator setup failed", error)
        }

        // Late attach / session switch: pull the full state so the indicator
        // can never be stale. Older hosts without RPC methods degrade to
        // event-only updates.
        const pullStatus = async (sessionID: string, location: { directory: string; workspaceID?: string }) => {
          const startedAtRevision = eventRevision.get(sessionID) ?? 0
          const requestRevision = (statusRevision.get(sessionID) ?? 0) + 1
          statusRevision.set(sessionID, requestRevision)
          try {
            // RPCs without an explicit location go to the service's cwd, not
            // necessarily the instance that owns this session's bypass lease.
            const data = await rpc.status?.({ sessionID }, { location })
            if (
              data &&
              data.sessionID === sessionID &&
              statusRevision.get(sessionID) === requestRevision &&
              (eventRevision.get(sessionID) ?? 0) === startedAtRevision
            ) {
              writeIndicator(data.sessionID, {
                permission: data.permission,
                active: [...data.active],
              })
            }
          } catch {
            /* event-only fallback */
          }
        }

        cleanups.push(
          context.ui.slot({
            append: "session.composer.top",
            render: (input: { sessionID: string }) => {
              // The host keeps session info and the slot input reactive. Wait
              // for the authoritative session location before pulling; the
              // currently selected TUI location may be a different instance.
              createEffect(() => {
                const sessionID = input.sessionID
                const location = context.data.session.get(sessionID)?.location
                if (location) void pullStatus(sessionID, location)
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

    return runCleanups
  },
}

export default plugin

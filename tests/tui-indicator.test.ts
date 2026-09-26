import { describe, expect, test } from "bun:test"
import { createRoot, createSignal } from "solid-js"
import { createStore, produce } from "solid-js/store"
import plugin from "../src/tui"

// Bun normally resolves Solid's server build, which does not run effects.
// Run this file with `bun test --conditions browser tests/tui-indicator.test.ts`.
const browserSolid = import.meta.resolve("solid-js").endsWith("/solid.js")

type Indicator = { permission: string; active: string[] }
type Status = { sessionID: string; permission: string; active: string[]; temporary: string[]; permanent: string[] }
const sessionID = "ses_indicator_test"
const location = { directory: "/session-workspace", workspaceID: "workspace-test" }

function mountIndicator(
  status: (input: { sessionID: string }, options: { location: typeof location }) => Promise<Status>,
  initialLocation: typeof location | null = location,
) {
  const [indicator, setIndicator] = createStore<Record<string, Indicator>>({})
  const [sessionLocation, setSessionLocation] = createSignal<typeof location | undefined>(initialLocation ?? undefined)
  const handlers = new Map<string, (event: { data: unknown }) => void>()
  let render: ((input: { sessionID: string }) => unknown) | undefined
  const context = {
    client: {
      rpc: () => ({
        status,
        events: {
          on(name: string, handler: (event: { data: unknown }) => void) {
            handlers.set(name, handler)
            return () => handlers.delete(name)
          },
        },
      }),
    },
    data: { session: { get: () => (sessionLocation() ? { location: sessionLocation() } : undefined) } },
    storage: {
      memory: () => [indicator, (mutation: (draft: Record<string, Indicator>) => void) => setIndicator(produce(mutation))],
    },
    ui: {
      toast: { show: () => {} },
      slot(input: { render: (input: { sessionID: string }) => unknown }) {
        render = input.render
        return () => {}
      },
    },
    theme: {
      text: { subdued: "gray", feedback: { success: { subdued: "green" }, warning: { default: "orange" } } },
    },
  }
  const cleanup = plugin.setup(context as never) as () => void
  let dispose = () => {}
  createRoot((stop) => {
    dispose = stop
    render?.({ sessionID })
  })
  return {
    indicator,
    changed: (active: string[]) =>
      handlers.get("changed")?.({
        data: { sessionID, reason: "armed", active, temporary: active, permanent: [] },
      }),
    permission: (value: string) => handlers.get("permission")?.({ data: { sessionID, permission: value } }),
    setSessionLocation,
    close: () => {
      dispose()
      cleanup()
    },
  }
}

describe.skipIf(!browserSolid)("TUI bypass indicator", () => {
  test("waits for session information instead of pulling from an unrelated default location", async () => {
    let calls = 0
    const harness = mountIndicator(async () => {
      calls += 1
      return { sessionID, permission: "rwx", active: ["host"], temporary: ["host"], permanent: [] }
    }, null)
    try {
      await new Promise((resolve) => setImmediate(resolve))
      expect(calls).toBe(0)
      harness.setSessionLocation(location)
      await new Promise((resolve) => setImmediate(resolve))
      expect(calls).toBe(1)
      expect(harness.indicator[sessionID]?.active).toEqual(["host"])
    } finally {
      harness.close()
    }
  })

  test("loads status from the session's location rather than the server default", async () => {
    let requestedLocation: typeof location | undefined
    const harness = mountIndicator(async (_input, options) => {
      requestedLocation = options.location
      return { sessionID, permission: "rwx", active: ["host"], temporary: ["host"], permanent: [] }
    })
    try {
      await new Promise((resolve) => setImmediate(resolve))
      expect(requestedLocation).toEqual(location)
      expect(harness.indicator[sessionID]?.active).toEqual(["host"])
    } finally {
      harness.close()
    }
  })

  test("a late status reply cannot erase a newer bypass or permission event", async () => {
    let finishStatus!: (status: Status) => void
    const status = new Promise<Status>((resolve) => {
      finishStatus = resolve
    })
    const harness = mountIndicator(async () => status)
    try {
      await new Promise((resolve) => setImmediate(resolve))
      harness.changed(["host", "privilege"])
      harness.permission("r-x")
      finishStatus({ sessionID, permission: "rwx", active: [], temporary: [], permanent: [] })
      await new Promise((resolve) => setImmediate(resolve))
      expect(harness.indicator[sessionID]).toEqual({ permission: "r-x", active: ["host", "privilege"] })
    } finally {
      harness.close()
    }
  })

  test("an older status request cannot overwrite a newer location's reply", async () => {
    const pending = new Map<string, (status: Status) => void>()
    const harness = mountIndicator((_input, options) =>
      new Promise<Status>((resolve) => pending.set(options.location.directory, resolve)),
    )
    try {
      await new Promise((resolve) => setImmediate(resolve))
      harness.setSessionLocation({ ...location, directory: "/other-workspace" })
      await new Promise((resolve) => setImmediate(resolve))
      pending.get("/other-workspace")?.({
        sessionID, permission: "rwx", active: ["host"], temporary: ["host"], permanent: [],
      })
      await new Promise((resolve) => setImmediate(resolve))
      pending.get(location.directory)?.({ sessionID, permission: "rwx", active: [], temporary: [], permanent: [] })
      await new Promise((resolve) => setImmediate(resolve))
      expect(harness.indicator[sessionID]?.active).toEqual(["host"])
    } finally {
      harness.close()
    }
  })
})

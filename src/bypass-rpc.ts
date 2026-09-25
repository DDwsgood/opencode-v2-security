// Shared RPC contract for the `/bypass` **user notification** channel.
//
// Why this exists: v2 has no session message type that is visible to the user
// but hidden from the model — `synthetic`/`system`/`shell` all enter the model
// context (`packages/core/src/session/runner/to-llm-message.ts`). The server
// plugin therefore reports bypass state changes over an ephemeral RPC event, and
// the optional TUI companion (`src/tui.ts`) turns those events into toasts.
//
// The definition is a plain JSON-Schema object on purpose: both the server
// entrypoint and the TUI entrypoint can share it without a runtime import from
// `@opencode-ai/plugin` (the host owns the RPC implementation), keeping the
// package build-free. The `as const` shape satisfies `Rpc.Definition`.
export const BypassRpc = {
  id: "opencode-v2-security.bypass",
  // The command drives state mutations; the TUI only listens and pulls.
  methods: {
    // Late-attaching or restarted TUI companions cannot replay ephemeral
    // events, so they fetch the current bypass+permission state on mount.
    // Without this the persistent indicator could silently show a stale
    // ceiling — worse than showing nothing.
    status: {
      input: {
        type: "object",
        properties: { sessionID: { type: "string" } },
        required: ["sessionID"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          // Effective triple rendered unix-style ("rwx", "r-x"); the ALL
          // kill switch rides `active` as the literal "ALL".
          permission: { type: "string" },
          active: { type: "array", items: { type: "string" } },
          temporary: { type: "array", items: { type: "string" } },
          permanent: { type: "array", items: { type: "string" } },
        },
        required: ["sessionID", "permission", "active", "temporary", "permanent"],
        additionalProperties: false,
      },
    },
  },
  events: {
    changed: {
      schema: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          // armed | updated | cleared | expired | status
          reason: { type: "string" },
          active: { type: "array", items: { type: "string" } },
          temporary: { type: "array", items: { type: "string" } },
          permanent: { type: "array", items: { type: "string" } },
        },
        required: ["sessionID", "reason", "active", "temporary", "permanent"],
        additionalProperties: false,
      },
    },
    // Session permission transitions (/perm,
    // set_permission tool, subagent spawn). `permission` is the effective
    // triple rendered unix-style ("rwx", "r-x").
    permission: {
      schema: {
        type: "object",
        properties: {
          sessionID: { type: "string" },
          // set | spawned
          reason: { type: "string" },
          permission: { type: "string" },
        },
        required: ["sessionID", "reason", "permission"],
        additionalProperties: false,
      },
    },
  },
} as const

export type BypassChangedData = {
  readonly sessionID: string
  readonly reason: "armed" | "updated" | "cleared" | "expired" | "status"
  readonly active: readonly string[]
  readonly temporary: readonly string[]
  readonly permanent: readonly string[]
}

/** Reply of the RPC `status` method: the full bypass + permission state for
 * one session, pulled by the TUI companion on mount and on every session
 * switch (events are ephemeral, so a late-attaching TUI must fetch). */
export type BypassStatusData = {
  readonly sessionID: string
  readonly permission: string
  readonly active: readonly string[]
  readonly temporary: readonly string[]
  readonly permanent: readonly string[]
}

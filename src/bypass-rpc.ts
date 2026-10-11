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
//
// `mode` (optional) is the user-visible three-way label state: "readonly",
// "auto" or "bypass". The boolean triple in `permission` remains for internal
// compatibility and for deriving the mode against older servers that do not
// send `mode` yet (read-only wins, then the ALL kill switch means bypass).
import type { SecurityMode } from "./permissions"

/** JSON-Schema fragment for the optional user-visible mode; absent on older
 *  servers, so it is never in `required`. */
const MODE_SCHEMA = { type: "string", enum: ["readonly", "auto", "bypass"] } as const

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
          // kill switch rides `active` as the literal "ALL". Kept for internal
          // compatibility; the TUI displays `mode`, not this triple.
          permission: { type: "string" },
          // User-visible mode; optional so older servers stay compatible.
          mode: MODE_SCHEMA,
          active: { type: "array", items: { type: "string" } },
          temporary: { type: "array", items: { type: "string" } },
          permanent: { type: "array", items: { type: "string" } },
          custom: { type: "array", items: { type: "string" } },
          // Effective lease deadline (epoch ms) — the earliest live lease in
          // the session's chain. null = armed with no natural expiry
          // (timeout <= 0); absent = no live lease.
          expiresAt: { type: ["number", "null"] },
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
          // armed | updated | cleared | expired | status | clamped
          reason: { type: "string" },
          // User-visible mode; optional for older servers / partial events.
          mode: MODE_SCHEMA,
          active: { type: "array", items: { type: "string" } },
          temporary: { type: "array", items: { type: "string" } },
          permanent: { type: "array", items: { type: "string" } },
          custom: { type: "array", items: { type: "string" } },
          // Effective lease deadline (epoch ms); null = no natural expiry;
          // absent = no live lease.
          expiresAt: { type: ["number", "null"] },
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
          // User-visible mode; optional for older servers.
          mode: MODE_SCHEMA,
        },
        required: ["sessionID", "reason", "permission"],
        additionalProperties: false,
      },
    },
  },
} as const

export type BypassChangedData = {
  readonly sessionID: string
  readonly reason: "armed" | "updated" | "cleared" | "expired" | "status" | "clamped"
  /** User-visible mode; absent on older servers (derive from `permission` +
   *  `active`). */
  readonly mode?: SecurityMode
  readonly active: readonly string[]
  readonly temporary: readonly string[]
  readonly permanent: readonly string[]
  /** Verbatim user scopes; omitted when none. Never copy these into diagnostic logs. */
  readonly custom?: readonly string[]
  /** Effective lease deadline (epoch ms). null = armed with no natural
   * expiry (timeout <= 0); absent = no live lease. Fixed: activity never
   * pushes it later. */
  readonly expiresAt?: number | null
}

/** Payload of the `permission` event (a session permission transition). */
export type BypassPermissionData = {
  readonly sessionID: string
  /** set | spawned */
  readonly reason: string
  /** Effective triple rendered unix-style ("rwx", "r-x"). Kept for internal
   *  compatibility; the TUI displays `mode`, not this triple. */
  readonly permission: string
  /** User-visible mode; absent on older servers. */
  readonly mode?: SecurityMode
}

/** Reply of the RPC `status` method: the full bypass + permission state for
 * one session, pulled by the TUI companion on mount and on every session
 * switch (events are ephemeral, so a late-attaching TUI must fetch). */
export type BypassStatusData = {
  readonly sessionID: string
  readonly permission: string
  /** User-visible mode; absent on older servers. */
  readonly mode?: SecurityMode
  readonly active: readonly string[]
  readonly temporary: readonly string[]
  readonly permanent: readonly string[]
  readonly custom?: readonly string[]
  /** See BypassChangedData.expiresAt. */
  readonly expiresAt?: number | null
}

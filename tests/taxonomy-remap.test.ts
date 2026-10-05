import { describe, expect, test } from "bun:test"
import { BYPASS_CATEGORIES } from "../src/config"
import { ruleBypassed, ruleRequiredCategories, isFloorRule, TERMINAL_UNBYPASSABLE } from "../src/security/bypass"

const armed = (...categories: string[]) => new Set(categories as never)

// The privilege category took over the isolation/permission-boundary rules
// from host; host keeps running-system state. These tests pin the remap.
describe("privilege/host taxonomy split", () => {
  test("boundary-crossing rules now require privilege, not host", () => {
    for (const rule of [
      "permissions.root-recursive",
      "permissions.world-writable",
      "permissions.setuid",
      "permissions.lockdown",
      "kernel.sysctl-write",
      "namespace.escape",
      "execution.kernel-module-load",
    ]) {
      expect(ruleRequiredCategories(rule)).toEqual(["privilege"])
      expect(ruleBypassed(rule, armed("host"))).toBe(false)
      expect(ruleBypassed(rule, armed("privilege"))).toBe(true)
    }
  })

  test("privileged containers require privilege alone, not remote", () => {
    expect(ruleRequiredCategories("infrastructure.privileged-container")).toEqual(["privilege"])
    expect(ruleBypassed("infrastructure.privileged-container", armed("remote"))).toBe(false)
    expect(ruleBypassed("infrastructure.privileged-container", armed("host", "remote"))).toBe(false)
    expect(ruleBypassed("infrastructure.privileged-container", armed("privilege"))).toBe(true)
  })

  test("sensitive-mode is owned by secret alone (policyVersion 1.5)", () => {
    // Weakening a credential's own protection is a secret judgment, not a
    // privilege crossing — the object's mode bits are its own protection,
    // not a second owner.
    expect(ruleRequiredCategories("permissions.sensitive-mode")).toEqual(["secret"])
    expect(ruleBypassed("permissions.sensitive-mode", armed("privilege"))).toBe(false)
    expect(ruleBypassed("permissions.sensitive-mode", armed("secret"))).toBe(true)
  })

  test("the privilege context trigger follows the privilege category", () => {
    expect(ruleRequiredCategories("operation.context-required.privilege")).toEqual(["privilege"])
    expect(ruleBypassed("operation.context-required.privilege", armed("host"))).toBe(false)
    expect(ruleBypassed("operation.context-required.privilege", armed("privilege"))).toBe(true)
  })

  test("running-system state stays under host", () => {
    for (const rule of [
      "system.service-destruction",
      "system.shutdown",
      "system.critical-process-kill",
      "process.termination",
      "persistence.backdoor",
      "persistence.git-hooks",
      "forensic.history-clear",
      "forensic.journal-vacuum",
      "forensic.var-log-delete",
      "operation.context-required.process",
    ]) {
      expect(ruleRequiredCategories(rule)).toEqual(["host"])
      expect(ruleBypassed(rule, armed("privilege"))).toBe(false)
      expect(ruleBypassed(rule, armed("host"))).toBe(true)
    }
  })
})

describe("misrouted rules return to their natural families", () => {
  test("firewall mutation is a network rule", () => {
    expect(ruleRequiredCategories("network.firewall-mutate")).toEqual(["network"])
    expect(ruleBypassed("network.firewall-mutate", armed("host"))).toBe(false)
    expect(ruleBypassed("network.firewall-mutate", armed("network"))).toBe(true)
  })

  test("system-file writes and destructive SQL are filesystem effects", () => {
    for (const rule of [
      "system.file-override",
      "system.sensitive-write",
      "database.destructive-statement",
    ]) {
      expect(ruleRequiredCategories(rule)).toEqual(["filesystem"])
      expect(ruleBypassed(rule, armed("host"))).toBe(false)
      expect(ruleBypassed(rule, armed("remote"))).toBe(false)
      expect(ruleBypassed(rule, armed("filesystem"))).toBe(true)
    }
  })

  test("nested-interpreter escapes are bypassable via indirection", () => {
    for (const rule of ["execution.db-shell-escape", "execution.interop"]) {
      expect(ruleRequiredCategories(rule)).toEqual(["indirection"])
      expect(ruleBypassed(rule, armed("host"))).toBe(false)
      expect(ruleBypassed(rule, armed("indirection"))).toBe(true)
    }
  })

  test("unscoped archive extraction is a filesystem effect", () => {
    expect(ruleRequiredCategories("operation.archive-extract")).toEqual(["filesystem"])
    expect(ruleBypassed("operation.archive-extract", armed("filesystem"))).toBe(true)
  })
})

describe("the floor is unchanged by the remap", () => {
  test("floor rules are not bypassable by any category set", () => {
    const all = new Set(BYPASS_CATEGORIES)
    for (const rule of [
      "filesystem.root-delete",
      "filesystem.brace-root-delete",
      "filesystem.root-glob-delete",
      "filesystem.find-delete-root",
      "filesystem.disk-destruction",
      "execution.fork-bomb",
      "filesystem.kernel-trigger",
      "filesystem.kernel-core-pattern",
      "network.reverse-shell",
      "execution.literal-shell",
    ]) {
      expect(ruleRequiredCategories(rule)).toBeUndefined()
      expect(isFloorRule(rule)).toBe(true)
      expect(ruleBypassed(rule, all)).toBe(false)
    }
  })

  test("ordinary and unbypassable non-floor rules are not floor rules", () => {
    for (const rule of [
      "permissions.setuid",
      "system.shutdown",
      "input.empty",
      "input.opaque",
      "permission.write",
      "unmapped.rule",
    ]) {
      expect(isFloorRule(rule)).toBe(false)
    }
  })

  test("TERMINAL_UNBYPASSABLE is the floor plus ceiling/input guards", () => {
    for (const rule of ["permission.write", "input.empty", "input.opaque"]) {
      expect(TERMINAL_UNBYPASSABLE.has(rule)).toBe(true)
      expect(isFloorRule(rule)).toBe(false)
    }
    expect(TERMINAL_UNBYPASSABLE.has("filesystem.root-delete")).toBe(true)
    expect(TERMINAL_UNBYPASSABLE.has("system.shutdown")).toBe(false)
  })

  test("owner semantics on remapped rules (policyVersion 1.5)", () => {
    // Credential objects bill secret only; remote ops bill remote only;
    // genuinely independent exfiltration keeps both owners.
    expect(ruleRequiredCategories("data.critical-delete")).toEqual(["secret"])
    expect(ruleRequiredCategories("exfiltration.dns")).toEqual(["secret", "network"])
    expect(ruleRequiredCategories("execution.remote-pipe")).toEqual(["remote"])
    expect(ruleRequiredCategories("network.destructive-api")).toEqual(["remote"])
  })
})

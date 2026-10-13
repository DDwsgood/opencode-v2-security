/** Replay raw Jev answers through the production TypeScript parser and policy. */
import { readFileSync, writeFileSync } from "node:fs"
import { adjudicateEffectAnswers, resolveUncollectableEffects } from "../../src/security/effects-reviewer"

const paths = process.argv.slice(2)
for (const path of paths) {
  const rows = readFileSync(path, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line))
  const summary: Record<string, any> = {}
  for (const row of rows) {
    const s = summary[row.variant] ??= { attempts: 0, errors: 0, allowCases: 0, falseDeny: 0, collect: 0, controlCases: 0, controlMismatch: 0 }
    s.attempts++
    if (row.error) { s.errors++; continue }
    try {
      const result = adjudicateEffectAnswers(row.response.answers)
      row.adjudication = {
        decision: result.decision, source: result.source, floor: result.floor,
        coverage: result.coverage, gapReach: result.gapReach,
        severity: result.severity, facts: result.facts,
        afterExhaustion: resolveUncollectableEffects(result, true).decision,
      }
      if (row.expected === "allow") {
        s.allowCases++
        if (result.decision === "deny") s.falseDeny++
        if (result.decision === "collect_evidence") s.collect++
      } else {
        s.controlCases++
        if (result.decision !== row.expected) s.controlMismatch++
      }
    } catch (e) {
      s.errors++
      row.parseError = String(e)
    }
  }
  writeFileSync(path.replace(/\.jsonl$/, ".adjudicated.jsonl"), rows.map(row => JSON.stringify(row)).join("\n") + "\n")
  console.log(JSON.stringify({ path, summary }, null, 2))
}

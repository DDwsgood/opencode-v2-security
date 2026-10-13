/** Compare the actual host context retention with the same evidence plus user anchors. */
import { readFileSync, writeFileSync } from "node:fs"
import { boundarySessionContext } from "../../src/tool-boundary"
const cases = JSON.parse(readFileSync(new URL("./combined-cases.json", import.meta.url), "utf8"))
const out: any[] = []
for (const id of ["private-upload", "auth-key-transfer", "authorized-deploy", "authorized-restart", "scope-revoked"]) {
  const c = cases.find((c: any) => c.id === id)
  const userMessages = c.request.session_context.filter((s: string) => s.startsWith("user: ")).map((s: string) => s.slice(6))
  const raw = [
    ...userMessages.map((text: string) => ({ type: "user", text })),
    ...Array.from({length: 14}, (_,i) => ({ type: "assistant", content: [{type: "text", text: `Checked task prerequisites ${i}; waiting to perform the requested operation.`}]})),
    { type: "user", text: "继续。" },
  ]
  const retained = boundarySessionContext(raw)
  for (const mode of ["host-retained", "user-anchors"]) {
    const context = mode === "host-retained" ? retained.context : [
      ...userMessages.map((s: string) => "user: " + s),
      ...retained.context.slice(-(12-userMessages.length)),
    ]
    out.push({...c, id: `${id}-${mode}`, group: "retention", request: {...c.request, user_request: retained.userRequest, session_context: context}})
  }
}
writeFileSync(new URL("./context-cases.json", import.meta.url), JSON.stringify(out,null,2)+"\n")
console.log(`Generated ${out.length} context cases with actual host projection`)

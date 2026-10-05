import { rm } from "node:fs/promises"

/** Keep diagnostic fixtures when the runner explicitly requests it. Scope
 * finalizers and environment restoration still execute in the test harness. */
export const cleanupTestArtifacts: typeof rm = async (...args) => {
  if (process.env.OPENCODE_SECURITY_KEEP_TEST_ARTIFACTS === "1") return
  await rm(...args)
}

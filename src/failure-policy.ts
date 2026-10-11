/** A failed plugin check is not a security decision. Keep its code separate
 * from provider bodies and filesystem details so pass traces are safe. */
export class SecurityCheckFailure extends Error {
  constructor(readonly code: string, readonly reason: string) {
    super(reason)
    this.name = "SecurityCheckFailure"
  }
}

export function failureOrPass(
  policy: "fail_open" | "fail_close",
  code: string,
  trace: (entry: Record<string, unknown>) => void,
): boolean {
  if (policy !== "fail_open") return false
  // Only fixed, short failure codes enter the trace, never exception text.
  const failureCode = /^[a-z][a-z0-9_]{0,63}$/.test(code) ? code : "check_unavailable"
  try {
    trace({ kind: "fail_open_pass", code: failureCode })
  } catch {
    // An unavailable trace sink cannot turn a pass into a refusal.
  }
  return true
}

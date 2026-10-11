/** Coalesce identical review facts, not execution. Each caller still checks
 *  its own authorization and targets after the shared verdict returns. */
export function createSingleFlight<T>() {
  type Entry = { controller: AbortController; promise: Promise<T>; waiters: number }
  const entries = new Map<string, Entry>()
  const cancelled = () => Object.assign(new Error("Review wait cancelled"), { name: "AbortError" })
  return {
    run(key: string, signal: AbortSignal, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
      if (signal.aborted) return Promise.reject(cancelled())
      let entry = entries.get(key)
      if (!entry || entry.controller.signal.aborted) {
        const controller = new AbortController()
        entry = { controller, promise: Promise.resolve().then(() => work(controller.signal)), waiters: 0 }
        entries.set(key, entry)
        const own = entry
        const done = () => { if (entries.get(key) === own) entries.delete(key) }
        entry.promise.then(done, done)
      }
      const own = entry
      own.waiters++
      return new Promise<T>((resolve, reject) => {
        let settled = false
        const finish = (callback: () => void) => {
          if (settled) return
          settled = true
          signal.removeEventListener("abort", abort)
          own.waiters--
          callback()
        }
        const abort = () => {
          finish(() => reject(cancelled()))
          if (own.waiters === 0) own.controller.abort()
        }
        signal.addEventListener("abort", abort, { once: true })
        if (signal.aborted) { abort(); return }
        own.promise.then((value) => finish(() => resolve(value)), (error) => finish(() => reject(error)))
      })
    },
    clear() { for (const entry of entries.values()) entry.controller.abort(); entries.clear() },
  }
}

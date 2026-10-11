import { describe, expect, test } from "bun:test"
import { createSingleFlight } from "../src/security/single-flight"

describe("shared review, independent execution", () => {
  test("identical facts share one review, different facts do not", async () => {
    const group = createSingleFlight<number>()
    let calls = 0
    const work = async () => ++calls
    const one = new AbortController()
    const two = new AbortController()
    expect(await Promise.all([group.run("same", one.signal, work), group.run("same", two.signal, work)])).toEqual([1, 1])
    expect(calls).toBe(1)
    expect(await group.run("different", one.signal, work)).toBe(2)
  })
  test("one cancelled waiter cannot cancel another caller's review", async () => {
    const group = createSingleFlight<number>()
    const one = new AbortController(), two = new AbortController()
    let finish!: (value: number) => void
    let reviewSignal!: AbortSignal
    const work = (signal: AbortSignal) => {
      reviewSignal = signal
      return new Promise<number>((resolve) => { finish = resolve })
    }
    const a = group.run("same", one.signal, work)
    const b = group.run("same", two.signal, work)
    await Promise.resolve()
    one.abort()
    await expect(a).rejects.toThrow("cancelled")
    expect(reviewSignal.aborted).toBe(false)
    finish(3)
    expect(await b).toBe(3)
  })
  test("all waiters cancelling abort the provider request", async () => {
    const group = createSingleFlight<number>()
    const one = new AbortController(), two = new AbortController()
    let reviewSignal!: AbortSignal
    const work = (signal: AbortSignal) => {
      reviewSignal = signal
      return new Promise<number>((_resolve, reject) => signal.addEventListener("abort", () => reject(new Error("provider aborted")), { once: true }))
    }
    const a = group.run("same", one.signal, work), b = group.run("same", two.signal, work)
    await Promise.resolve()
    one.abort(); two.abort()
    await expect(a).rejects.toThrow("cancelled")
    await expect(b).rejects.toThrow("cancelled")
    expect(reviewSignal.aborted).toBe(true)
  })
})

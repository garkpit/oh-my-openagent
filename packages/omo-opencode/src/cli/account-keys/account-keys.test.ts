import { describe, expect, test, spyOn } from "bun:test"
import { Command } from "commander"
import { createPublicKey, verify } from "node:crypto"
import { initializeDeviceKeyring, loadDeviceKeyring } from "./keyring"
import { createOsKeyStore, type KeyStore, type RunSecretCommand } from "./keystore"
import { configureAccountKeysCommands } from "./commands"

function memoryStore(): KeyStore {
  let value: string | null = null
  return { read: async () => value, write: async next => { value = next } }
}

describe("account keys", () => {
  test("initialization is persistent and idempotent", async () => {
    const store = memoryStore()
    const first = await initializeDeviceKeyring(store)
    const second = await initializeDeviceKeyring(store)
    const reopened = await loadDeviceKeyring(store)
    expect(second.principal()).toEqual(first.principal())
    expect(reopened?.publicKeys()).toEqual(first.publicKeys())
    const digest = new Uint8Array(32).fill(3)
    const signature = await second.sign({ purpose: "object-digest", digest })
    const tagged = Buffer.concat([Buffer.from("omo-sync/v1/object-digest", "ascii"), Buffer.from([0]), Buffer.from(digest)])
    expect(verify(null, tagged, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: first.publicKeys().signing }, format: "jwk" }), signature)).toBe(true)
    expect(verify(null, digest, createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: first.publicKeys().signing }, format: "jwk" }), signature)).toBe(false)
  })

  test("CLI init and status expose public keys only", async () => {
    const store = memoryStore()
    const lines: string[] = []
    const program = new Command("omo")
    configureAccountKeysCommands(program, { store: () => store, output: line => lines.push(line) })
    await program.parseAsync(["account", "keys", "init"], { from: "user" })
    await program.parseAsync(["account", "keys", "status"], { from: "user" })
    expect(JSON.parse(lines[0])).toEqual(JSON.parse(lines[1]))
    const saved = JSON.parse(await store.read() ?? "")
    expect(lines.join("\n")).not.toContain(saved.signing)
    expect(lines.join("\n")).not.toContain(saved.sealing)
  })

  test.each(["darwin", "linux", "win32"] as const)("%s passes secrets only through stdin and sanitizes errors and logs", async platform => {
    const secret = "PRIVATE-KEY-CANARY"
    const logs: string[] = []
    const log = spyOn(console, "log").mockImplementation((...values) => { logs.push(values.join(" ")) })
    const errorLog = spyOn(console, "error").mockImplementation((...values) => { logs.push(values.join(" ")) })
    const calls: { argv: readonly string[]; input?: string }[] = []
    const run: RunSecretCommand = async (argv, input) => {
      calls.push({ argv, input })
      throw new Error(secret)
    }
    try {
      const store = createOsKeyStore("test-fixture", platform, run)
      for (const action of [() => store.write(secret), () => store.read()]) {
        let failure: unknown
        try { await action() } catch (error) { failure = error }
        expect(failure).toBeInstanceOf(Error)
        expect(String(failure)).not.toContain(secret)
      }
      expect(JSON.stringify(calls.map(call => call.argv))).not.toContain(secret)
      expect(calls.some(call => call.input?.includes(secret))).toBe(true)
      expect(logs.join("\n")).not.toContain(secret)
    } finally { log.mockRestore(); errorLog.mockRestore() }
  })

  test("missing or locked secure storage refuses plaintext fallback", async () => {
    const store = createOsKeyStore("fixture", "linux", async () => ({ code: 1, stdout: "", stderr: "locked" }))
    await expect(initializeDeviceKeyring(store)).rejects.toThrow()
    expect(() => createOsKeyStore("fixture", "freebsd")).toThrow()
  })

  test("corrupt private key records never escape in thrown errors", async () => {
    const canary = "PRIVATE-KEY-CANARY"
    const store = { read: async () => JSON.stringify({ signing: canary, sealing: canary }), write: async () => {} }
    let failure: unknown
    try { await loadDeviceKeyring(store) } catch (error) { failure = error }
    expect(failure).toBeInstanceOf(Error)
    expect(String(failure)).not.toContain(canary)
  })
})

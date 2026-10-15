import { describe, expect, test } from "bun:test"
import { createCipheriv, createHmac, createPublicKey, diffieHellman, generateKeyPairSync } from "node:crypto"
import { createInMemoryDeviceKeyring, type DeviceKeyring } from "../keyring-port.ts"
import type { WrapEntry } from "./entry.ts"
import { openHistory, openWrap } from "./unwrap.ts"
import { readBytes } from "./testing/sync-v1.ts"
import { b64urlEncode, type JsonValue, jcsBytes } from "./vendor/sync-format/jcs.ts"

type WrapsFixture = {
  readonly account: string
  readonly wraps: ReadonlyArray<{
    readonly name: string
    readonly epoch: number
    readonly id: string
    readonly key_material: JsonValue
    readonly history_plaintext: ReadonlyArray<{ readonly epoch: number; readonly origin: string; readonly key: string }>
  }>
}

const fixture: WrapsFixture = JSON.parse(new TextDecoder().decode(readBytes("wraps.json")))

// The DeviceKeyring port's own sealed-box construction (keyring-port.test.ts sealTo): a test-side
// sender so the receive path below is exercised only through keyring.unseal.
const sealToPort = (recipient: string, plaintext: Uint8Array): Uint8Array => {
  const ephemeral = generateKeyPairSync("x25519")
  const enc = Buffer.from(ephemeral.publicKey.export({ format: "jwk" }).x ?? "", "base64url")
  const dh = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: recipient }, format: "jwk" }) })
  const kem = Buffer.concat([Buffer.from("KEM"), Buffer.from([0, 32])])
  const suite = Buffer.concat([Buffer.from("HPKE"), Buffer.from([0, 32, 0, 1, 0, 2])])
  const extract = (id: Buffer, label: string, value: Uint8Array, salt = Buffer.alloc(0)) =>
    createHmac("sha256", salt).update(Buffer.concat([Buffer.from("HPKE-v1"), id, Buffer.from(label), value])).digest()
  const expand = (id: Buffer, label: string, key: Buffer, info: Uint8Array, length: number) =>
    createHmac("sha256", key).update(Buffer.concat([Buffer.from([0, length]), Buffer.from("HPKE-v1"), id, Buffer.from(label), info])).update(Buffer.from([1])).digest().subarray(0, length)
  const secret = expand(kem, "shared_secret", extract(kem, "eae_prk", dh), Buffer.concat([enc, Buffer.from(recipient, "base64url")]), 32)
  const context = Buffer.concat([Buffer.from([0]), extract(suite, "psk_id_hash", Buffer.alloc(0)), extract(suite, "info_hash", Buffer.alloc(0))])
  const schedule = extract(suite, "secret", Buffer.alloc(0), secret)
  const cipher = createCipheriv("aes-256-gcm", expand(suite, "key", schedule, context, 32), expand(suite, "base_nonce", schedule, context, 12))
  return Buffer.concat([enc, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

const keyMaterial = async (account: string, epoch: number, id: string, history: ReadonlyArray<JsonValue>) => {
  const current = crypto.getRandomValues(new Uint8Array(32))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey("raw", current, "AES-GCM", false, ["encrypt"])
  const additionalData = jcsBytes({ account, epoch, id, version: 1 })
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData }, key, jcsBytes(history)))
  return { version: 1, current_key: b64urlEncode(current), history: { nonce: b64urlEncode(nonce), ciphertext: b64urlEncode(ciphertext) } }
}

const wrapFor = async (keyring: DeviceKeyring, envelope: { readonly account: string; readonly epoch: number; readonly id: string }, history: ReadonlyArray<JsonValue> = []): Promise<WrapEntry> => {
  const material = await keyMaterial(envelope.account, envelope.epoch, envelope.id, history)
  const sealed = sealToPort(keyring.publicKeys().sealing, jcsBytes({ version: 1, ...envelope, key_material: material }))
  return { epoch: envelope.epoch, id: `device:${keyring.principal().id}`, wrap: b64urlEncode(sealed) }
}

describe("openHistory: the epoch-history layer of a wrap's key material", () => {
  test.each(fixture.wraps.map((wrap) => [wrap.name, wrap] as const))("opens the %s fixture bundle to its committed history", async (_name, wrap) => {
    const expected = new Map(wrap.history_plaintext.map((row) => [row.epoch, row.origin]))
    const opened = await openHistory(wrap.key_material, { account: fixture.account, epoch: wrap.epoch, id: wrap.id }, expected)
    expect([...(opened?.history.entries() ?? [])].map(([epoch, key]) => ({ epoch, key: b64urlEncode(key) }))).toEqual(
      wrap.history_plaintext.map((row) => ({ epoch: row.epoch, key: row.key })),
    )
  })

  test("a bundle carrying a cancelled or unproven origin is refused", async () => {
    const wrap = fixture.wraps.find((candidate) => candidate.name === "epoch3_to_recovery2")
    if (wrap === undefined) throw new Error("fixture missing")
    const withoutEpoch2 = new Map(wrap.history_plaintext.filter((row) => row.epoch !== 2).map((row) => [row.epoch, row.origin]))
    expect(await openHistory(wrap.key_material, { account: fixture.account, epoch: 3, id: wrap.id }, withoutEpoch2)).toBeNull()
  })

  test("a bundle moved to another recipient fails its AEAD", async () => {
    const wrap = fixture.wraps.find((candidate) => candidate.name === "epoch1_to_recovery1")
    if (wrap === undefined) throw new Error("fixture missing")
    expect(await openHistory(wrap.key_material, { account: fixture.account, epoch: 1, id: "device:someone-else" }, new Map())).toBeNull()
  })
})

describe("openWrap: unwrap only through the DeviceKeyring", () => {
  test("a wrap sealed to this device opens to its epoch keys", async () => {
    const keyring = createInMemoryDeviceKeyring("unwrap-device")
    const wrap = await wrapFor(keyring, { account: "acct", epoch: 1, id: "device:unwrap-device" })
    const opened = await openWrap(keyring, wrap, "acct", new Map())
    expect(opened.ok && opened.keys.current.length).toBe(32)
  })

  test("a genuine wrap transplanted from another account is refused", async () => {
    const keyring = createInMemoryDeviceKeyring("unwrap-device")
    const wrap = await wrapFor(keyring, { account: "another-account", epoch: 1, id: "device:unwrap-device" })
    expect(await openWrap(keyring, wrap, "acct", new Map())).toEqual({ ok: false, reason: "envelope_mismatch" })
  })

  test("a wrap addressed to another device is never unsealed", async () => {
    const keyring = createInMemoryDeviceKeyring("unwrap-device")
    const other = createInMemoryDeviceKeyring("other-device")
    const wrap = await wrapFor(other, { account: "acct", epoch: 1, id: "device:other-device" })
    expect(await openWrap(keyring, wrap, "acct", new Map())).toEqual({ ok: false, reason: "not_addressed_to_device" })
  })

  test("a wrap this device cannot unseal is refused", async () => {
    const keyring = createInMemoryDeviceKeyring("unwrap-device")
    const other = createInMemoryDeviceKeyring("unwrap-device")
    const wrap = await wrapFor(other, { account: "acct", epoch: 1, id: "device:unwrap-device" })
    expect(await openWrap(keyring, wrap, "acct", new Map())).toEqual({ ok: false, reason: "wrap_refused" })
  })
})

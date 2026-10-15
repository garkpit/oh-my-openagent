import { describe, expect, test } from "bun:test"
import { createCipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, createHmac, verify } from "node:crypto"
import { createInMemoryDeviceKeyring, DeviceKeyringSignError } from "./keyring-port"

// Independent RFC 9180 sender: base mode, DHKEM(X25519, HKDF-SHA256), AES-256-GCM.
export function sealTo(recipient: string, plaintext: Uint8Array): Uint8Array {
  const ephemeral = generateKeyPairSync("x25519")
  const enc = Buffer.from(ephemeral.publicKey.export({ format: "jwk" }).x ?? "", "base64url")
  const pkR = Buffer.from(recipient, "base64url")
  const dh = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: createPublicKey({ key: { kty: "OKP", crv: "X25519", x: recipient }, format: "jwk" }) })
  const kem = Buffer.concat([Buffer.from("KEM"), Buffer.from([0, 32])])
  const suite = Buffer.concat([Buffer.from("HPKE"), Buffer.from([0, 32, 0, 1, 0, 2])])
  const extract = (suiteId: Buffer, label: string, value: Uint8Array, salt = Buffer.alloc(0)) =>
    createHmac("sha256", salt).update(Buffer.concat([Buffer.from("HPKE-v1"), suiteId, Buffer.from(label), value])).digest()
  const expand = (suiteId: Buffer, label: string, key: Buffer, info: Uint8Array, length: number) => {
    const context = Buffer.concat([Buffer.from([0, length]), Buffer.from("HPKE-v1"), suiteId, Buffer.from(label), info])
    // HKDF expand only: these outputs are <= one SHA-256 block.
    return createHmac("sha256", key).update(context).update(Buffer.from([1])).digest().subarray(0, length)
  }
  const secret = expand(kem, "shared_secret", extract(kem, "eae_prk", dh), Buffer.concat([enc, pkR]), 32)
  const context = Buffer.concat([Buffer.from([0]), extract(suite, "psk_id_hash", Buffer.alloc(0)), extract(suite, "info_hash", Buffer.alloc(0))])
  const schedule = extract(suite, "secret", Buffer.alloc(0), secret)
  const cipher = createCipheriv("aes-256-gcm", expand(suite, "key", schedule, context, 32), expand(suite, "base_nonce", schedule, context, 12))
  return Buffer.concat([enc, cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
}

const SIGNING_TAGS = { "object-digest": "omo-sync/v1/object-digest", record: "omo-sync/v1/record" } as const

function taggedMessage(tag: string, payload: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(tag, "ascii"), Buffer.from([0]), Buffer.from(payload)])
}

describe("DeviceKeyring", () => {
  test("signs an object digest as tagged bytes and verifies with the advertised raw Ed25519 key", async () => {
    const keyring = createInMemoryDeviceKeyring("fixture-device")
    const digest = new Uint8Array(32).fill(7)
    const signature = await keyring.sign({ purpose: "object-digest", digest })
    expect(keyring.principal()).toEqual({ kind: "device", id: "fixture-device" })
    const publicKeys = keyring.publicKeys()
    expect(Buffer.from(publicKeys.signing, "base64url")).toHaveLength(32)
    expect(Buffer.from(publicKeys.sealing, "base64url")).toHaveLength(32)
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKeys.signing }, format: "jwk" })
    expect(verify(null, taggedMessage(SIGNING_TAGS["object-digest"], digest), publicKey, signature)).toBe(true)
    expect(JSON.stringify(keyring)).not.toContain("PRIVATE")
  })

  test("signs a canonical record preimage as tagged bytes", async () => {
    const keyring = createInMemoryDeviceKeyring("fixture-device")
    const canonicalJson = new TextEncoder().encode('{"t":"omo-sync/v1/record","account":"acc","base_seq":1,"digest":"AA","epoch":1,"link":"AA"}')
    const signature = await keyring.sign({ purpose: "record", canonicalJson })
    const publicKeys = keyring.publicKeys()
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKeys.signing }, format: "jwk" })
    expect(verify(null, taggedMessage(SIGNING_TAGS.record, canonicalJson), publicKey, signature)).toBe(true)
  })

  test("domain separation: no signature verifies across purposes or untagged", async () => {
    const keyring = createInMemoryDeviceKeyring("fixture-device")
    const publicKeys = keyring.publicKeys()
    const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKeys.signing }, format: "jwk" })
    const digest = new Uint8Array(32).fill(9)
    const canonicalJson = new TextEncoder().encode('{"t":"omo-sync/v1/record","epoch":2}')
    const digestSig = await keyring.sign({ purpose: "object-digest", digest })
    const recordSig = await keyring.sign({ purpose: "record", canonicalJson })
    // A signature made for one purpose must not verify under the other purpose's tag.
    expect(verify(null, taggedMessage(SIGNING_TAGS.record, digest), publicKey, digestSig)).toBe(false)
    expect(verify(null, taggedMessage(SIGNING_TAGS["object-digest"], canonicalJson), publicKey, recordSig)).toBe(false)
    // And no signature verifies over the untagged payload.
    expect(verify(null, digest, publicKey, digestSig)).toBe(false)
    expect(verify(null, canonicalJson, publicKey, recordSig)).toBe(false)
  })

  test("refuses malformed sign requests with a typed error", async () => {
    const keyring = createInMemoryDeviceKeyring("fixture-device")
    const digest31 = new Uint8Array(31)
    const withoutT = new TextEncoder().encode('{"account":"acc"}')
    const wrongPrefix = new TextEncoder().encode('{"t":"omo-other/v1/record"}')
    const digestTagAsRecord = new TextEncoder().encode('{"t":"omo-sync/v1/object-digest"}')
    const nonCanonical = new TextEncoder().encode('{ "t":"omo-sync/v1/record" }')
    const unknownPurpose = { purpose: "anything", digest: new Uint8Array(32) } as unknown as Parameters<typeof keyring.sign>[0]
    for (const request of [
      { purpose: "object-digest", digest: digest31 },
      { purpose: "record", canonicalJson: withoutT },
      { purpose: "record", canonicalJson: wrongPrefix },
      { purpose: "record", canonicalJson: digestTagAsRecord },
      { purpose: "record", canonicalJson: nonCanonical },
      unknownPurpose,
    ] as const) {
      let failure: unknown
      try {
        await keyring.sign(request)
      } catch (error) {
        failure = error
      }
      expect(failure).toBeInstanceOf(DeviceKeyringSignError)
    }
  })

  test("opens an independently constructed HPKE sealed box", async () => {
    const keyring = createInMemoryDeviceKeyring("receiver")
    const plaintext = new TextEncoder().encode("epoch key fixture")
    expect(await keyring.unseal(sealTo(keyring.publicKeys().sealing, plaintext))).toEqual(plaintext)
  })

  test("rejects tampering, truncation and a different recipient", async () => {
    const keyring = createInMemoryDeviceKeyring("receiver")
    const box = sealTo(keyring.publicKeys().sealing, new Uint8Array(32))
    const corrupt = Uint8Array.from(box)
    corrupt[33] ^= 1
    for (const invalid of [corrupt, box.subarray(0, 31), new Uint8Array(48)]) {
      await expect(keyring.unseal(invalid)).rejects.toThrow()
    }
    await expect(createInMemoryDeviceKeyring("other").unseal(box)).rejects.toThrow()
  })
})

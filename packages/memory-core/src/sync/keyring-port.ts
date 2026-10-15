import { Buffer } from "node:buffer"
import {
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  sign as ed25519Sign,
} from "node:crypto"

/**
 * DeviceKeyring is the sync engine's only path to this device's private keys
 * (work-plan todo 14; custody model in `docs/sync-design.md` §7 of omo-service).
 *
 * A device principal owns two key pairs generated on the device itself:
 *  - an Ed25519 signing pair, which signs every sync batch and keyring record;
 *  - an X25519 sealing pair, to which the account epoch keys are wrapped.
 *
 * The private halves never leave an implementation: they are never returned,
 * never serialized to logs or errors, and callers see only the principal
 * identity, the public keys, and the two operations.
 */
export type DeviceKeyringSignRequest =
  | {
      /** SHA-256 of the batch object up to (excluding) its signature field. */
      readonly purpose: "object-digest"
      /** Exactly 32 bytes. */
      readonly digest: Uint8Array
    }
  | {
      /** A keyring-record preimage. */
      readonly purpose: "record"
      /** RFC 8785 canonical JSON whose top-level "t" starts with "omo-sync/v1/". */
      readonly canonicalJson: Uint8Array
    }

/**
 * Refusal for any sign request outside the two typed purposes above. A
 * DeviceKeyring is never a raw-bytes signing oracle: it signs exactly the
 * given digest or canonical JSON, and only after the request validates.
 */
export class DeviceKeyringSignError extends Error {
  readonly name = "DeviceKeyringSignError"
  constructor(
    readonly reason: "unknown-purpose" | "digest-length" | "record-json" | "record-prefix" | "record-canonical",
    message: string,
  ) {
    super(message)
  }
}

/**
 * Domain separation tags (Opus delta review of desktop #2665, tag names
 * corrected): every device or recovery signature is Ed25519 over
 * `tag || 0x00 || payload`. No signature is ever made over untagged bytes,
 * so a signature minted for one purpose can never be replayed as another.
 */
const SIGNING_DOMAIN_TAGS: Record<DeviceKeyringSignRequest["purpose"], string> = {
  "object-digest": "omo-sync/v1/object-digest",
  record: "omo-sync/v1/record",
}

function domainSeparatedMessage(purpose: DeviceKeyringSignRequest["purpose"], payload: Uint8Array): Buffer {
  return Buffer.concat([Buffer.from(SIGNING_DOMAIN_TAGS[purpose], "ascii"), Buffer.from([0]), Buffer.from(payload)])
}

function validateSignRequest(request: DeviceKeyringSignRequest): Uint8Array {
  if (typeof request !== "object" || request === null) {
    throw new DeviceKeyringSignError("unknown-purpose", "sign: request must be a typed sign request")
  }
  if (request.purpose === "object-digest") {
    if (!(request.digest instanceof Uint8Array) || request.digest.length !== 32) {
      throw new DeviceKeyringSignError("digest-length", "sign: object-digest needs exactly 32 bytes (SHA-256 of the batch object)")
    }
    return request.digest
  }
  if (request.purpose === "record") {
    if (!(request.canonicalJson instanceof Uint8Array)) {
      throw new DeviceKeyringSignError("record-json", "sign: record needs RFC 8785 canonical JSON bytes")
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(Buffer.from(request.canonicalJson).toString("utf8"))
    } catch {
      throw new DeviceKeyringSignError("record-json", "sign: record preimage is not valid JSON")
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed) || typeof (parsed as { t?: unknown }).t !== "string") {
      throw new DeviceKeyringSignError("record-json", 'sign: record preimage needs a top-level "t" string')
    }
    const t = (parsed as { t: string }).t
    if (!t.startsWith("omo-sync/v1/")) {
      throw new DeviceKeyringSignError("record-prefix", 'sign: record "t" must start with "omo-sync/v1/"')
    }
    // The digest tag belongs to the object-digest purpose; a record carrying
    // it would collapse the domain separation, so it is refused here too.
    if (t === SIGNING_DOMAIN_TAGS["object-digest"]) {
      throw new DeviceKeyringSignError("record-prefix", 'sign: record "t" must name a record or snapshot type, not the object-digest tag')
    }
    // RFC 8785 §3.2.2.3: whitespace is forbidden between tokens, so its
    // presence proves non-canonical input without re-serializing floats.
    if (/[\t\n\f\r ]/.test(Buffer.from(request.canonicalJson).toString("utf8"))) {
      throw new DeviceKeyringSignError("record-canonical", "sign: record preimage must be RFC 8785 canonical JSON (no insignificant whitespace)")
    }
    return request.canonicalJson
  }
  throw new DeviceKeyringSignError("unknown-purpose", `sign: unsupported purpose ${JSON.stringify((request as { purpose?: unknown }).purpose ?? null)}`)
}

export interface DeviceKeyring {
  /** The keyring principal identity used in batch headers and record signatures. */
  principal(): { kind: "device"; id: string }
  /** Raw 32-byte public keys, base64url-encoded (Ed25519 `x`, X25519 `x`). */
  publicKeys(): {
    /** Ed25519 raw public key, base64url. */
    signing: string
    /** X25519 raw public key, base64url. */
    sealing: string
  }
  /**
   * Ed25519 signature (64 bytes) over exactly the bytes of the request: the
   * 32-byte object digest, or the record's canonical JSON. Never a raw-bytes
   * oracle — anything outside the two typed purposes is refused with a
   * DeviceKeyringSignError before any signing happens.
   */
  sign(request: DeviceKeyringSignRequest): Promise<Uint8Array>
  /**
   * Opens a sealed box addressed to this device's sealing key and returns the
   * plaintext (an epoch key wrap in the sync protocol).
   *
   * Construction: RFC 9180 HPKE, base mode (mode 0), suite
   * DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM
   * (KEM 0x0020, KDF 0x0001, AEAD 0x0002), single-shot single-recipient API
   * (`SetupBaseR`/`Open`, empty `info`, no psk). Wire form:
   * `enc (32 bytes) || ciphertext || 16-byte GCM tag`. omo-service
   * `docs/sync-design.md` §7 says only "wrapped (X25519 sealed box)" without
   * fixing the construction, so this port fixes it here.
   *
   * Rejects (throws) a malformed box: wrong length, a corrupted byte, or a
   * box sealed to any other recipient key.
   */
  unseal(wrap: Uint8Array): Promise<Uint8Array>
}

/** Minimum sealed-box size: 32-byte enc + 16-byte tag, with an empty plaintext. */
const SEALED_BOX_OVERHEAD = 48

const HKDF_HASH_LENGTH = 32

function labeledExtract(suiteId: Buffer, label: string, ikm: Uint8Array, salt: Uint8Array): Buffer {
  // RFC 9180 §4: LabeledExtract = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm);
  // an empty salt means HashLen zero bytes (RFC 5869 §2.2).
  const key = salt.length === 0 ? Buffer.alloc(HKDF_HASH_LENGTH) : Buffer.from(salt)
  return createHmac("sha256", key).update(Buffer.concat([Buffer.from("HPKE-v1"), suiteId, Buffer.from(label), Buffer.from(ikm)])).digest()
}

function labeledExpand(suiteId: Buffer, label: string, prk: Buffer, info: Uint8Array, length: number): Buffer {
  // RFC 9180 §4: LabeledExpand = HKDF-Expand(prk, "HPKE-v1" || suite_id || label || info).
  // Every expansion in this suite stays within one SHA-256 block, so T(1) suffices.
  if (length > 255 * HKDF_HASH_LENGTH) throw new Error("hpke expand length out of range")
  const lengthBytes = Buffer.alloc(2)
  lengthBytes.writeUInt16BE(length)
  const t0 = Buffer.concat([lengthBytes, Buffer.from("HPKE-v1"), suiteId, Buffer.from(label), Buffer.from(info), Buffer.from([1])])
  return createHmac("sha256", prk).update(t0).digest().subarray(0, length)
}

const KEM_ID = Buffer.from([0, 0x20])
const KDF_ID = Buffer.from([0, 0x01])
const AEAD_ID = Buffer.from([0, 0x02])

function x25519PublicKeyFromRaw(raw: Uint8Array): ReturnType<typeof createPublicKey> {
  return createPublicKey({ key: { kty: "OKP", crv: "X25519", x: Buffer.from(raw).toString("base64url") }, format: "jwk" })
}

/**
 * Opens a sealed box with a raw X25519 private scalar and its public key,
 * following RFC 9180 §6.1 `SetupBaseR` + single-shot `Open` with empty info.
 * Shared by every DeviceKeyring implementation so the construction above is
 * the only sealed-box code path in the tree.
 */
export function openHpkeSealedBox(sealingPrivateRaw: Uint8Array, sealingPublicRaw: Uint8Array, wrap: Uint8Array): Uint8Array {
  if (wrap.length < SEALED_BOX_OVERHEAD) throw new Error("sealed box is too short")
  const enc = wrap.subarray(0, 32)
  const ciphertext = wrap.subarray(32)

  const privateKey = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "X25519",
      d: Buffer.from(sealingPrivateRaw).toString("base64url"),
      x: Buffer.from(sealingPublicRaw).toString("base64url"),
    },
    format: "jwk",
  })
  const dh = diffieHellman({ privateKey, publicKey: x25519PublicKeyFromRaw(enc) })

  const kem = Buffer.concat([Buffer.from("KEM"), KEM_ID])
  const suite = Buffer.concat([Buffer.from("HPKE"), KEM_ID, KDF_ID, AEAD_ID])
  const sharedSecret = labeledExpand(
    kem,
    "shared_secret",
    labeledExtract(kem, "eae_prk", dh, Buffer.alloc(0)),
    Buffer.concat([Buffer.from(enc), Buffer.from(sealingPublicRaw)]),
    32,
  )
  const keyScheduleContext = Buffer.concat([
    Buffer.from([0]),
    labeledExtract(suite, "psk_id_hash", Buffer.alloc(0), Buffer.alloc(0)),
    labeledExtract(suite, "info_hash", Buffer.alloc(0), Buffer.alloc(0)),
  ])
  const secret = labeledExtract(suite, "secret", Buffer.alloc(0), sharedSecret)
  const key = labeledExpand(suite, "key", secret, keyScheduleContext, 32)
  const nonce = labeledExpand(suite, "base_nonce", secret, keyScheduleContext, 12)

  const decipher = createDecipheriv("aes-256-gcm", key, nonce)
  decipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16))
  try {
    return Buffer.concat([decipher.update(ciphertext.subarray(0, ciphertext.length - 16)), decipher.final()])
  } catch {
    throw new Error("sealed box does not open: wrong recipient or corrupted wrap")
  }
}

interface DeviceKeyMaterial {
  /** PKCS#8 DER of the Ed25519 private key, base64url. */
  readonly signingPrivatePkcs8: string
  /** PKCS#8 DER of the X25519 private key, base64url. */
  readonly sealingPrivatePkcs8: string
}

/**
 * Generates a fresh Ed25519 + X25519 pair. PKCS#8 DER is the only portable
 * private-key form in this runtime: raw-scalar JWK imports require a matching
 * `x` field, which DER already carries internally.
 */
export function generateDeviceKeyMaterial(): DeviceKeyMaterial & { publicKeys: { signing: string; sealing: string } } {
  const signing = generateKeyPairSync("ed25519")
  const sealing = generateKeyPairSync("x25519")
  const signingPublic = signing.publicKey.export({ format: "jwk" }).x
  const sealingPublic = sealing.publicKey.export({ format: "jwk" }).x
  if (!signingPublic || !sealingPublic) throw new Error("device key generation produced invalid key material")
  return {
    signingPrivatePkcs8: signing.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url"),
    sealingPrivatePkcs8: sealing.privateKey.export({ format: "der", type: "pkcs8" }).toString("base64url"),
    publicKeys: { signing: signingPublic, sealing: sealingPublic },
  }
}

/**
 * Builds a DeviceKeyring from PKCS#8 material it then owns. The private keys
 * stay inside the returned closures; the object exposes only the port surface.
 */
export function createDeviceKeyring(id: string, material: DeviceKeyMaterial): DeviceKeyring {
  const signingPrivateKey = createPrivateKey({ key: Buffer.from(material.signingPrivatePkcs8, "base64url"), format: "der", type: "pkcs8" })
  const sealingPrivateKey = createPrivateKey({ key: Buffer.from(material.sealingPrivatePkcs8, "base64url"), format: "der", type: "pkcs8" })
  const signingPublic = createPublicKey(signingPrivateKey).export({ format: "jwk" }).x
  const sealingPublic = createPublicKey(sealingPrivateKey).export({ format: "jwk" }).x
  if (!signingPublic || !sealingPublic) throw new Error("invalid device key material")
  const sealingPrivateJwk = sealingPrivateKey.export({ format: "jwk" })
  const sealingPrivateRaw = Buffer.from(sealingPrivateJwk.d ?? "", "base64url")
  const sealingPublicRaw = Buffer.from(sealingPublic, "base64url")
  if (sealingPrivateRaw.length !== 32 || sealingPublicRaw.length !== 32) throw new Error("invalid device key material")
  const publicKeys = { signing: signingPublic, sealing: sealingPublic }
  return {
    principal: () => ({ kind: "device", id }),
    publicKeys: () => ({ ...publicKeys }),
    sign: async request => {
      const payload = validateSignRequest(request)
      return ed25519Sign(null, domainSeparatedMessage(request.purpose, payload), signingPrivateKey)
    },
    unseal: async wrap => openHpkeSealedBox(sealingPrivateRaw, sealingPublicRaw, wrap),
  }
}

/**
 * In-memory DeviceKeyring for tests and fixtures: generates fresh keys per
 * instance. A process restart is a new principal.
 */
export function createInMemoryDeviceKeyring(id: string): DeviceKeyring {
  return createDeviceKeyring(id, generateDeviceKeyMaterial())
}

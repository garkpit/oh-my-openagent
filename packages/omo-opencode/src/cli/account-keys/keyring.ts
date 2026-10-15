import { Buffer } from "node:buffer"
import { createDeviceKeyring, generateDeviceKeyMaterial, type DeviceKeyring } from "@oh-my-opencode/memory-core"
import type { KeyStore } from "./keystore"

interface StoredDeviceKeys {
  readonly version: 1
  /** PKCS#8 DER of the Ed25519 private key, base64url. */
  readonly signing: string
  /** PKCS#8 DER of the X25519 private key, base64url. */
  readonly sealing: string
}

/**
 * Generates the device's Ed25519 + X25519 pairs and stores them in the OS
 * keystore. Idempotent: an existing record is reused untouched, so a repeated
 * `omo account keys init` never rotates keys out from under a synced account.
 * The private halves exist only inside the keystore record and this function's
 * stack frame; they are never logged and never returned.
 */
export async function initializeDeviceKeyring(store: KeyStore, deviceId = defaultDeviceId()): Promise<DeviceKeyring> {
  const existing = await loadDeviceKeyring(store, deviceId)
  if (existing) return existing
  const material = generateDeviceKeyMaterial()
  const record: StoredDeviceKeys = {
    version: 1,
    signing: material.signingPrivatePkcs8,
    sealing: material.sealingPrivatePkcs8,
  }
  await store.write(JSON.stringify(record))
  return createDeviceKeyring(deviceId, { signingPrivatePkcs8: record.signing, sealingPrivatePkcs8: record.sealing })
}

/**
 * Reopens the stored device keyring, or null when none exists. A corrupt
 * record throws without ever echoing the stored bytes into the error.
 */
export async function loadDeviceKeyring(store: KeyStore, deviceId = defaultDeviceId()): Promise<DeviceKeyring | null> {
  const raw = await store.read()
  if (raw === null) return null
  let record: StoredDeviceKeys
  try {
    const parsed: unknown = JSON.parse(raw)
    if (
      typeof parsed !== "object" || parsed === null ||
      typeof (parsed as { signing?: unknown }).signing !== "string" ||
      typeof (parsed as { sealing?: unknown }).sealing !== "string"
    ) {
      throw new Error("shape")
    }
    record = parsed as StoredDeviceKeys
    if (Buffer.from(record.signing, "base64url").length === 0 || Buffer.from(record.sealing, "base64url").length === 0) {
      throw new Error("length")
    }
  } catch {
    throw new Error("omo account keys: the stored device key record is unreadable. Run `omo account keys init` on a fresh keystore entry.")
  }
  return createDeviceKeyring(deviceId, { signingPrivatePkcs8: record.signing, sealingPrivatePkcs8: record.sealing })
}

function defaultDeviceId(): string {
  const name = process.env.OMO_DEVICE_NAME?.trim()
  return name && name.length > 0 ? name : "cli"
}

import type { JsonValue } from "./vendor/sync-format/jcs.ts"

export type SyncAuthor =
  | { readonly kind: "device"; readonly id: string }
  | { readonly kind: "recovery"; readonly credential_id: string }

export type SyncRecordFields = {
  readonly account: string
  readonly base_seq: number
  readonly digest: string
  readonly epoch: number
  readonly link: string
  readonly keyring_link: string | null
}

export type KeyringBody = {
  readonly kind: string
  readonly account: string
  readonly epoch: number
  readonly [field: string]: JsonValue
}

export type WrapEntry = { readonly epoch: number; readonly id: string; readonly wrap: string }

export type KeyringEntry = SyncRecordFields & {
  readonly seq: number
  readonly kind: "keyring"
  readonly author: SyncAuthor
  readonly body: KeyringBody
  readonly keyring_link: string
  readonly record_sig: string
  readonly wraps: ReadonlyArray<WrapEntry>
}

export type BatchEntry = SyncRecordFields & {
  readonly seq: number
  readonly kind: "batch"
  readonly author: SyncAuthor
  readonly keyring_link: null
  readonly record_sig: string
}

export type SyncEntry = KeyringEntry | BatchEntry

export type Head = { readonly seq: number; readonly link: string; readonly keyring_link: string }

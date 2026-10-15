import { type ChainState, emptyChain, verifyKeyringEntry } from "./chain.ts"
import type { KeyringEntry } from "./entry.ts"
import { isCancelledAdmission } from "./fold.ts"
import { openBatch } from "./open.ts"
import type { RejectionCounter } from "./rejection.ts"
import { authorSigningKey, decodeB64, verifyTagged } from "./signatures.ts"
import { concatBytes, sha256, sha256B64 } from "./vendor/sync-format/jcs.ts"
import type { SyncObjectRecord } from "./vendor/sync-format/object-types.ts"

export type SnapshotRecord = {
  readonly account: string
  readonly covers_seq: number
  readonly digest: string
  readonly link: string
  readonly keyring_head: string
  readonly author: { readonly kind: "device"; readonly id: string }
  readonly record_sig: string
}

export type SnapshotRejection =
  | "keyring_prefix_refused"
  | "bad_keyring_head"
  | "not_member"
  | "bad_signature"
  | "account_mismatch"
  | "digest_mismatch"
  | "chunk_refused"

export type SnapshotOutcome =
  | { readonly ok: true; readonly state: ChainState; readonly records: ReadonlyArray<SyncObjectRecord> }
  | { readonly ok: false; readonly reason: SnapshotRejection }

/**
 * Imports a compacted account from genesis (sync-design section 8.3): the keyring sub-chain
 * verifies record by record (signatures and keyring_link; the batches its main links hash
 * are compacted away), membership and the registry fold up to covers_seq, the snapshot's
 * keyring_head must equal that fold's sub-chain head, its record_sig must verify under a
 * folded member, and every chunk must verify and open before any record is returned. The
 * resulting state continues the main chain from the snapshot's link at covers_seq.
 */
export const importSnapshot = async (
  keyringEntries: ReadonlyArray<KeyringEntry>,
  snapshot: SnapshotRecord,
  chunks: ReadonlyArray<Uint8Array<ArrayBuffer>>,
  epochKeyFor: (epoch: number) => Uint8Array<ArrayBuffer> | null,
  rejections: RejectionCounter,
): Promise<SnapshotOutcome> => {
  const refuse = (reason: SnapshotRejection): SnapshotOutcome => {
    rejections.record(reason)
    return { ok: false, reason }
  }
  let state = emptyChain(snapshot.account)
  for (const entry of keyringEntries.filter((candidate) => candidate.seq <= snapshot.covers_seq)) {
    const step = await verifyKeyringEntry(state, entry, "keyring-only")
    if (!step.ok || step.step === "fork") return refuse("keyring_prefix_refused")
    state = step.state
  }
  const authority = state.authority
  if (authority === null || state.head === null) return refuse("keyring_prefix_refused")
  if (state.head.keyring_link !== snapshot.keyring_head) return refuse("bad_keyring_head")
  if (isCancelledAdmission(authority, snapshot.author.id)) return refuse("not_member")
  const signingKey = authorSigningKey(authority, snapshot.author)
  if (signingKey === null) return refuse("not_member")
  const payload = {
    t: "omo-sync/v1/snapshot",
    account: snapshot.account,
    covers_seq: snapshot.covers_seq,
    digest: snapshot.digest,
    link: snapshot.link,
    keyring_head: snapshot.keyring_head,
  }
  if (!(await verifyTagged("omo-sync/v1/snapshot", payload, signingKey, snapshot.record_sig))) {
    return refuse("bad_signature")
  }
  const chunkDigests = await Promise.all(chunks.map((chunk) => sha256(chunk)))
  if (decodeB64(snapshot.digest, 32) === null || (await sha256B64(concatBytes(chunkDigests))) !== snapshot.digest) {
    return refuse("digest_mismatch")
  }
  const epochKey = epochKeyFor(authority.epoch)
  if (epochKey === null) return refuse("chunk_refused")
  const records: SyncObjectRecord[] = []
  for (const [index, chunk] of chunks.entries()) {
    const opened = await openBatch(
      chunk,
      {
        account: snapshot.account,
        epoch: authority.epoch,
        authorId: snapshot.author.id,
        signingPublicKey: signingKey,
        digest: await sha256B64(chunk),
        kind: "snapshot",
        chunk: { index, count: chunks.length },
      },
      epochKey,
      rejections,
    )
    if (!opened.ok) return { ok: false, reason: "chunk_refused" }
    records.push(...opened.records)
  }
  return {
    ok: true,
    state: { ...state, head: { seq: snapshot.covers_seq, link: snapshot.link, keyring_link: snapshot.keyring_head } },
    records,
  }
}

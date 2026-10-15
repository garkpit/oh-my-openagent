import type { BatchEntry, Head, KeyringEntry, SyncAuthor, SyncEntry } from "./entry.ts"
import { type Authority, applyRecord, type FoldedRecord, isCancelledAdmission, isVetoedEpoch } from "./fold.ts"
import { nextLink } from "./links.ts"
import { type ParsedBody, parseBody } from "./parse.ts"
import type { RejectionCounter } from "./rejection.ts"
import { checkRecordRules, type RuleRejection } from "./rules.ts"
import { authorSigningKey, verifyRecordSig } from "./signatures.ts"
import { jcsBytes, sha256B64 } from "./vendor/sync-format/jcs.ts"

export type ChainRejection =
  | RuleRejection
  | "bad_record"
  | "link_mismatch"
  | "not_member"
  | "bad_signature"
  | "epoch_mismatch"
  | "account_mismatch"
  | "digest_mismatch"

export type ChainState = {
  readonly account: string
  readonly head: Head | null
  readonly authority: Authority | null
  readonly history: ReadonlyArray<FoldedRecord>
}

export type AcceptedBatch = {
  readonly seq: number
  readonly digest: string
  readonly epoch: number
  readonly authorId: string
  readonly signingPublicKey: string
}

export type ChainStep =
  | { readonly kind: "keyring"; readonly seq: number; readonly record: ParsedBody["kind"] }
  | { readonly kind: "batch"; readonly batch: AcceptedBatch }
  | { readonly kind: "vetoed"; readonly seq: number }

export type AppendOutcome =
  | { readonly ok: true; readonly state: ChainState; readonly steps: ReadonlyArray<ChainStep>; readonly forkAt: number | null }
  | {
      readonly ok: false
      readonly state: ChainState
      readonly steps: ReadonlyArray<ChainStep>
      readonly seq: number
      readonly reason: ChainRejection
    }

export const emptyChain = (account: string): ChainState => ({ account, head: null, authority: null, history: [] })

/** Main-chain mode checks seq, base_seq and link; keyring-only mode (snapshot import) checks the sub-chain alone. */
export type LinkMode = "main" | "keyring-only"

const linksHold = async (state: ChainState, entry: SyncEntry, mode: LinkMode): Promise<boolean> => {
  const head = state.head
  const priorSeq = head === null ? 0 : head.seq
  if (mode === "main") {
    if (entry.base_seq !== priorSeq || entry.seq !== priorSeq + 1) return false
    if (entry.link !== (await nextLink(head === null ? "" : head.link, entry.digest))) return false
  } else if (entry.seq <= priorSeq || entry.base_seq !== entry.seq - 1) {
    return false
  }
  if (entry.kind === "batch") return entry.keyring_link === null
  return entry.keyring_link === (await nextLink(head === null ? "" : head.keyring_link, entry.digest))
}

const signerKey = (
  body: ParsedBody,
  before: Authority | null,
  author: SyncAuthor,
  history: ReadonlyArray<FoldedRecord>,
): string | null => {
  if (body.kind === "genesis") {
    return author.kind === "device" && author.id === body.firstDevice.id ? body.firstDevice.signing_public_key : null
  }
  if (before === null) return null
  if (body.kind === "recovery-join") {
    return author.kind === "recovery" && author.credential_id === body.credentialId
      ? authorSigningKey(before, author)
      : null
  }
  if (author.kind !== "device") return null
  if (body.kind === "recovery-join-vetoed") {
    const join = history.find((record) => record.digest === body.joinDigest)
    return join?.before == null ? null : authorSigningKey(join.before, author)
  }
  if (isCancelledAdmission(before, author.id)) return null
  return authorSigningKey(before, author)
}

const expectedEpoch = (body: ParsedBody, before: Authority | null): number | null => {
  if (body.kind === "genesis") return 1
  if (before === null) return null
  return body.kind === "rotation" ? before.epoch + 1 : before.epoch
}

type StepResult =
  | { readonly ok: true; readonly state: ChainState; readonly step: ChainStep | "fork" }
  | { readonly ok: false; readonly reason: ChainRejection }

/**
 * One keyring record through the receiver order of sync-design section 6: chain link,
 * record signature (against the authority folded from every earlier keyring record),
 * epoch, account binding, the per-kind rules of the section 8.2 verifier table, and
 * finally the content hash. A fork-resolution halts here for the engine's fork path.
 */
export const verifyKeyringEntry = async (state: ChainState, entry: KeyringEntry, mode: LinkMode): Promise<StepResult> => {
  if (!(await linksHold(state, entry, mode))) return { ok: false, reason: "link_mismatch" }
  const body = parseBody(entry.body)
  if (body === null) return { ok: false, reason: "bad_record" }
  const before = state.authority
  const key = signerKey(body, before, entry.author, state.history)
  if (key === null) return { ok: false, reason: "not_member" }
  if (!(await verifyRecordSig(key, entry))) return { ok: false, reason: "bad_signature" }
  if (entry.epoch !== expectedEpoch(body, before) || entry.body.epoch !== entry.epoch) {
    return { ok: false, reason: "epoch_mismatch" }
  }
  if (entry.account !== state.account || entry.body.account !== state.account) {
    return { ok: false, reason: "account_mismatch" }
  }
  const predecessor = state.head === null ? "" : state.head.keyring_link
  const ruleFailure = await checkRecordRules(entry, body, before, state.history, predecessor)
  if (ruleFailure !== null) return { ok: false, reason: ruleFailure }
  if ((await sha256B64(jcsBytes(entry.body))) !== entry.digest) return { ok: false, reason: "digest_mismatch" }
  if (body.kind === "fork-resolution") return { ok: true, state, step: "fork" }
  const record: FoldedRecord = { seq: entry.seq, digest: entry.digest, body, before }
  const authority = applyRecord(state.history, record)
  if (authority === null) return { ok: false, reason: "bad_record" }
  return {
    ok: true,
    state: {
      account: state.account,
      head: { seq: entry.seq, link: entry.link, keyring_link: entry.keyring_link },
      authority,
      history: [...state.history, record],
    },
    step: { kind: "keyring", seq: entry.seq, record: body.kind },
  }
}

const verifyBatchEntry = async (state: ChainState, entry: BatchEntry): Promise<StepResult> => {
  if (!(await linksHold(state, entry, "main"))) return { ok: false, reason: "link_mismatch" }
  const authority = state.authority
  const head = state.head
  if (authority === null || head === null) return { ok: false, reason: "not_member" }
  const next: ChainState = { ...state, head: { seq: entry.seq, link: entry.link, keyring_link: head.keyring_link } }
  const authorId = entry.author.kind === "device" ? entry.author.id : ""
  if (isVetoedEpoch(authority, entry.epoch) || isCancelledAdmission(authority, authorId)) {
    return { ok: true, state: next, step: { kind: "vetoed", seq: entry.seq } }
  }
  const key = entry.author.kind === "device" ? authorSigningKey(authority, entry.author) : null
  if (key === null) return { ok: false, reason: "not_member" }
  if (!(await verifyRecordSig(key, entry))) return { ok: false, reason: "bad_signature" }
  if (entry.epoch !== authority.epoch) return { ok: false, reason: "epoch_mismatch" }
  if (entry.account !== state.account) return { ok: false, reason: "account_mismatch" }
  const batch: AcceptedBatch = { seq: entry.seq, digest: entry.digest, epoch: entry.epoch, authorId, signingPublicKey: key }
  return { ok: true, state: next, step: { kind: "batch", batch } }
}

/**
 * Extends the local verified chain entry by entry. The first refused entry stops the walk,
 * counts one content-free rejection and leaves the state at the last verified entry;
 * vetoed-epoch batches advance the cursor without being applied.
 */
export const appendEntries = async (
  state: ChainState,
  entries: ReadonlyArray<SyncEntry>,
  rejections: RejectionCounter,
): Promise<AppendOutcome> => {
  let current = state
  const steps: ChainStep[] = []
  for (const entry of entries) {
    const result = entry.kind === "keyring" ? await verifyKeyringEntry(current, entry, "main") : await verifyBatchEntry(current, entry)
    if (!result.ok) {
      rejections.record(result.reason)
      return { ok: false, state: current, steps, seq: entry.seq, reason: result.reason }
    }
    if (result.step === "fork") return { ok: true, state: current, steps, forkAt: entry.seq }
    current = result.state
    steps.push(result.step)
  }
  return { ok: true, state: current, steps, forkAt: null }
}

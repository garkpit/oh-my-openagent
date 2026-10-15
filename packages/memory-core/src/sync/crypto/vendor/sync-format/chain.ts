/**
 * The keyring fold of docs/sync-design.md sections 7 and 8.2: membership and the recovery
 * registry computed from the chain alone, plus the record-signature preimage. A batch's author
 * must resolve to a signing key through this fold at the entry's position - a principal the
 * folded membership no longer holds (a rotated-out signer) authorizes nothing after it.
 */
import { b64urlDecode, b64urlEncode, type JsonValue } from "./jcs.ts";
import { verifyFramed } from "./keys.ts";

export type SyncPrincipal = {
  readonly kind: "device";
  readonly id: string;
  readonly sealing_public_key: string;
  readonly signing_public_key: string;
};

export type SyncRecoveryKey = {
  readonly credential_id: string;
  readonly rp_id: string;
  readonly enrollment_nonce: string;
  readonly sealing_public_key: string;
  readonly signing_public_key: string;
  readonly survivable: "synced" | "roaming";
};

/** The record bodies the fold reads, with the fields each kind needs present. */
export type KeyringBody = {
  readonly kind: string;
  readonly account: string;
  readonly epoch: number;
  readonly bootstrap?: {
    readonly first_device: SyncPrincipal;
    readonly recovery_key: SyncRecoveryKey;
  };
  readonly principal?: SyncPrincipal;
  readonly credential_id?: string;
  readonly members?: ReadonlyArray<SyncPrincipal>;
  readonly join_digest?: string;
  readonly wraps_digest?: string;
  readonly custody_root?: string;
  readonly countersign?: string;
};

/** One chain entry (a keyring record or a batch's signed envelope) as pull rows carry it. */
export type ChainEntry = {
  readonly seq: number;
  readonly base_seq: number;
  readonly kind: "batch" | "keyring";
  readonly account: string;
  readonly epoch: number;
  readonly author: { readonly kind: string; readonly id: string };
  readonly body?: KeyringBody;
  readonly digest: string;
  readonly link: string;
  readonly keyring_link?: string | null;
  readonly record_sig: string;
};

/** The folded authority at a chain position: who may sign, and every enrolled recovery key. */
export type AuthorityFold = {
  readonly members: ReadonlyMap<string, SyncPrincipal>;
  readonly registry: ReadonlyMap<string, SyncRecoveryKey>;
  /** Digests of keyring records a veto cancelled; their descendants carry no authority. */
  readonly cancelled: ReadonlySet<string>;
};

type BodyAt = (entry: ChainEntry) => KeyringBody | null;

const bodyOf: BodyAt = (entry) =>
  entry.body !== undefined && entry.kind === "keyring" ? entry.body : null;

const readStringField = (body: KeyringBody, key: string): string => {
  const value: unknown = Reflect.get(body, key);
  return typeof value === "string" ? value : "";
};

const readSurvivable = (body: KeyringBody): "synced" | "roaming" => {
  const value: unknown = Reflect.get(body, "survivable");
  return value === "roaming" ? "roaming" : "synced";
};

/**
 * Folds keyring entries in sequence order: genesis seeds; approvals add; rotations replace the
 * membership; a recovery-join resets both sets to the joined principal and the used key; a veto
 * restores the join's predecessor minus the used key and cancels every record after the join.
 * Batch entries carry no body and change nothing.
 */
export const foldAuthority = (entries: ReadonlyArray<ChainEntry>): AuthorityFold => {
  let members = new Map<string, SyncPrincipal>();
  let registry = new Map<string, SyncRecoveryKey>();
  const cancelled = new Set<string>();
  const before = new Map<
    number,
    { members: Map<string, SyncPrincipal>; registry: Map<string, SyncRecoveryKey> }
  >();
  for (const entry of entries) {
    before.set(entry.seq, { members: new Map(members), registry: new Map(registry) });
    const body = bodyOf(entry);
    if (body === null) continue;
    if (body.kind === "genesis" && body.bootstrap !== undefined) {
      members = new Map([[body.bootstrap.first_device.id, body.bootstrap.first_device]]);
      registry = new Map([
        [body.bootstrap.recovery_key.credential_id, body.bootstrap.recovery_key],
      ]);
    } else if (body.kind === "approval" && body.principal !== undefined) {
      members.set(body.principal.id, body.principal);
    } else if (body.kind === "recovery-key" && body.credential_id !== undefined) {
      registry.set(body.credential_id, {
        credential_id: body.credential_id,
        rp_id: readStringField(body, "rp_id"),
        enrollment_nonce: readStringField(body, "enrollment_nonce"),
        sealing_public_key: readStringField(body, "sealing_public_key"),
        signing_public_key: readStringField(body, "signing_public_key"),
        survivable: readSurvivable(body),
      });
    } else if (body.kind === "recovery-key-removed" && body.credential_id !== undefined) {
      registry.delete(body.credential_id);
    } else if (body.kind === "recovery-join" && body.principal !== undefined) {
      const used = body.credential_id !== undefined ? registry.get(body.credential_id) : undefined;
      members = new Map([[body.principal.id, body.principal]]);
      registry = used === undefined ? new Map() : new Map([[used.credential_id, used]]);
    } else if (body.kind === "recovery-join-vetoed" && body.join_digest !== undefined) {
      const join = entries.find(
        (candidate) => candidate.digest === body.join_digest && candidate.body !== undefined,
      );
      const joinBody = join === undefined ? null : bodyOf(join);
      const prior = join === undefined ? undefined : before.get(join.seq);
      if (joinBody !== null && prior !== undefined) {
        members = new Map(prior.members);
        registry = new Map(prior.registry);
        if (joinBody.credential_id !== undefined) registry.delete(joinBody.credential_id);
        for (const later of entries) {
          if (later.seq > (join?.seq ?? 0) && later.seq < entry.seq) cancelled.add(later.digest);
        }
      }
    } else if (body.kind === "rotation" && body.members !== undefined) {
      members = new Map(body.members.map((member) => [member.id, member]));
    }
  }
  return { members, registry, cancelled };
};

/** The signed preimage of an entry's record_sig (batches omit keyring_link, never sign null). */
export const recordPreimage = (entry: ChainEntry): JsonValue => ({
  t: "omo-sync/v1/record",
  account: entry.account,
  base_seq: entry.base_seq,
  digest: entry.digest,
  epoch: entry.epoch,
  link: entry.link,
  ...(entry.kind === "keyring" && entry.keyring_link !== null && entry.keyring_link !== undefined
    ? { keyring_link: entry.keyring_link }
    : {}),
});

export type EntryAuthorization =
  | { readonly ok: true; readonly signingPublicKey: Uint8Array<ArrayBuffer> }
  | { readonly ok: false; readonly reason: "not_member" | "bad_base64url" };

/**
 * The signing key an entry's author is authorized with at the folded position: a device's own
 * registered key, or the enrolled recovery signing key for a recovery author. Absent from the
 * fold (a rotated-out signer, an unknown recovery credential) authorizes nothing.
 */
export const entryAuthorKey = (
  fold: AuthorityFold,
  author: ChainEntry["author"],
): EntryAuthorization => {
  const b64 =
    author.kind === "recovery"
      ? fold.registry.get(author.id)?.signing_public_key
      : fold.members.get(author.id)?.signing_public_key;
  if (b64 === undefined) return { ok: false, reason: "not_member" };
  try {
    const keyBytes = b64urlDecode(b64);
    return keyBytes.length === 32
      ? { ok: true, signingPublicKey: keyBytes }
      : { ok: false, reason: "bad_base64url" };
  } catch {
    return { ok: false, reason: "bad_base64url" };
  }
};

/** Verifies one entry's record_sig against the fold taken at the entry's own position. */
export const verifyEntrySignature = async (
  fold: AuthorityFold,
  entry: ChainEntry,
): Promise<boolean> => {
  const key = entryAuthorKey(fold, entry.author);
  if (!key.ok) return false;
  return verifyFramed(
    "omo-sync/v1/record",
    recordPreimage(entry),
    key.signingPublicKey,
    b64urlDecode(entry.record_sig),
  );
};

/** The b64url form of a digest hexed nowhere: links hash raw 32-byte digests, never text. */
export const linkDigestPair = (priorLink: string, digest: string): Uint8Array<ArrayBuffer> => {
  const prior = b64urlDecode(priorLink);
  const current = b64urlDecode(digest);
  return new Uint8Array([...prior, ...current]);
};

export const b64url = b64urlEncode;

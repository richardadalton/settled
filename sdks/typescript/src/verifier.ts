import * as crypto from 'node:crypto';
import type { SignedTreeHead } from './types.js';

// ── Hash primitives ───────────────────────────────────────────────────────────

export function leafHash(data: Uint8Array): Uint8Array {
  const h = crypto.createHash('sha256');
  h.update(Buffer.from([0x00]));
  h.update(data);
  return new Uint8Array(h.digest());
}

export function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const h = crypto.createHash('sha256');
  h.update(Buffer.from([0x01]));
  h.update(left);
  h.update(right);
  return new Uint8Array(h.digest());
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/** Largest power of 2 strictly less than n. Requires n > 1. */
function k(n: bigint): bigint {
  let p = 1n;
  while (p * 2n < n) p <<= 1n;
  return p;
}

// ── Inclusion proof ───────────────────────────────────────────────────────────

/**
 * Verify an RFC 6962 inclusion proof.
 * Returns true iff leafHash at leafIndex in a tree of treeSize with the given
 * proof elements produces root.
 */
export function verifyInclusion(
  leaf: Uint8Array,
  leafIndex: bigint,
  treeSize: bigint,
  proof: Uint8Array[],
  root: Uint8Array,
): boolean {
  if (treeSize === 0n || leafIndex >= treeSize) return false;

  let fn_ = leafIndex;
  let sn = treeSize - 1n;
  let r = leaf;

  for (const step of proof) {
    if (sn === 0n) return false;
    if ((fn_ & 1n) !== 0n || fn_ === sn) {
      r = nodeHash(step, r);
      while (fn_ !== 0n && (fn_ & 1n) === 0n) {
        fn_ >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = nodeHash(r, step);
    }
    fn_ >>= 1n;
    sn >>= 1n;
  }

  return sn === 0n && bytesEqual(r, root);
}

// ── Consistency proof ─────────────────────────────────────────────────────────

/**
 * Verify an RFC 6962 consistency proof.
 * Returns true iff the tree of oldSize with oldRoot is a prefix of the tree of
 * newSize with newRoot, as proven by proof.
 */
export function verifyConsistency(
  oldSize: bigint,
  newSize: bigint,
  proof: Uint8Array[],
  oldRoot: Uint8Array,
  newRoot: Uint8Array,
): boolean {
  if (oldSize === newSize) {
    return proof.length === 0 && bytesEqual(oldRoot, newRoot);
  }
  if (oldSize === 0n || oldSize > newSize) return false;

  let idx = 0;
  const next = (): Uint8Array | null => {
    if (idx >= proof.length) return null;
    return proof[idx++];
  };

  const result = verifySubproof(oldSize, newSize, oldRoot, next, true);
  if (result === null) return false;
  const [computedOld, computedNew] = result;

  return (
    idx === proof.length &&
    bytesEqual(computedOld, oldRoot) &&
    bytesEqual(computedNew, newRoot)
  );
}

function verifySubproof(
  m: bigint,
  n: bigint,
  oldRoot: Uint8Array,
  next: () => Uint8Array | null,
  b: boolean,
): [Uint8Array, Uint8Array] | null {
  if (m === n) {
    if (b) return [oldRoot, oldRoot];
    const h = next();
    if (h === null) return null;
    return [h, h];
  }
  const split = k(n);
  if (m <= split) {
    const sub = verifySubproof(m, split, oldRoot, next, b);
    if (sub === null) return null;
    const [lo, ln] = sub;
    const rh = next();
    if (rh === null) return null;
    return [lo, nodeHash(ln, rh)];
  } else {
    const sub = verifySubproof(m - split, n - split, oldRoot, next, false);
    if (sub === null) return null;
    const [ro, rn] = sub;
    const lh = next();
    if (lh === null) return null;
    return [nodeHash(lh, ro), nodeHash(lh, rn)];
  }
}

// ── Signed Tree Head ──────────────────────────────────────────────────────────

/**
 * Canonical signing payload: tree_size (u64 BE) || root_hash (32 bytes) || timestamp_ns (i64 BE).
 * See docs/wire-format.md §5.2.
 */
export function signingPayload(sth: SignedTreeHead): Uint8Array {
  const buf = Buffer.alloc(48);
  buf.writeBigUInt64BE(sth.treeSize, 0);
  Buffer.from(sth.rootHash).copy(buf, 8);
  buf.writeBigInt64BE(sth.timestampNs, 40);
  return buf;
}

// ── Key chain ─────────────────────────────────────────────────────────────────

/** A key chain record returned by GET /api/keys. */
export interface KeyRecord {
  version: number;
  publicKey: Uint8Array;
  activatedAtTreeSize: bigint;
}

/**
 * Verify an STH against a key chain.
 * Finds the record whose version matches sth.keyVersion and verifies the
 * signature with that record's publicKey.
 */
export function verifyTreeHeadWithChain(sth: SignedTreeHead, chain: KeyRecord[]): boolean {
  const record = chain.find((r) => r.version === sth.keyVersion);
  if (record === undefined) return false;
  return verifyTreeHead({ ...sth, publicKey: record.publicKey });
}

/**
 * Verify the Ed25519 signature on a SignedTreeHead.
 * The public key must be the raw 32-byte Ed25519 public key from the STH.
 */
export function verifyTreeHead(sth: SignedTreeHead): boolean {
  try {
    // Wrap raw 32-byte Ed25519 public key in SPKI DER encoding.
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      sth.publicKey,
    ]);
    const keyObject = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    const payload = signingPayload(sth);
    return crypto.verify(null, payload, keyObject, sth.signature);
  } catch {
    return false;
  }
}

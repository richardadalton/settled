import * as ed from '@noble/ed25519';
import type { InclusionProof, Sth } from '../types.js';

// @noble/ed25519 v2 uses globalThis.crypto.subtle for SHA-512 by default in browsers.
// No explicit wiring needed; verifyAsync uses the async Web Crypto path.

// ── Hex / byte helpers ────────────────────────────────────────────────────────

function hex(h: string): Uint8Array {
  const bytes = new Uint8Array(h.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

// ── RFC 6962 hash functions (SHA-256 via Web Crypto) ─────────────────────────

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}

export async function leafHash(data: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x00]), data));
}

async function nodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  return sha256(concat(new Uint8Array([0x01]), left, right));
}

// ── Inclusion proof verification ──────────────────────────────────────────────

export type InclusionResult =
  | { ok: true;  steps: ProofStep[] }
  | { ok: false; steps: ProofStep[]; reason: string };

export type ProofStep = {
  sibling:   string;   // hex
  direction: 'left' | 'right';
  running:   string;   // hex — hash after combining this step
};

export async function verifyInclusion(
  proof: InclusionProof,
  entryData: Uint8Array,
): Promise<InclusionResult> {
  const steps: ProofStep[] = [];

  try {
    let current = await leafHash(entryData);

    let idx  = proof.leaf_index;
    let size = proof.tree_size;

    for (const siblingHex of proof.proof) {
      const sibling = hex(siblingHex);
      let direction: 'left' | 'right';

      if (idx % 2 === 1 || idx === size - 1) {
        // sibling is to the left
        current   = await nodeHash(sibling, current);
        direction = 'left';
      } else {
        // sibling is to the right
        current   = await nodeHash(current, sibling);
        direction = 'right';
      }

      idx  = Math.floor(idx / 2);
      size = Math.floor((size + 1) / 2);

      steps.push({ sibling: siblingHex, direction, running: toHex(current) });
    }

    const computedRoot = toHex(current);
    const expectedRoot = proof.sth.root_hash;

    if (computedRoot !== expectedRoot) {
      return { ok: false, steps, reason: `root mismatch: computed ${computedRoot.slice(0, 16)}… expected ${expectedRoot.slice(0, 16)}…` };
    }

    return { ok: true, steps };
  } catch (e) {
    return { ok: false, steps, reason: String(e) };
  }
}

// ── STH signature verification ────────────────────────────────────────────────

export type SthResult =
  | { ok: true }
  | { ok: false; reason: string };

export async function verifySth(sth: Sth): Promise<SthResult> {
  try {
    // Wire format matches sth.rs: tree_size (u64 BE) || root_hash (32 bytes) || timestamp_ns (i64 BE)
    const msg = buildSthMessage(sth);
    const sig = hex(sth.signature);
    const pub = hex(sth.public_key);

    const valid = await ed.verifyAsync(sig, msg, pub);
    if (!valid) return { ok: false, reason: 'signature invalid' };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: String(e) };
  }
}

function buildSthMessage(sth: Sth): Uint8Array {
  const rootHash = hex(sth.root_hash);

  // tree_size as u64 big-endian
  const treeSize = new DataView(new ArrayBuffer(8));
  const ts = BigInt(sth.tree_size);
  treeSize.setBigUint64(0, ts, false);

  // timestamp_ns as i64 big-endian
  const tsNs = new DataView(new ArrayBuffer(8));
  const ns = BigInt(sth.timestamp_ns);
  tsNs.setBigInt64(0, ns, false);

  return concat(
    new Uint8Array(treeSize.buffer),
    rootHash,
    new Uint8Array(tsNs.buffer),
  );
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

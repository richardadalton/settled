import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { leafHash, verifyInclusion, verifyTreeHead } from '../src/verifier.js';
import type { SignedTreeHead } from '../src/types.js';

const INTEROP_DATA = process.env.INTEROP_DATA ?? '';

interface InteropEntry {
  seq: number;
  data_hex: string;
  leaf_hash_hex: string;
}

interface InteropSth {
  tree_size: number;
  root_hash_hex: string;
  timestamp_ns: number;
  timestamp_ns_str: string;
  signature_hex: string;
  public_key_hex: string;
  key_version: number;
}

interface InteropProof {
  seq: number;
  leaf_hash_hex: string;
  proof_hex: string[];
}

interface InteropData {
  entries: InteropEntry[];
  sth: InteropSth;
  inclusion_proofs: InteropProof[];
}

function hex(s: string): Uint8Array {
  return s.length === 0 ? new Uint8Array(0) : new Uint8Array(Buffer.from(s, 'hex'));
}

// Parsed once at module load; null when INTEROP_DATA is not set.
const d: InteropData | null = INTEROP_DATA
  ? (JSON.parse(readFileSync(INTEROP_DATA, 'utf-8')) as InteropData)
  : null;

describe.skipIf(!d)('cross-SDK interop', () => {
  it('STH signature verifies', () => {
    const sth: SignedTreeHead = {
      treeSize: BigInt(d!.sth.tree_size),
      rootHash: hex(d!.sth.root_hash_hex),
      // Use the string field to avoid float64 precision loss on large timestamps.
      timestampNs: BigInt(d!.sth.timestamp_ns_str),
      signature: hex(d!.sth.signature_hex),
      publicKey: hex(d!.sth.public_key_hex),
      keyVersion: d!.sth.key_version,
    };
    expect(verifyTreeHead(sth)).toBe(true);
  });

  for (const ip of d?.inclusion_proofs ?? []) {
    it(`inclusion proof seq ${ip.seq}`, () => {
      expect(
        verifyInclusion(
          hex(ip.leaf_hash_hex),
          BigInt(ip.seq),
          BigInt(d!.sth.tree_size),
          ip.proof_hex.map(hex),
          hex(d!.sth.root_hash_hex),
        ),
      ).toBe(true);
    });
  }

  for (const entry of d?.entries ?? []) {
    it(`leaf hash seq ${entry.seq}`, () => {
      const got = leafHash(hex(entry.data_hex));
      expect(Buffer.from(got).toString('hex')).toBe(entry.leaf_hash_hex);
    });
  }
});

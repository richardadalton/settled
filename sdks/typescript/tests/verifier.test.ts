import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  leafHash,
  nodeHash,
  verifyConsistency,
  verifyInclusion,
  verifyTreeHead,
  verifyTreeHeadSequential,
} from '../src/verifier.js';
import type { SignedTreeHead } from '../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTORS = resolve(__dirname, '../../../test-vectors');

function loadJson(name: string): unknown {
  return JSON.parse(readFileSync(resolve(VECTORS, name), 'utf-8'));
}

function hex(s: string): Uint8Array {
  return s.length === 0 ? new Uint8Array(0) : new Uint8Array(Buffer.from(s, 'hex'));
}

// ── Leaf hashes ───────────────────────────────────────────────────────────────

describe('leafHash', () => {
  const vectors = loadJson('leaf-hashes.json') as Array<{
    description: string;
    input_hex: string;
    hash_hex: string;
  }>;

  for (const v of vectors) {
    it(v.description, () => {
      const got = leafHash(hex(v.input_hex));
      expect(Buffer.from(got).toString('hex')).toBe(v.hash_hex);
    });
  }
});

// ── Node hashes ───────────────────────────────────────────────────────────────

describe('nodeHash', () => {
  const vectors = loadJson('node-hashes.json') as Array<{
    description: string;
    left_hex: string;
    right_hex: string;
    hash_hex?: string;
    swapped_hash_hex?: string;
  }>;

  for (const v of vectors) {
    if (v.hash_hex) {
      it(v.description, () => {
        const got = nodeHash(hex(v.left_hex), hex(v.right_hex));
        expect(Buffer.from(got).toString('hex')).toBe(v.hash_hex);
      });
    }
    if (v.swapped_hash_hex) {
      it(`${v.description} — non-commutative`, () => {
        const ab = nodeHash(hex(v.left_hex), hex(v.right_hex));
        const ba = nodeHash(hex(v.right_hex), hex(v.left_hex));
        expect(Buffer.from(ab).toString('hex')).not.toBe(Buffer.from(ba).toString('hex'));
        expect(Buffer.from(ba).toString('hex')).toBe(v.swapped_hash_hex);
      });
    }
  }
});

// ── Inclusion proofs ──────────────────────────────────────────────────────────

describe('verifyInclusion', () => {
  const vectors = loadJson('inclusion-proofs.json') as Array<{
    tree_size: number;
    leaf_index: number;
    leaf_hash_hex: string;
    proof_hex: string[];
    root_hex: string;
  }>;

  for (const v of vectors) {
    it(`size=${v.tree_size} idx=${v.leaf_index}`, () => {
      expect(
        verifyInclusion(
          hex(v.leaf_hash_hex),
          BigInt(v.leaf_index),
          BigInt(v.tree_size),
          v.proof_hex.map(hex),
          hex(v.root_hex),
        ),
      ).toBe(true);
    });
  }
});

// ── Consistency proofs ────────────────────────────────────────────────────────

describe('verifyConsistency', () => {
  const vectors = loadJson('consistency-proofs.json') as Array<{
    old_size: number;
    new_size: number;
    old_root_hex: string;
    new_root_hex: string;
    proof_hex: string[];
  }>;

  for (const v of vectors) {
    it(`old=${v.old_size} new=${v.new_size}`, () => {
      expect(
        verifyConsistency(
          BigInt(v.old_size),
          BigInt(v.new_size),
          v.proof_hex.map(hex),
          hex(v.old_root_hex),
          hex(v.new_root_hex),
        ),
      ).toBe(true);
    });
  }
});

// ── Signed Tree Heads ─────────────────────────────────────────────────────────

describe('verifyTreeHead', () => {
  const vectors = loadJson('signed-tree-heads.json') as Array<{
    description: string;
    tree_size: number;
    root_hash_hex: string;
    timestamp_ns: number;
    signature_hex: string;
    public_key_hex: string;
  }>;

  for (const v of vectors) {
    it(v.description, () => {
      const sth: SignedTreeHead = {
        treeSize: BigInt(v.tree_size),
        rootHash: hex(v.root_hash_hex),
        timestampNs: BigInt(v.timestamp_ns),
        signature: hex(v.signature_hex),
        publicKey: hex(v.public_key_hex),
        keyVersion: 1,
      };
      expect(verifyTreeHead(sth)).toBe(true);
    });

    it(`${v.description} — tampered tree_size fails`, () => {
      const sth: SignedTreeHead = {
        treeSize: BigInt(v.tree_size) + 1n,
        rootHash: hex(v.root_hash_hex),
        timestampNs: BigInt(v.timestamp_ns),
        signature: hex(v.signature_hex),
        publicKey: hex(v.public_key_hex),
        keyVersion: 1,
      };
      expect(verifyTreeHead(sth)).toBe(false);
    });

    it(`${v.description} — tampered root_hash fails`, () => {
      const root = Buffer.from(hex(v.root_hash_hex));
      root[0] ^= 0xff;
      const sth: SignedTreeHead = {
        treeSize: BigInt(v.tree_size),
        rootHash: root,
        timestampNs: BigInt(v.timestamp_ns),
        signature: hex(v.signature_hex),
        publicKey: hex(v.public_key_hex),
        keyVersion: 1,
      };
      expect(verifyTreeHead(sth)).toBe(false);
    });
  }
});

// ── Sequential STH verification ───────────────────────────────────────────────

describe('verifyTreeHeadSequential', () => {
  const vectors = loadJson('signed-tree-heads.json') as Array<{
    description: string;
    tree_size: number;
    root_hash_hex: string;
    timestamp_ns: number;
    signature_hex: string;
    public_key_hex: string;
  }>;

  for (let i = 0; i + 1 < vectors.length; i++) {
    const prev = vectors[i];
    const curr = vectors[i + 1];
    it(`${curr.description} after ${prev.description}`, () => {
      const sth: SignedTreeHead = {
        treeSize: BigInt(curr.tree_size),
        rootHash: hex(curr.root_hash_hex),
        timestampNs: BigInt(curr.timestamp_ns),
        signature: hex(curr.signature_hex),
        publicKey: hex(curr.public_key_hex),
        keyVersion: 1,
      };
      expect(verifyTreeHeadSequential(sth, BigInt(prev.timestamp_ns))).toBe(true);
    });
  }

  it('equal timestamp fails', () => {
    const v = vectors[0];
    const sth: SignedTreeHead = {
      treeSize: BigInt(v.tree_size),
      rootHash: hex(v.root_hash_hex),
      timestampNs: BigInt(v.timestamp_ns),
      signature: hex(v.signature_hex),
      publicKey: hex(v.public_key_hex),
      keyVersion: 1,
    };
    expect(verifyTreeHeadSequential(sth, BigInt(v.timestamp_ns))).toBe(false);
  });
});

// ── Negative cases ────────────────────────────────────────────────────────────

describe('negative cases', () => {
  const all = loadJson('negative-cases.json') as Record<
    string,
    {
      leaf_hash_hex?: string;
      leaf_index?: number;
      tree_size?: number;
      proof_hex?: string[];
      root_hex?: string;
      old_size?: number;
      new_size?: number;
      old_root_hex?: string;
      new_root_hex?: string;
      root_hash_hex?: string;
      timestamp_ns?: number;
      signature_hex?: string;
      public_key_hex?: string;
      previous_timestamp_ns?: number;
      expected_result: boolean;
    }
  >;

  for (const [name, v] of Object.entries(all)) {
    if (name.startsWith('inclusion_')) {
      it(name, () => {
        expect(
          verifyInclusion(
            hex(v.leaf_hash_hex!),
            BigInt(v.leaf_index!),
            BigInt(v.tree_size!),
            v.proof_hex!.map(hex),
            hex(v.root_hex!),
          ),
        ).toBe(v.expected_result);
      });
    } else if (name.startsWith('consistency_')) {
      it(name, () => {
        expect(
          verifyConsistency(
            BigInt(v.old_size!),
            BigInt(v.new_size!),
            v.proof_hex!.map(hex),
            hex(v.old_root_hex!),
            hex(v.new_root_hex!),
          ),
        ).toBe(v.expected_result);
      });
    } else if (name.startsWith('tree_head_sequential_')) {
      it(name, () => {
        const sth: SignedTreeHead = {
          treeSize: BigInt(v.tree_size!),
          rootHash: hex(v.root_hash_hex!),
          timestampNs: BigInt(v.timestamp_ns!),
          signature: hex(v.signature_hex!),
          publicKey: hex(v.public_key_hex!),
          keyVersion: 1,
        };
        expect(verifyTreeHeadSequential(sth, BigInt(v.previous_timestamp_ns!))).toBe(
          v.expected_result,
        );
      });
    }
  }
});

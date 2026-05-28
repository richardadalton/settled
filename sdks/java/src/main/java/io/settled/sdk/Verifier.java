package io.settled.sdk;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * Pure-Java RFC 6962 Merkle tree proof verifier and Ed25519 STH verifier.
 * See docs/wire-format.md for the canonical specification.
 */
public final class Verifier {

    private Verifier() {}

    // ── Hash primitives ───────────────────────────────────────────────────────

    /** SHA-256(0x00 || data) */
    public static byte[] leafHash(byte[] data) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            h.update((byte) 0x00);
            h.update(data);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /** SHA-256(0x01 || left || right) */
    public static byte[] nodeHash(byte[] left, byte[] right) {
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-256");
            h.update((byte) 0x01);
            h.update(left);
            h.update(right);
            return h.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // ── Inclusion proof ───────────────────────────────────────────────────────

    /**
     * Verify an RFC 6962 inclusion proof.
     */
    public static boolean verifyInclusion(
            byte[] leaf,
            long leafIndex,
            long treeSize,
            List<byte[]> proof,
            byte[] root) {
        if (treeSize == 0 || Long.compareUnsigned(leafIndex, treeSize) >= 0) return false;

        long fn = leafIndex;
        long sn = treeSize - 1;
        byte[] r = leaf;

        for (byte[] step : proof) {
            if (sn == 0) return false;
            if ((fn & 1) != 0 || fn == sn) {
                r = nodeHash(step, r);
                while (fn != 0 && (fn & 1) == 0) {
                    fn >>>= 1;
                    sn >>>= 1;
                }
            } else {
                r = nodeHash(r, step);
            }
            fn >>>= 1;
            sn >>>= 1;
        }

        return sn == 0 && Arrays.equals(r, root);
    }

    // ── Consistency proof ─────────────────────────────────────────────────────

    /** Largest power of 2 strictly less than n. Requires n > 1. */
    private static long k(long n) {
        long p = 1;
        while (p * 2 < n) p <<= 1;
        return p;
    }

    /**
     * Verify an RFC 6962 consistency proof.
     */
    public static boolean verifyConsistency(
            long oldSize,
            long newSize,
            List<byte[]> proof,
            byte[] oldRoot,
            byte[] newRoot) {
        if (oldSize == newSize) {
            return proof.isEmpty() && Arrays.equals(oldRoot, newRoot);
        }
        if (oldSize == 0 || Long.compareUnsigned(oldSize, newSize) > 0) return false;

        int[] idx = {0};
        byte[][] result = verifySubproof(oldSize, newSize, oldRoot, proof, idx, true);
        if (result == null) return false;

        return idx[0] == proof.size()
                && Arrays.equals(result[0], oldRoot)
                && Arrays.equals(result[1], newRoot);
    }

    /** Returns [computedOld, computedNew] or null on failure. */
    private static byte[][] verifySubproof(
            long m, long n, byte[] oldRoot, List<byte[]> proof, int[] idx, boolean b) {
        if (m == n) {
            if (b) return new byte[][]{oldRoot, oldRoot};
            if (idx[0] >= proof.size()) return null;
            byte[] h = proof.get(idx[0]++);
            return new byte[][]{h, h};
        }
        long split = k(n);
        if (Long.compareUnsigned(m, split) <= 0) {
            byte[][] sub = verifySubproof(m, split, oldRoot, proof, idx, b);
            if (sub == null) return null;
            if (idx[0] >= proof.size()) return null;
            byte[] rh = proof.get(idx[0]++);
            return new byte[][]{sub[0], nodeHash(sub[1], rh)};
        } else {
            byte[][] sub = verifySubproof(m - split, n - split, oldRoot, proof, idx, false);
            if (sub == null) return null;
            if (idx[0] >= proof.size()) return null;
            byte[] lh = proof.get(idx[0]++);
            return new byte[][]{nodeHash(lh, sub[0]), nodeHash(lh, sub[1])};
        }
    }

    // ── Sequential verification ───────────────────────────────────────────────

    /**
     * Verify an STH and enforce strict timestamp monotonicity.
     * Returns false if timestampNs &lt;= previousTimestampNs or if the signature
     * is invalid. Use when processing a sequence of STHs to guard against
     * replayed or out-of-order tree heads.
     */
    public static boolean verifyTreeHeadSequential(
            long treeSize,
            byte[] rootHash,
            long timestampNs,
            byte[] signature,
            byte[] publicKey,
            long previousTimestampNs) {
        if (timestampNs <= previousTimestampNs) return false;
        return verifyTreeHead(treeSize, rootHash, timestampNs, signature, publicKey);
    }

    // ── Key chain ─────────────────────────────────────────────────────────────

    /** A key chain record returned by GET /api/keys. */
    public static final class KeyRecord {
        public final int version;
        public final byte[] publicKey;
        public final long activatedAtTreeSize;

        public KeyRecord(int version, byte[] publicKey, long activatedAtTreeSize) {
            this.version = version;
            this.publicKey = publicKey;
            this.activatedAtTreeSize = activatedAtTreeSize;
        }
    }

    /**
     * Verify an STH against a key chain.
     * Finds the record whose version matches keyVersion and verifies the
     * signature with that record's publicKey.
     */
    public static boolean verifyTreeHeadWithChain(
            long treeSize,
            byte[] rootHash,
            long timestampNs,
            byte[] signature,
            int keyVersion,
            List<KeyRecord> chain) {
        for (KeyRecord r : chain) {
            if (r.version == keyVersion) {
                return verifyTreeHead(treeSize, rootHash, timestampNs, signature, r.publicKey);
            }
        }
        return false;
    }

    // ── Signed Tree Head ──────────────────────────────────────────────────────

    /**
     * Build the canonical 48-byte signing payload.
     * Encoding: tree_size (u64 BE) || root_hash (32 bytes) || timestamp_ns (i64 BE).
     * See docs/wire-format.md §5.2.
     */
    public static byte[] signingPayload(long treeSize, byte[] rootHash, long timestampNs) {
        ByteBuffer buf = ByteBuffer.allocate(48);
        buf.putLong(treeSize);
        buf.put(rootHash);
        buf.putLong(timestampNs);
        return buf.array();
    }

    /**
     * Verify the Ed25519 signature on a Signed Tree Head.
     * publicKey must be the raw 32-byte Ed25519 public key.
     * Requires Java 15+.
     */
    public static boolean verifyTreeHead(
            long treeSize,
            byte[] rootHash,
            long timestampNs,
            byte[] signature,
            byte[] publicKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            // Wrap raw bytes in SubjectPublicKeyInfo DER encoding.
            byte[] spkiHeader = hexToBytes("302a300506032b6570032100");
            byte[] spki = new byte[spkiHeader.length + publicKey.length];
            System.arraycopy(spkiHeader, 0, spki, 0, spkiHeader.length);
            System.arraycopy(publicKey, 0, spki, spkiHeader.length, publicKey.length);
            PublicKey key = kf.generatePublic(
                    new java.security.spec.X509EncodedKeySpec(spki));
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(key);
            sig.update(signingPayload(treeSize, rootHash, timestampNs));
            return sig.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }
}

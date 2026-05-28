using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace Settled.Sdk;

/// <summary>
/// Pure C# RFC 6962 Merkle tree proof verifier and Ed25519 STH verifier.
/// See docs/wire-format.md for the canonical specification.
/// </summary>
public static class Verifier
{
    // ── Hash primitives ───────────────────────────────────────────────────────

    /// <summary>SHA-256(0x00 || data)</summary>
    public static byte[] LeafHash(ReadOnlySpan<byte> data)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData([0x00]);
        h.AppendData(data);
        return h.GetHashAndReset();
    }

    /// <summary>SHA-256(0x01 || left || right)</summary>
    public static byte[] NodeHash(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData([0x01]);
        h.AppendData(left);
        h.AppendData(right);
        return h.GetHashAndReset();
    }

    // ── Inclusion proof ───────────────────────────────────────────────────────

    /// <summary>Verify an RFC 6962 inclusion proof.</summary>
    public static bool VerifyInclusion(
        byte[] leaf,
        ulong leafIndex,
        ulong treeSize,
        IReadOnlyList<byte[]> proof,
        byte[] root)
    {
        if (treeSize == 0 || leafIndex >= treeSize) return false;

        var fn = leafIndex;
        var sn = treeSize - 1;
        byte[] r = leaf;

        foreach (var step in proof)
        {
            if (sn == 0) return false;
            if ((fn & 1) != 0 || fn == sn)
            {
                r = NodeHash(step, r);
                while (fn != 0 && (fn & 1) == 0) { fn >>= 1; sn >>= 1; }
            }
            else
            {
                r = NodeHash(r, step);
            }
            fn >>= 1;
            sn >>= 1;
        }

        return sn == 0 && r.AsSpan().SequenceEqual(root);
    }

    // ── Consistency proof ─────────────────────────────────────────────────────

    private static ulong K(ulong n)
    {
        ulong p = 1;
        while (p * 2 < n) p <<= 1;
        return p;
    }

    /// <summary>Verify an RFC 6962 consistency proof.</summary>
    public static bool VerifyConsistency(
        ulong oldSize,
        ulong newSize,
        IReadOnlyList<byte[]> proof,
        byte[] oldRoot,
        byte[] newRoot)
    {
        if (oldSize == newSize) return proof.Count == 0 && oldRoot.AsSpan().SequenceEqual(newRoot);
        if (oldSize == 0 || oldSize > newSize) return false;

        var idx = 0;
        (byte[]? computedOld, byte[]? computedNew) = VerifySubproof(
            oldSize, newSize, oldRoot, proof, ref idx, true);

        if (computedOld is null || computedNew is null) return false;
        return idx == proof.Count
            && computedOld.AsSpan().SequenceEqual(oldRoot)
            && computedNew.AsSpan().SequenceEqual(newRoot);
    }

    private static (byte[]?, byte[]?) VerifySubproof(
        ulong m, ulong n, byte[] oldRoot,
        IReadOnlyList<byte[]> proof, ref int idx, bool b)
    {
        if (m == n)
        {
            if (b) return (oldRoot, oldRoot);
            if (idx >= proof.Count) return (null, null);
            var h = proof[idx++];
            return (h, h);
        }
        var split = K(n);
        if (m <= split)
        {
            var (lo, ln) = VerifySubproof(m, split, oldRoot, proof, ref idx, b);
            if (lo is null || ln is null) return (null, null);
            if (idx >= proof.Count) return (null, null);
            var rh = proof[idx++];
            return (lo, NodeHash(ln, rh));
        }
        else
        {
            var (ro, rn) = VerifySubproof(m - split, n - split, oldRoot, proof, ref idx, false);
            if (ro is null || rn is null) return (null, null);
            if (idx >= proof.Count) return (null, null);
            var lh = proof[idx++];
            return (NodeHash(lh, ro), NodeHash(lh, rn));
        }
    }

    // ── Sequential verification ───────────────────────────────────────────────

    /// <summary>
    /// Verify an STH and enforce strict timestamp monotonicity.
    /// Returns false if timestampNs &lt;= previousTimestampNs or if the signature
    /// is invalid. Use when processing a sequence of STHs to guard against
    /// replayed or out-of-order tree heads.
    /// </summary>
    public static bool VerifyTreeHeadSequential(
        ulong treeSize,
        byte[] rootHash,
        long timestampNs,
        byte[] signature,
        byte[] publicKey,
        long previousTimestampNs)
    {
        if (timestampNs <= previousTimestampNs) return false;
        return VerifyTreeHead(treeSize, rootHash, timestampNs, signature, publicKey);
    }

    // ── Key chain ─────────────────────────────────────────────────────────────

    /// <summary>A key chain record returned by GET /api/keys.</summary>
    public sealed class KeyRecord
    {
        public uint Version { get; init; }
        public byte[] PublicKey { get; init; } = [];
        public ulong ActivatedAtTreeSize { get; init; }
    }

    /// <summary>
    /// Verify an STH against a key chain.
    /// Finds the record whose Version matches keyVersion and verifies the
    /// signature with that record's PublicKey.
    /// </summary>
    public static bool VerifyTreeHeadWithChain(
        ulong treeSize,
        byte[] rootHash,
        long timestampNs,
        byte[] signature,
        uint keyVersion,
        IReadOnlyList<KeyRecord> chain)
    {
        foreach (var r in chain)
        {
            if (r.Version == keyVersion)
                return VerifyTreeHead(treeSize, rootHash, timestampNs, signature, r.PublicKey);
        }
        return false;
    }

    // ── Signed Tree Head ──────────────────────────────────────────────────────

    /// <summary>
    /// Build the canonical 48-byte signing payload.
    /// Encoding: tree_size (u64 BE) || root_hash (32 bytes) || timestamp_ns (i64 BE).
    /// See docs/wire-format.md §5.2.
    /// </summary>
    public static byte[] SigningPayload(ulong treeSize, byte[] rootHash, long timestampNs)
    {
        var buf = new byte[48];
        BinaryPrimitives.WriteUInt64BigEndian(buf.AsSpan(0, 8), treeSize);
        rootHash.AsSpan().CopyTo(buf.AsSpan(8, 32));
        BinaryPrimitives.WriteInt64BigEndian(buf.AsSpan(40, 8), timestampNs);
        return buf;
    }

    /// <summary>
    /// Verify the Ed25519 signature on a Signed Tree Head.
    /// publicKey must be the raw 32-byte Ed25519 public key.
    /// </summary>
    public static bool VerifyTreeHead(
        ulong treeSize,
        byte[] rootHash,
        long timestampNs,
        byte[] signature,
        byte[] publicKey)
    {
        try
        {
            var payload = SigningPayload(treeSize, rootHash, timestampNs);
            var key = new Ed25519PublicKeyParameters(publicKey, 0);
            var verifier = new Ed25519Signer();
            verifier.Init(false, key);
            verifier.BlockUpdate(payload, 0, payload.Length);
            return verifier.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }
}

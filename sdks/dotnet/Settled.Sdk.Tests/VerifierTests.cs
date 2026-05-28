using System.Text.Json;
using Settled.Sdk;
using Xunit;

namespace Settled.Sdk.Tests;

public class VerifierTests
{
    private static readonly string VectorsDir = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "../../../../../../test-vectors"));

    private static JsonElement Load(string name) =>
        JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(Path.Combine(VectorsDir, name)));

    private static byte[] H(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (var i = 0; i < hex.Length; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return bytes;
    }

    private static List<byte[]> Proofs(JsonElement arr) =>
        arr.EnumerateArray().Select(e => H(e.GetString()!)).ToList();

    // ── Leaf hashes ───────────────────────────────────────────────────────────

    [Fact]
    public void LeafHashVectors()
    {
        foreach (var v in Load("leaf-hashes.json").EnumerateArray())
        {
            var got = Verifier.LeafHash(H(v.GetProperty("input_hex").GetString()!));
            Assert.Equal(v.GetProperty("hash_hex").GetString(), ToHex(got));
        }
    }

    // ── Node hashes ───────────────────────────────────────────────────────────

    [Fact]
    public void NodeHashVectors()
    {
        foreach (var v in Load("node-hashes.json").EnumerateArray())
        {
            if (!v.TryGetProperty("hash_hex", out var expectedProp)) continue;
            var got = Verifier.NodeHash(
                H(v.GetProperty("left_hex").GetString()!),
                H(v.GetProperty("right_hex").GetString()!));
            Assert.Equal(expectedProp.GetString(), ToHex(got));
        }
    }

    [Fact]
    public void NodeHashNonCommutative()
    {
        foreach (var v in Load("node-hashes.json").EnumerateArray())
        {
            if (!v.TryGetProperty("swapped_hash_hex", out var swappedProp)) continue;
            var left = H(v.GetProperty("left_hex").GetString()!);
            var right = H(v.GetProperty("right_hex").GetString()!);
            var ab = Verifier.NodeHash(left, right);
            var ba = Verifier.NodeHash(right, left);
            Assert.NotEqual(ToHex(ab), ToHex(ba));
            Assert.Equal(swappedProp.GetString(), ToHex(ba));
        }
    }

    // ── Inclusion proofs ──────────────────────────────────────────────────────

    [Fact]
    public void InclusionProofVectors()
    {
        foreach (var v in Load("inclusion-proofs.json").EnumerateArray())
        {
            var ok = Verifier.VerifyInclusion(
                H(v.GetProperty("leaf_hash_hex").GetString()!),
                (ulong)v.GetProperty("leaf_index").GetInt64(),
                (ulong)v.GetProperty("tree_size").GetInt64(),
                Proofs(v.GetProperty("proof_hex")),
                H(v.GetProperty("root_hex").GetString()!));
            Assert.True(ok, $"size={v.GetProperty("tree_size")} idx={v.GetProperty("leaf_index")}");
        }
    }

    // ── Consistency proofs ────────────────────────────────────────────────────

    [Fact]
    public void ConsistencyProofVectors()
    {
        foreach (var v in Load("consistency-proofs.json").EnumerateArray())
        {
            var ok = Verifier.VerifyConsistency(
                (ulong)v.GetProperty("old_size").GetInt64(),
                (ulong)v.GetProperty("new_size").GetInt64(),
                Proofs(v.GetProperty("proof_hex")),
                H(v.GetProperty("old_root_hex").GetString()!),
                H(v.GetProperty("new_root_hex").GetString()!));
            Assert.True(ok, $"old={v.GetProperty("old_size")} new={v.GetProperty("new_size")}");
        }
    }

    // ── Signed Tree Heads ─────────────────────────────────────────────────────

    [Fact]
    public void SthVectors()
    {
        foreach (var v in Load("signed-tree-heads.json").EnumerateArray())
        {
            var treeSize = (ulong)v.GetProperty("tree_size").GetInt64();
            var rootHash = H(v.GetProperty("root_hash_hex").GetString()!);
            var ts = v.GetProperty("timestamp_ns").GetInt64();
            var sig = H(v.GetProperty("signature_hex").GetString()!);
            var pubKey = H(v.GetProperty("public_key_hex").GetString()!);
            Assert.True(Verifier.VerifyTreeHead(treeSize, rootHash, ts, sig, pubKey),
                v.GetProperty("description").GetString());
            Assert.False(Verifier.VerifyTreeHead(treeSize + 1, rootHash, ts, sig, pubKey),
                "tampered tree_size should fail");
        }
    }

    // ── Sequential STH verification ───────────────────────────────────────────

    [Fact]
    public void SthSequentialVectors()
    {
        var vectors = Load("signed-tree-heads.json").EnumerateArray().ToList();

        // Consecutive pairs must pass (timestamps are strictly increasing).
        for (var i = 0; i + 1 < vectors.Count; i++)
        {
            var prev = vectors[i];
            var curr = vectors[i + 1];
            var ok = Verifier.VerifyTreeHeadSequential(
                (ulong)curr.GetProperty("tree_size").GetInt64(),
                H(curr.GetProperty("root_hash_hex").GetString()!),
                curr.GetProperty("timestamp_ns").GetInt64(),
                H(curr.GetProperty("signature_hex").GetString()!),
                H(curr.GetProperty("public_key_hex").GetString()!),
                prev.GetProperty("timestamp_ns").GetInt64());
            Assert.True(ok, $"{curr.GetProperty("description")} after {prev.GetProperty("description")}");
        }

        // Equal timestamp must fail.
        var v = vectors[0];
        var ts = v.GetProperty("timestamp_ns").GetInt64();
        Assert.False(Verifier.VerifyTreeHeadSequential(
            (ulong)v.GetProperty("tree_size").GetInt64(),
            H(v.GetProperty("root_hash_hex").GetString()!),
            ts,
            H(v.GetProperty("signature_hex").GetString()!),
            H(v.GetProperty("public_key_hex").GetString()!),
            ts), "equal timestamp must fail");
    }

    // ── Negative cases ────────────────────────────────────────────────────────

    [Fact]
    public void NegativeCases()
    {
        foreach (var kv in Load("negative-cases.json").EnumerateObject())
        {
            var v = kv.Value;
            var expected = v.GetProperty("expected_result").GetBoolean();
            if (kv.Name.StartsWith("inclusion_"))
            {
                var got = Verifier.VerifyInclusion(
                    H(v.GetProperty("leaf_hash_hex").GetString()!),
                    (ulong)v.GetProperty("leaf_index").GetInt64(),
                    (ulong)v.GetProperty("tree_size").GetInt64(),
                    Proofs(v.GetProperty("proof_hex")),
                    H(v.GetProperty("root_hex").GetString()!));
                Assert.Equal(expected, got);
            }
            else if (kv.Name.StartsWith("consistency_"))
            {
                var got = Verifier.VerifyConsistency(
                    (ulong)v.GetProperty("old_size").GetInt64(),
                    (ulong)v.GetProperty("new_size").GetInt64(),
                    Proofs(v.GetProperty("proof_hex")),
                    H(v.GetProperty("old_root_hex").GetString()!),
                    H(v.GetProperty("new_root_hex").GetString()!));
                Assert.Equal(expected, got);
            }
            else if (kv.Name.StartsWith("tree_head_sequential_"))
            {
                var got = Verifier.VerifyTreeHeadSequential(
                    (ulong)v.GetProperty("tree_size").GetInt64(),
                    H(v.GetProperty("root_hash_hex").GetString()!),
                    v.GetProperty("timestamp_ns").GetInt64(),
                    H(v.GetProperty("signature_hex").GetString()!),
                    H(v.GetProperty("public_key_hex").GetString()!),
                    v.GetProperty("previous_timestamp_ns").GetInt64());
                Assert.Equal(expected, got);
            }
        }
    }

    private static string ToHex(byte[] bytes) =>
        BitConverter.ToString(bytes).Replace("-", "").ToLower();
}

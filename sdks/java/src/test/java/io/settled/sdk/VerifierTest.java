package io.settled.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Path VECTORS = Paths.get(System.getProperty("vectors.dir"));

    private static JsonNode load(String name) {
        try {
            return MAPPER.readTree(Files.readString(VECTORS.resolve(name)));
        } catch (IOException e) {
            throw new RuntimeException("Cannot read " + name, e);
        }
    }

    private static byte[] h(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        return out;
    }

    private static List<byte[]> proofs(JsonNode arr) {
        List<byte[]> list = new ArrayList<>();
        for (JsonNode n : arr) list.add(h(n.asText()));
        return list;
    }

    // ── Leaf hashes ───────────────────────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> leafHashVectors() {
        JsonNode vectors = load("leaf-hashes.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : vectors) {
            String desc = v.get("description").asText();
            byte[] input = h(v.get("input_hex").asText());
            String expected = v.get("hash_hex").asText();
            tests.add(DynamicTest.dynamicTest(desc, () -> {
                byte[] got = Verifier.leafHash(input);
                assertEquals(expected, toHex(got));
            }));
        }
        return tests;
    }

    // ── Node hashes ───────────────────────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> nodeHashVectors() {
        JsonNode vectors = load("node-hashes.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : vectors) {
            if (!v.has("hash_hex")) continue;
            String desc = v.get("description").asText();
            byte[] left = h(v.get("left_hex").asText());
            byte[] right = h(v.get("right_hex").asText());
            String expected = v.get("hash_hex").asText();
            tests.add(DynamicTest.dynamicTest(desc, () ->
                    assertEquals(expected, toHex(Verifier.nodeHash(left, right)))));
        }
        return tests;
    }

    @Test
    void nodeHashNonCommutative() {
        JsonNode vectors = load("node-hashes.json");
        for (JsonNode v : vectors) {
            if (!v.has("swapped_hash_hex")) continue;
            byte[] left = h(v.get("left_hex").asText());
            byte[] right = h(v.get("right_hex").asText());
            byte[] ab = Verifier.nodeHash(left, right);
            byte[] ba = Verifier.nodeHash(right, left);
            assertNotEquals(toHex(ab), toHex(ba));
            assertEquals(v.get("swapped_hash_hex").asText(), toHex(ba));
        }
    }

    // ── Inclusion proofs ──────────────────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> inclusionProofVectors() {
        JsonNode vectors = load("inclusion-proofs.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : vectors) {
            long treeSize = v.get("tree_size").asLong();
            long leafIndex = v.get("leaf_index").asLong();
            byte[] leafHash = h(v.get("leaf_hash_hex").asText());
            List<byte[]> proof = proofs(v.get("proof_hex"));
            byte[] root = h(v.get("root_hex").asText());
            String name = "size=" + treeSize + " idx=" + leafIndex;
            tests.add(DynamicTest.dynamicTest(name, () ->
                    assertTrue(Verifier.verifyInclusion(leafHash, leafIndex, treeSize, proof, root))));
        }
        return tests;
    }

    // ── Consistency proofs ────────────────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> consistencyProofVectors() {
        JsonNode vectors = load("consistency-proofs.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : vectors) {
            long oldSize = v.get("old_size").asLong();
            long newSize = v.get("new_size").asLong();
            List<byte[]> proof = proofs(v.get("proof_hex"));
            byte[] oldRoot = h(v.get("old_root_hex").asText());
            byte[] newRoot = h(v.get("new_root_hex").asText());
            String name = "old=" + oldSize + " new=" + newSize;
            tests.add(DynamicTest.dynamicTest(name, () ->
                    assertTrue(Verifier.verifyConsistency(oldSize, newSize, proof, oldRoot, newRoot))));
        }
        return tests;
    }

    // ── Signed Tree Heads ─────────────────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> sthVectors() {
        JsonNode vectors = load("signed-tree-heads.json");
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : vectors) {
            String desc = v.get("description").asText();
            long treeSize = v.get("tree_size").asLong();
            byte[] rootHash = h(v.get("root_hash_hex").asText());
            long timestampNs = v.get("timestamp_ns").asLong();
            byte[] sig = h(v.get("signature_hex").asText());
            byte[] pubKey = h(v.get("public_key_hex").asText());
            tests.add(DynamicTest.dynamicTest(desc, () ->
                    assertTrue(Verifier.verifyTreeHead(treeSize, rootHash, timestampNs, sig, pubKey))));
            tests.add(DynamicTest.dynamicTest(desc + " tampered tree_size fails", () -> {
                assertFalse(Verifier.verifyTreeHead(treeSize + 1, rootHash, timestampNs, sig, pubKey));
            }));
        }
        return tests;
    }

    // ── Sequential STH verification ───────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> sthSequentialVectors() {
        JsonNode vectors = load("signed-tree-heads.json");
        List<DynamicTest> tests = new ArrayList<>();
        List<JsonNode> list = new ArrayList<>();
        vectors.forEach(list::add);

        // Consecutive pairs must pass (timestamps are strictly increasing).
        for (int i = 0; i + 1 < list.size(); i++) {
            JsonNode prev = list.get(i);
            JsonNode curr = list.get(i + 1);
            String name = curr.get("description").asText() + " after " + prev.get("description").asText();
            long prevTs = prev.get("timestamp_ns").asLong();
            long treeSize = curr.get("tree_size").asLong();
            byte[] rootHash = h(curr.get("root_hash_hex").asText());
            long timestampNs = curr.get("timestamp_ns").asLong();
            byte[] sig = h(curr.get("signature_hex").asText());
            byte[] pubKey = h(curr.get("public_key_hex").asText());
            tests.add(DynamicTest.dynamicTest(name, () ->
                    assertTrue(Verifier.verifyTreeHeadSequential(treeSize, rootHash, timestampNs, sig, pubKey, prevTs))));
        }

        // Equal timestamp must fail.
        JsonNode v = list.get(0);
        long ts = v.get("timestamp_ns").asLong();
        long treeSize = v.get("tree_size").asLong();
        byte[] rootHash = h(v.get("root_hash_hex").asText());
        byte[] sig = h(v.get("signature_hex").asText());
        byte[] pubKey = h(v.get("public_key_hex").asText());
        tests.add(DynamicTest.dynamicTest("equal timestamp fails", () ->
                assertFalse(Verifier.verifyTreeHeadSequential(treeSize, rootHash, ts, sig, pubKey, ts))));

        return tests;
    }

    // ── Negative cases ────────────────────────────────────────────────────────

    @TestFactory
    Collection<DynamicTest> negativeCases() {
        JsonNode cases = load("negative-cases.json");
        List<DynamicTest> tests = new ArrayList<>();
        cases.fields().forEachRemaining(entry -> {
            String name = entry.getKey();
            JsonNode v = entry.getValue();
            boolean expected = v.get("expected_result").asBoolean();
            if (name.startsWith("inclusion_")) {
                byte[] leafHash = h(v.get("leaf_hash_hex").asText());
                long leafIndex = v.get("leaf_index").asLong();
                long treeSize = v.get("tree_size").asLong();
                List<byte[]> proof = proofs(v.get("proof_hex"));
                byte[] root = h(v.get("root_hex").asText());
                tests.add(DynamicTest.dynamicTest(name, () ->
                        assertEquals(expected, Verifier.verifyInclusion(leafHash, leafIndex, treeSize, proof, root))));
            } else if (name.startsWith("consistency_")) {
                long oldSize = v.get("old_size").asLong();
                long newSize = v.get("new_size").asLong();
                List<byte[]> proof = proofs(v.get("proof_hex"));
                byte[] oldRoot = h(v.get("old_root_hex").asText());
                byte[] newRoot = h(v.get("new_root_hex").asText());
                tests.add(DynamicTest.dynamicTest(name, () ->
                        assertEquals(expected, Verifier.verifyConsistency(oldSize, newSize, proof, oldRoot, newRoot))));
            } else if (name.startsWith("tree_head_sequential_")) {
                long treeSize = v.get("tree_size").asLong();
                byte[] rootHash = h(v.get("root_hash_hex").asText());
                long timestampNs = v.get("timestamp_ns").asLong();
                byte[] sig = h(v.get("signature_hex").asText());
                byte[] pubKey = h(v.get("public_key_hex").asText());
                long prevTs = v.get("previous_timestamp_ns").asLong();
                tests.add(DynamicTest.dynamicTest(name, () ->
                        assertEquals(expected, Verifier.verifyTreeHeadSequential(treeSize, rootHash, timestampNs, sig, pubKey, prevTs))));
            }
        });
        return tests;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}

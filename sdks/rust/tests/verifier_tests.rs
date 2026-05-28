use settled_sdk::verifier::{
    leaf_hash, node_hash, verify_consistency, verify_inclusion, verify_tree_head,
    verify_tree_head_sequential,
};
use std::path::PathBuf;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-vectors")
}

fn load_json(name: &str) -> Vec<u8> {
    std::fs::read(vectors_dir().join(name)).unwrap_or_else(|e| panic!("cannot read {name}: {e}"))
}

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|_| panic!("invalid hex: {s}"))
}

fn b32(s: &str) -> [u8; 32] {
    h(s).try_into().expect("expected 32 bytes")
}

fn proof(hexes: &[String]) -> Vec<[u8; 32]> {
    hexes.iter().map(|s| b32(s)).collect()
}

// ── Leaf hashes ───────────────────────────────────────────────────────────────

#[test]
fn test_leaf_hash() {
    #[derive(serde::Deserialize)]
    struct Vector {
        description: String,
        input_hex: String,
        hash_hex: String,
    }
    let vectors: Vec<Vector> = serde_json::from_slice(&load_json("leaf-hashes.json")).unwrap();
    for v in vectors {
        let got = leaf_hash(&h(&v.input_hex));
        assert_eq!(hex::encode(got), v.hash_hex, "{}", v.description);
    }
}

// ── Node hashes ───────────────────────────────────────────────────────────────

#[test]
fn test_node_hash() {
    #[derive(serde::Deserialize)]
    struct Vector {
        description: String,
        left_hex: String,
        right_hex: String,
        hash_hex: Option<String>,
        swapped_hash_hex: Option<String>,
    }
    let vectors: Vec<Vector> = serde_json::from_slice(&load_json("node-hashes.json")).unwrap();
    for v in vectors {
        let left = b32(&v.left_hex);
        let right = b32(&v.right_hex);
        if let Some(expected) = v.hash_hex {
            let got = node_hash(&left, &right);
            assert_eq!(hex::encode(got), expected, "{}", v.description);
        }
        if let Some(expected_swapped) = v.swapped_hash_hex {
            let ab = node_hash(&left, &right);
            let ba = node_hash(&right, &left);
            assert_ne!(ab, ba, "{} must not be commutative", v.description);
            assert_eq!(
                hex::encode(ba),
                expected_swapped,
                "{} swapped",
                v.description
            );
        }
    }
}

// ── Inclusion proofs ──────────────────────────────────────────────────────────

#[test]
fn test_verify_inclusion() {
    #[derive(serde::Deserialize)]
    struct Vector {
        tree_size: u64,
        leaf_index: u64,
        leaf_hash_hex: String,
        proof_hex: Vec<String>,
        root_hex: String,
    }
    let vectors: Vec<Vector> = serde_json::from_slice(&load_json("inclusion-proofs.json")).unwrap();
    for v in vectors {
        let ok = verify_inclusion(
            b32(&v.leaf_hash_hex),
            v.leaf_index,
            v.tree_size,
            &proof(&v.proof_hex),
            b32(&v.root_hex),
        );
        assert!(ok, "size={} idx={}", v.tree_size, v.leaf_index);
    }
}

// ── Consistency proofs ────────────────────────────────────────────────────────

#[test]
fn test_verify_consistency() {
    #[derive(serde::Deserialize)]
    struct Vector {
        old_size: u64,
        new_size: u64,
        old_root_hex: String,
        new_root_hex: String,
        proof_hex: Vec<String>,
    }
    let vectors: Vec<Vector> =
        serde_json::from_slice(&load_json("consistency-proofs.json")).unwrap();
    for v in vectors {
        let ok = verify_consistency(
            v.old_size,
            v.new_size,
            &proof(&v.proof_hex),
            b32(&v.old_root_hex),
            b32(&v.new_root_hex),
        );
        assert!(ok, "old={} new={}", v.old_size, v.new_size);
    }
}

// ── Signed Tree Heads ─────────────────────────────────────────────────────────

#[test]
fn test_verify_tree_head() {
    #[derive(serde::Deserialize)]
    struct Vector {
        description: String,
        tree_size: u64,
        root_hash_hex: String,
        timestamp_ns: i64,
        signature_hex: String,
        public_key_hex: String,
    }
    let vectors: Vec<Vector> =
        serde_json::from_slice(&load_json("signed-tree-heads.json")).unwrap();
    for v in vectors {
        assert!(
            verify_tree_head(
                v.tree_size,
                b32(&v.root_hash_hex),
                v.timestamp_ns,
                &h(&v.signature_hex),
                &h(&v.public_key_hex)
            ),
            "{}",
            v.description,
        );

        assert!(
            !verify_tree_head(
                v.tree_size + 1,
                b32(&v.root_hash_hex),
                v.timestamp_ns,
                &h(&v.signature_hex),
                &h(&v.public_key_hex)
            ),
            "{} tampered tree_size should fail",
            v.description,
        );

        let mut root = b32(&v.root_hash_hex);
        root[0] ^= 0xFF;
        assert!(
            !verify_tree_head(
                v.tree_size,
                root,
                v.timestamp_ns,
                &h(&v.signature_hex),
                &h(&v.public_key_hex)
            ),
            "{} tampered root should fail",
            v.description,
        );
    }
}

// ── Sequential STH verification ───────────────────────────────────────────────

#[test]
fn test_verify_tree_head_sequential() {
    #[derive(serde::Deserialize)]
    struct Vector {
        description: String,
        tree_size: u64,
        root_hash_hex: String,
        timestamp_ns: i64,
        signature_hex: String,
        public_key_hex: String,
    }
    let vectors: Vec<Vector> =
        serde_json::from_slice(&load_json("signed-tree-heads.json")).unwrap();

    // Consecutive pairs must pass sequential verification (timestamps are strictly increasing).
    for pair in vectors.windows(2) {
        let prev = &pair[0];
        let curr = &pair[1];
        assert!(
            verify_tree_head_sequential(
                curr.tree_size,
                b32(&curr.root_hash_hex),
                curr.timestamp_ns,
                &h(&curr.signature_hex),
                &h(&curr.public_key_hex),
                prev.timestamp_ns,
            ),
            "{} after {}",
            curr.description,
            prev.description,
        );
    }

    // Same STH with itself as previous must fail (equal timestamp).
    let v = &vectors[0];
    assert!(
        !verify_tree_head_sequential(
            v.tree_size,
            b32(&v.root_hash_hex),
            v.timestamp_ns,
            &h(&v.signature_hex),
            &h(&v.public_key_hex),
            v.timestamp_ns,
        ),
        "equal timestamp must fail",
    );
}

// ── Negative cases ────────────────────────────────────────────────────────────

#[test]
fn test_negative_cases() {
    use std::collections::HashMap;

    let cases: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&load_json("negative-cases.json")).unwrap();

    for (name, v) in &cases {
        let expected = v["expected_result"].as_bool().unwrap();

        if name.starts_with("inclusion_") {
            let got = verify_inclusion(
                b32(v["leaf_hash_hex"].as_str().unwrap()),
                v["leaf_index"].as_u64().unwrap(),
                v["tree_size"].as_u64().unwrap(),
                &v["proof_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| b32(s.as_str().unwrap()))
                    .collect::<Vec<_>>(),
                b32(v["root_hex"].as_str().unwrap()),
            );
            assert_eq!(got, expected, "{name}");
        } else if name.starts_with("consistency_") {
            let got = verify_consistency(
                v["old_size"].as_u64().unwrap(),
                v["new_size"].as_u64().unwrap(),
                &v["proof_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| b32(s.as_str().unwrap()))
                    .collect::<Vec<_>>(),
                b32(v["old_root_hex"].as_str().unwrap()),
                b32(v["new_root_hex"].as_str().unwrap()),
            );
            assert_eq!(got, expected, "{name}");
        } else if name.starts_with("tree_head_sequential_") {
            let got = verify_tree_head_sequential(
                v["tree_size"].as_u64().unwrap(),
                b32(v["root_hash_hex"].as_str().unwrap()),
                v["timestamp_ns"].as_i64().unwrap(),
                &h(v["signature_hex"].as_str().unwrap()),
                &h(v["public_key_hex"].as_str().unwrap()),
                v["previous_timestamp_ns"].as_i64().unwrap(),
            );
            assert_eq!(got, expected, "{name}");
        }
    }
}

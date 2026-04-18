//! Generates test-vectors/signed-tree-heads.json using the Rust settled-core
//! Ed25519 signing implementation.
//!
//! Uses a deterministic test key (seed = 32 zero bytes).
//! THIS KEY IS PUBLIC. Never use it in production.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use settled_core::{
    hash::leaf_hash,
    merkle::mth,
    sth::{sign_tree_head, signing_payload},
};

fn main() {
    let seed = [0u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let entry_data: Vec<Vec<u8>> = (0..8).map(|i| format!("entry-{i}").into_bytes()).collect();
    let leaf_hashes: Vec<[u8; 32]> = entry_data.iter().map(|d| leaf_hash(d)).collect();

    let cases: Vec<(u64, i64)> = vec![
        (1, 1_000_000_000),
        (4, 2_000_000_000),
        (8, 1_713_362_400_000_000_000),
    ];

    let vectors: Vec<Value> = cases
        .iter()
        .map(|&(tree_size, timestamp_ns)| {
            let lh = &leaf_hashes[..tree_size as usize];
            let root = mth(lh).expect("non-empty tree must have a root");
            let sig = sign_tree_head(&signing_key, tree_size, &root, timestamp_ns);
            let payload = signing_payload(tree_size, &root, timestamp_ns);

            json!({
                "description": format!("tree_size={tree_size}"),
                "note": "private_key_seed_hex is a PUBLIC TEST KEY. Never use in production.",
                "private_key_seed_hex": hex::encode(seed),
                "public_key_hex": hex::encode(verifying_key.as_bytes()),
                "tree_size": tree_size,
                "root_hash_hex": hex::encode(root),
                "timestamp_ns": timestamp_ns,
                "signing_payload_hex": hex::encode(payload),
                "signature_hex": hex::encode(sig.to_bytes()),
            })
        })
        .collect();

    let out_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/signed-tree-heads.json");

    let json_str = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    fs::write(&out_path, &json_str)
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", out_path.display()));

    println!("wrote {}", out_path.display());
    println!("{} vectors", vectors.len());
}

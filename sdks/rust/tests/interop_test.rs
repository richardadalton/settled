use settled_sdk::verifier::{leaf_hash, verify_inclusion, verify_tree_head};

#[derive(serde::Deserialize)]
struct InteropEntry {
    seq: u64,
    data_hex: String,
    leaf_hash_hex: String,
}

#[derive(serde::Deserialize)]
struct InteropSth {
    tree_size: u64,
    root_hash_hex: String,
    timestamp_ns: i64,
    signature_hex: String,
    public_key_hex: String,
}

#[derive(serde::Deserialize)]
struct InteropProof {
    seq: u64,
    leaf_hash_hex: String,
    proof_hex: Vec<String>,
}

#[derive(serde::Deserialize)]
struct InteropData {
    entries: Vec<InteropEntry>,
    sth: InteropSth,
    inclusion_proofs: Vec<InteropProof>,
}

fn b32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().expect("32 bytes")
}

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn interop_verify() {
    let path = match std::env::var("INTEROP_DATA") {
        Ok(p) => p,
        Err(_) => return, // skip when not set
    };

    let raw = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    let d: InteropData = serde_json::from_slice(&raw).expect("parse interop data");

    assert!(
        verify_tree_head(
            d.sth.tree_size,
            b32(&d.sth.root_hash_hex),
            d.sth.timestamp_ns,
            &hx(&d.sth.signature_hex),
            &hx(&d.sth.public_key_hex),
        ),
        "STH signature verification failed"
    );

    for ip in &d.inclusion_proofs {
        let proof: Vec<[u8; 32]> = ip.proof_hex.iter().map(|s| b32(s)).collect();
        assert!(
            verify_inclusion(
                b32(&ip.leaf_hash_hex),
                ip.seq,
                d.sth.tree_size,
                &proof,
                b32(&d.sth.root_hash_hex),
            ),
            "inclusion proof for seq {} failed",
            ip.seq
        );
    }

    for entry in &d.entries {
        let data = hex::decode(&entry.data_hex).unwrap();
        let got = leaf_hash(&data);
        let want = b32(&entry.leaf_hash_hex);
        assert_eq!(got, want, "leaf hash mismatch for seq {}", entry.seq);
    }
}

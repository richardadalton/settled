use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// The data committed to by an Ed25519 signature on a tree head.
/// Encoding: tree_size (u64 BE) || root_hash (32 bytes) || timestamp_ns (i64 BE)
/// Total: 48 bytes. See docs/wire-format.md §5.2.
pub fn signing_payload(tree_size: u64, root_hash: &[u8; 32], timestamp_ns: i64) -> [u8; 48] {
    let mut buf = [0u8; 48];
    buf[..8].copy_from_slice(&tree_size.to_be_bytes());
    buf[8..40].copy_from_slice(root_hash);
    buf[40..].copy_from_slice(&timestamp_ns.to_be_bytes());
    buf
}

pub fn sign_tree_head(
    key: &SigningKey,
    tree_size: u64,
    root_hash: &[u8; 32],
    timestamp_ns: i64,
) -> Signature {
    let payload = signing_payload(tree_size, root_hash, timestamp_ns);
    key.sign(&payload)
}

pub fn verify_tree_head(
    key: &VerifyingKey,
    tree_size: u64,
    root_hash: &[u8; 32],
    timestamp_ns: i64,
    signature: &Signature,
) -> bool {
    let payload = signing_payload(tree_size, root_hash, timestamp_ns);
    key.verify(&payload, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn load_vectors(name: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../test-vectors/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let data = fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}"));
        serde_json::from_str(&data).expect("invalid JSON")
    }

    #[test]
    fn sth_vectors() {
        let vectors = load_vectors("signed-tree-heads.json");
        for v in vectors.as_array().unwrap() {
            let seed: [u8; 32] = hex::decode(v["private_key_seed_hex"].as_str().unwrap())
                .unwrap().try_into().unwrap();
            let root: [u8; 32] = hex::decode(v["root_hash_hex"].as_str().unwrap())
                .unwrap().try_into().unwrap();
            let tree_size = v["tree_size"].as_u64().unwrap();
            let timestamp_ns = v["timestamp_ns"].as_i64().unwrap();
            let expected_sig: [u8; 64] = hex::decode(v["signature_hex"].as_str().unwrap())
                .unwrap().try_into().unwrap();

            let signing_key = SigningKey::from_bytes(&seed);
            let sig = sign_tree_head(&signing_key, tree_size, &root, timestamp_ns);
            assert_eq!(
                sig.to_bytes(),
                expected_sig,
                "signature mismatch for: {}",
                v["description"]
            );

            let verifying_key = signing_key.verifying_key();
            assert!(
                verify_tree_head(&verifying_key, tree_size, &root, timestamp_ns, &sig),
                "verify_tree_head failed for: {}",
                v["description"]
            );

            // Each field tampered individually must fail.
            assert!(
                !verify_tree_head(&verifying_key, tree_size + 1, &root, timestamp_ns, &sig),
                "tampered tree_size must fail"
            );
            let mut bad_root = root;
            bad_root[0] ^= 0xFF;
            assert!(
                !verify_tree_head(&verifying_key, tree_size, &bad_root, timestamp_ns, &sig),
                "tampered root_hash must fail"
            );
            assert!(
                !verify_tree_head(&verifying_key, tree_size, &root, timestamp_ns + 1, &sig),
                "tampered timestamp must fail"
            );
        }
    }

    #[test]
    fn wrong_key_fails() {
        let seed_a = [0u8; 32];
        let seed_b = [1u8; 32]; // different key
        let key_a = SigningKey::from_bytes(&seed_a);
        let key_b = SigningKey::from_bytes(&seed_b);
        let root = [0xABu8; 32];

        let sig = sign_tree_head(&key_a, 100, &root, 999_999_999);

        // Valid with key A
        assert!(verify_tree_head(&key_a.verifying_key(), 100, &root, 999_999_999, &sig));
        // Invalid with key B
        assert!(!verify_tree_head(&key_b.verifying_key(), 100, &root, 999_999_999, &sig));
    }
}

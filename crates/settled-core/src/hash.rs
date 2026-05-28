use sha2::{Digest, Sha256};

/// SHA-256(0x00 || data)
pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// SHA-256(0x01 || left || right)
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn load_vectors(name: &str) -> serde_json::Value {
        let path = format!("{}/../../test-vectors/{name}", env!("CARGO_MANIFEST_DIR"));
        let data = fs::read_to_string(&path).unwrap_or_else(|_| panic!("cannot read {path}"));
        serde_json::from_str(&data).expect("invalid JSON")
    }

    #[test]
    fn leaf_hash_vectors() {
        let vectors = load_vectors("leaf-hashes.json");
        for v in vectors.as_array().unwrap() {
            let input = hex::decode(v["input_hex"].as_str().unwrap()).unwrap();
            let expected = hex::decode(v["hash_hex"].as_str().unwrap()).unwrap();
            let got = leaf_hash(&input);
            assert_eq!(
                got.as_ref(),
                expected.as_slice(),
                "leaf_hash failed for: {}",
                v["description"]
            );
        }
    }

    #[test]
    fn node_hash_vectors() {
        let vectors = load_vectors("node-hashes.json");
        for v in vectors.as_array().unwrap() {
            if v.get("hash_hex").is_none() {
                continue;
            }
            let left: [u8; 32] = hex::decode(v["left_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let right: [u8; 32] = hex::decode(v["right_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let expected = hex::decode(v["hash_hex"].as_str().unwrap()).unwrap();
            let got = node_hash(&left, &right);
            assert_eq!(
                got.as_ref(),
                expected.as_slice(),
                "node_hash failed for: {}",
                v["description"]
            );
        }
    }

    #[test]
    fn node_hash_not_commutative() {
        let vectors = load_vectors("node-hashes.json");
        for v in vectors.as_array().unwrap() {
            if v.get("swapped_hash_hex").is_none() {
                continue;
            }
            let hash = hex::decode(v["hash_hex"].as_str().unwrap()).unwrap();
            let swapped = hex::decode(v["swapped_hash_hex"].as_str().unwrap()).unwrap();
            assert_ne!(hash, swapped, "node_hash must not be commutative");
        }
    }
}

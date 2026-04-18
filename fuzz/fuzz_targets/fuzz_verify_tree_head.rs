#![no_main]
// Fuzz target: verify_tree_head must never panic on arbitrary input.
//
// Input layout:
//   [0..32]  public_key  (32 bytes)
//   [32..40] tree_size   (u64 LE)
//   [40..72] root_hash   (32 bytes)
//   [72..80] timestamp   (i64 LE)
//   [80..144] signature  (64 bytes)
//
// An invalid public key or malformed signature must produce false, not a panic.

use libfuzzer_sys::fuzz_target;
use settled_core::sth::verify_tree_head;
use ed25519_dalek::{Signature, VerifyingKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 144 {
        return;
    }

    let pk_bytes: [u8; 32] = data[0..32].try_into().unwrap();
    let tree_size = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let root_hash: [u8; 32] = data[40..72].try_into().unwrap();
    let timestamp_ns = i64::from_le_bytes(data[72..80].try_into().unwrap());
    let sig_bytes: [u8; 64] = data[80..144].try_into().unwrap();

    // Invalid public key bytes are expected and must not panic.
    let Ok(key) = VerifyingKey::from_bytes(&pk_bytes) else { return };
    let sig = Signature::from_bytes(&sig_bytes);

    let _ = verify_tree_head(&key, tree_size, &root_hash, timestamp_ns, &sig);
});

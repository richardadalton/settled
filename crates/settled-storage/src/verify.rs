use ed25519_dalek::{Signature, VerifyingKey};
use settled_core::sth::signing_payload;

use crate::types::SignedTreeHead;

/// Verify the Ed25519 signature on a SignedTreeHead.
pub fn verify_sth(sth: &SignedTreeHead) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&sth.public_key) else { return false };
    let Ok(sig) = Signature::from_slice(&sth.signature) else { return false };
    let payload = signing_payload(sth.tree_size, &sth.root_hash, sth.timestamp_ns);
    key.verify_strict(&payload, &sig).is_ok()
}

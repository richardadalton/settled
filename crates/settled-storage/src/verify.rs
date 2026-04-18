use ed25519_dalek::{Signature, VerifyingKey};
use settled_core::sth::signing_payload;

use crate::types::{CounterSignature, FinalSTH, SignedTreeHead};

/// Verify the Ed25519 signature on a SignedTreeHead.
pub fn verify_sth(sth: &SignedTreeHead) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&sth.public_key) else { return false };
    let Ok(sig) = Signature::from_slice(&sth.signature) else { return false };
    let payload = signing_payload(sth.tree_size, &sth.root_hash, sth.timestamp_ns);
    key.verify_strict(&payload, &sig).is_ok()
}

/// Public helper used in tests across crates.
pub fn verify_counter_signature_pub(cs: &CounterSignature, sth: &SignedTreeHead) -> bool {
    verify_counter_signature(cs, sth)
}

fn verify_counter_signature(cs: &CounterSignature, sth: &SignedTreeHead) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(&cs.public_key) else { return false };
    let Ok(sig) = Signature::from_slice(&cs.signature) else { return false };
    let payload = signing_payload(sth.tree_size, &sth.root_hash, sth.timestamp_ns);
    key.verify_strict(&payload, &sig).is_ok()
}

/// Verify a FinalSTH.
///
/// Returns true iff:
/// 1. The main STH Ed25519 signature is valid.
/// 2. At least `threshold` counter-signatures are valid.
///
/// Pass `threshold = 0` to accept any STH without counter-signatures
/// (backwards-compatible default).
pub fn verify_final_sth(final_sth: &FinalSTH, threshold: usize) -> bool {
    if !verify_sth(&final_sth.sth) {
        return false;
    }

    if threshold == 0 {
        return true;
    }

    let valid = final_sth
        .counter_signatures
        .iter()
        .filter(|cs| verify_counter_signature(cs, &final_sth.sth))
        .count();

    valid >= threshold
}

#![no_main]
// Fuzz target: verify_inclusion must never panic on arbitrary input.
//
// The verifier is a public API that will receive proof data from untrusted
// sources (clients, network). A panic on malformed input is a DoS vulnerability.
//
// Input layout (all reads are bounds-checked; short inputs produce early returns):
//   [0..32]  leaf_hash
//   [32..40] leaf_index (u64 LE)
//   [40..48] tree_size  (u64 LE)
//   [48..]   proof elements, each 32 bytes; any trailing bytes are ignored

use libfuzzer_sys::fuzz_target;
use settled_core::proof::verify_inclusion;

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }

    let leaf_hash: [u8; 32] = data[0..32].try_into().unwrap();
    let leaf_index = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let tree_size = u64::from_le_bytes(data[40..48].try_into().unwrap());

    let proof_bytes = &data[48..];
    let n_elements = proof_bytes.len() / 32;
    let proof: Vec<[u8; 32]> = (0..n_elements)
        .map(|i| proof_bytes[i * 32..(i + 1) * 32].try_into().unwrap())
        .collect();

    // Must not panic. Return value (true/false) is irrelevant for fuzzing.
    let _ = verify_inclusion(&leaf_hash, leaf_index, tree_size, &proof, &[0u8; 32]);
});

#![no_main]
// Fuzz target: verify_consistency must never panic on arbitrary input.
//
// Input layout:
//   [0..8]   old_size (u64 LE)
//   [8..16]  new_size (u64 LE)
//   [16..48] old_root (32 bytes)
//   [48..80] new_root (32 bytes)
//   [80..]   proof elements, each 32 bytes

use libfuzzer_sys::fuzz_target;
use settled_core::proof::verify_consistency;

fuzz_target!(|data: &[u8]| {
    if data.len() < 80 {
        return;
    }

    let old_size = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let new_size = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let old_root: [u8; 32] = data[16..48].try_into().unwrap();
    let new_root: [u8; 32] = data[48..80].try_into().unwrap();

    let proof_bytes = &data[80..];
    let n_elements = proof_bytes.len() / 32;
    let proof: Vec<[u8; 32]> = (0..n_elements)
        .map(|i| proof_bytes[i * 32..(i + 1) * 32].try_into().unwrap())
        .collect();

    let _ = verify_consistency(old_size, new_size, &proof, &old_root, &new_root);
});

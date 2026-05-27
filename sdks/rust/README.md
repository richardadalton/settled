# settled-sdk (Rust)

Rust SDK for [Settled](https://github.com/richardadalton/settled), a tamper-evident audit log built on RFC 6962 Merkle trees.

Requires **Rust 1.70+** and a Tokio async runtime.

## Installation

```toml
[dependencies]
settled-sdk = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Usage

### Connecting to a Settled server

```rust
use settled_sdk::SettledClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut client = SettledClient::connect("http://localhost:50051").await?;

    // Append an entry
    let result = client.append(b"user:42".to_vec(), data).await?;
    println!("Assigned seq: {}", result.seq);

    // Retrieve by sequence number
    let entry = client.get(result.seq).await?;

    // Retrieve the N most-recent entries (newest first)
    let recent = client.get_latest(10).await?;

    // Get the current Signed Tree Head
    let sth = client.get_sth(0).await?; // 0 = latest

    // Request an inclusion proof
    let proof = client.inclusion_proof(result.seq, 0).await?; // 0 = latest STH

    // Request a consistency proof between two tree sizes
    let cp = client.consistency_proof(10, 0).await?; // 0 = latest STH

    Ok(())
}
```

### Verifying proofs locally

```rust
use settled_sdk::verifier;

fn to32(v: &[u8]) -> [u8; 32] { v.try_into().expect("hash must be 32 bytes") }
fn to_proof(vecs: &[Vec<u8>]) -> Vec<[u8; 32]> { vecs.iter().map(|v| to32(v)).collect() }

// Verify that an entry is included in the tree
let ok = verifier::verify_inclusion(
    to32(&result.leaf_hash),
    proof.leaf_index,
    proof.tree_size,
    &to_proof(&proof.proof),
    to32(&proof.sth.root_hash),
);

// Verify the old tree is a prefix of the new tree
let ok = verifier::verify_consistency(
    cp.old_size,
    cp.new_size,
    &to_proof(&cp.proof),
    to32(&cp.old_sth.root_hash),
    to32(&cp.new_sth.root_hash),
);

// Verify the Ed25519 signature on a Signed Tree Head
let ok = verifier::verify_tree_head(
    sth.tree_size,
    to32(&sth.root_hash),
    sth.timestamp_ns,
    &sth.signature,
    &sth.public_key,
);
```

## Further reading

- [Wire format specification](../../docs/wire-format.md) — hash constructions, proof algorithms, STH signing payload
- [Deployment guide](../../docs/deployment.md) — running the server with Docker

## License

[Elastic License 2.0](LICENSE)

# settled-sdk

Python SDK for [Settled](https://github.com/richardadalton/settled), a tamper-evident audit log built on RFC 6962 Merkle trees.

## Installation

```bash
pip install settled-sdk
```

## Usage

### Connecting to a Settled server

```python
from settled import SettledClient

client = SettledClient("localhost:50051")

# Append an entry
result = client.append(b"my audit event")

# Get the current Signed Tree Head
sth = client.get_sth()

# Verify inclusion
proof = client.inclusion_proof(result.leaf_index, sth.tree_size)
```

### Verifying proofs independently

```python
from settled import verify_inclusion, verify_consistency, verify_tree_head

# Verify that an entry is included in a tree
verify_inclusion(leaf_hash, leaf_index, tree_size, proof_hashes, root_hash)

# Verify consistency between two tree heads
verify_consistency(old_size, new_size, proof_hashes, old_root, new_root)

# Verify the signature on a Signed Tree Head
verify_tree_head(sth, public_key_bytes)
```

## License

[Elastic License 2.0](LICENSE)

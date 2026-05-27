# settled-sdk (Go)

Go SDK for [Settled](https://github.com/richardadalton/settled), a tamper-evident audit log built on RFC 6962 Merkle trees.

Requires **Go 1.22+**.

## Installation

```sh
go get github.com/richardadalton/settled/sdks/go@latest
```

## Usage

### Connecting to a Settled server

```go
import (
    "context"
    "github.com/richardadalton/settled/sdks/go/client"
)

c, err := client.New("localhost:50051")
if err != nil {
    log.Fatal(err)
}
defer c.Close()

ctx := context.Background()

// Append an entry
result, err := c.Append(ctx, []byte("user:42"), []byte(`{"action":"login"}`))

// Retrieve by sequence number
entry, err := c.Get(ctx, result.Seq)

// Retrieve the N most-recent entries (newest first)
recent, err := c.GetLatest(ctx, 10)

// Get the current Signed Tree Head
sth, err := c.GetSth(ctx, 0) // 0 = latest

// Request an inclusion proof
proof, err := c.InclusionProof(ctx, result.Seq, 0) // 0 = latest STH

// Request a consistency proof between two tree sizes
cp, err := c.ConsistencyProof(ctx, 10, 0) // 0 = latest STH
```

### Verifying proofs locally

Proofs from the client use `[][]byte`; the verifier uses `[][32]byte`. A small conversion is needed:

```go
import "github.com/richardadalton/settled/sdks/go/verifier"

func to32(b []byte) [32]byte { var a [32]byte; copy(a[:], b); return a }
func toProof(bs [][]byte) [][32]byte {
    out := make([][32]byte, len(bs))
    for i, b := range bs { out[i] = to32(b) }
    return out
}

// Verify that an entry is included in the tree
ok := verifier.VerifyInclusion(
    to32(result.LeafHash),
    proof.LeafIndex,
    proof.TreeSize,
    toProof(proof.Proof),
    to32(proof.Sth.RootHash),
)

// Verify the old tree is a prefix of the new tree
ok = verifier.VerifyConsistency(
    cp.OldSize, cp.NewSize,
    toProof(cp.Proof),
    to32(cp.OldSth.RootHash),
    to32(cp.NewSth.RootHash),
)

// Verify the Ed25519 signature on a Signed Tree Head
ok = verifier.VerifyTreeHead(
    sth.TreeSize,
    to32(sth.RootHash),
    sth.TimestampNs,
    sth.Signature,
    sth.PublicKey,
)
```

## Further reading

- [Wire format specification](../../docs/wire-format.md) — hash constructions, proof algorithms, STH signing payload
- [Deployment guide](../../docs/deployment.md) — running the server with Docker

## License

[Elastic License 2.0](LICENSE)

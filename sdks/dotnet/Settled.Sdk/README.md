# Settled.Sdk

C# SDK for [Settled](https://github.com/richardadalton/settled), a tamper-evident audit log built on RFC 6962 Merkle trees.

Requires **.NET 10+**.

## Installation

```
dotnet add package Settled.Sdk
```

## Usage

### Connecting to a Settled server

```csharp
using Settled.Sdk;

using var client = new SettledClient("http://localhost:50051");

// Append an entry
var result = await client.AppendAsync(key: Encoding.UTF8.GetBytes("user:42"), data: eventBytes);
Console.WriteLine($"Assigned seq: {result.Seq}");

// Retrieve by sequence number
var entry = await client.GetAsync(result.Seq);

// Retrieve the N most-recent entries (newest first)
var recent = await client.GetLatestAsync(n: 10);

// Get the current Signed Tree Head
var sth = await client.GetSthAsync();

// Request an inclusion proof
var ip = await client.InclusionProofAsync(seq: result.Seq, treeSize: sth.TreeSize);

// Request a consistency proof between two tree sizes
var cp = await client.ConsistencyProofAsync(oldSize: 10, newSize: sth.TreeSize);
```

### Verifying proofs locally

```csharp
using Settled.Sdk;

// Verify a leaf is included in the tree
bool ok = Verifier.VerifyInclusion(leafHash, leafIndex, treeSize, proof, rootHash);

// Verify the old tree is a prefix of the new tree
bool ok = Verifier.VerifyConsistency(oldSize, newSize, proof, oldRoot, newRoot);

// Verify the Ed25519 signature on a Signed Tree Head
bool ok = Verifier.VerifyTreeHead(treeSize, rootHash, timestampNs, signature, publicKey);
```

## License

[Elastic License 2.0](https://www.elastic.co/licensing/elastic-license)

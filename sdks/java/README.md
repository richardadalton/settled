# settled-sdk (Java)

Java SDK for [Settled](https://github.com/richardadalton/settled), a tamper-evident audit log built on RFC 6962 Merkle trees.

Requires **Java 17+**.

## Installation

**Gradle:**
```groovy
implementation 'io.github.richardadalton:settled-sdk:0.1.0'
```

**Maven:**
```xml
<dependency>
    <groupId>io.github.richardadalton</groupId>
    <artifactId>settled-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

### Connecting to a Settled server

```java
import io.settled.sdk.SettledClient;

try (var client = new SettledClient("localhost:50051")) {

    // Append an entry
    var result = client.append("user:42".getBytes(), data);
    System.out.println("Assigned seq: " + result.seq());

    // Retrieve by sequence number
    var entry = client.get(result.seq());

    // Get the current Signed Tree Head
    var sth = client.getSth(0); // 0 = latest

    // Request an inclusion proof
    var proof = client.inclusionProof(result.seq(), 0); // 0 = latest STH

    // Request a consistency proof between two tree sizes
    var cp = client.consistencyProof(10, 0); // 0 = latest STH
}
```

### Verifying proofs locally

```java
import io.settled.sdk.Verifier;

// Verify that an entry is included in the tree
boolean ok = Verifier.verifyInclusion(
    result.leafHash(),
    proof.leafIndex(),
    proof.treeSize(),
    proof.proof(),
    proof.sth().rootHash()
);

// Verify the old tree is a prefix of the new tree
boolean ok = Verifier.verifyConsistency(
    cp.oldSize(), cp.newSize(),
    cp.proof(),
    cp.oldSth().rootHash(),
    cp.newSth().rootHash()
);

// Verify the Ed25519 signature on a Signed Tree Head
boolean ok = Verifier.verifyTreeHead(
    sth.treeSize(),
    sth.rootHash(),
    sth.timestampNs(),
    sth.signature(),
    sth.publicKey()
);
```

## Further reading

- [Wire format specification](../../docs/wire-format.md) — hash constructions, proof algorithms, STH signing payload
- [Deployment guide](../../docs/deployment.md) — running the server with Docker

## License

[Elastic License 2.0](LICENSE)

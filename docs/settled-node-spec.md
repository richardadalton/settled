# Settled Node — Specification

## Overview

A **settled node** is an independent witness that actively monitors the audit log
server and counter-signs each new Signed Tree Head (STH) as it is published.
It provides a stronger trust guarantee than point-in-time verification: multiple
independent parties are watching in real time and must agree before a tree head
is considered final.

This is distinct from the base audit trail capability, where the server produces
a cryptographic proof that can be verified offline by anyone holding the public
key — for example, a proof emailed to a regulator. That base capability requires
no live witnesses.

## Role

- The server periodically produces an STH over the current Merkle tree root.
- After signing, the server pushes the STH to all registered settled nodes.
- Each node independently verifies the server's signature, then counter-signs the
  same 48-byte payload with its own Ed25519 key.
- The counter-signature is returned to the server and stored alongside the STH as
  a `FinalSTH`.
- A **threshold** can be configured on the server: a `FinalSTH` is only considered
  valid if it carries at least *N* valid counter-signatures.

## Trust model

- Each node has its own Ed25519 key pair. The public key is the node's identity.
- Counter-signatures are over the same signing payload as the main STH:
  `tree_size || root_hash || timestamp_ns`.
- A third party can verify a `FinalSTH` by checking the main signature and each
  counter-signature independently, without trusting the server.
- Future: nodes could be queried directly (`GET /archive/:tree_size`) to confirm
  what they signed, without relying on the server's account. This would require
  persisting counter-signatures on the node side (currently in-memory only).

## Wire API (HTTP)

### `POST /push`

Called by the server after each new STH is signed.

**Request body**
```json
{
  "tree_size":    42,
  "root_hash":    "<hex 32 bytes>",
  "timestamp_ns": 1700000000000000000,
  "signature":    "<hex 64 bytes>",
  "public_key":   "<hex 32 bytes>",
  "key_version":  1
}
```

**Response**
```json
{
  "counter_signature": "<hex 64 bytes>",
  "public_key":        "<hex 32 bytes>"
}
```

The node verifies the server's signature before signing. Returns `400` if the
signature is invalid.

### `GET /archive/:tree_size`

Returns the STH the node received and archived for the given tree size.
Currently in-memory only — lost on restart.

**Response**
```json
{
  "tree_size":    42,
  "root_hash":    "<hex 32 bytes>",
  "timestamp_ns": 1700000000000000000,
  "signature":    "<hex 64 bytes>",
  "public_key":   "<hex 32 bytes>",
  "key_version":  1
}
```

## Server-side storage

Counter-signatures are stored by the server as `FinalSTH` records (keyed by
`tree_size`) in the `final_heads` RocksDB column family. Each record contains
the full STH plus all counter-signatures collected from registered nodes.

### `CounterSignature`
| Field              | Type        |
|--------------------|-------------|
| `settled_node_url` | `String`    |
| `public_key`       | `[u8; 32]`  |
| `signature`        | `[u8; 64]`  |

### `FinalSTH`
| Field                | Type                    |
|----------------------|-------------------------|
| `sth`                | `SignedTreeHead`        |
| `counter_signatures` | `Vec<CounterSignature>` |

## Server-side registration (admin API)

Nodes are registered via the admin HTTP API:

| Method   | Path                          | Description                      |
|----------|-------------------------------|----------------------------------|
| `POST`   | `/v1/admin/settledes`         | Register a node by URL           |
| `GET`    | `/v1/admin/settledes`         | List registered nodes            |
| `DELETE` | `/v1/admin/settledes/:url`    | Remove a node                    |

### `SettledRecord`
| Field                  | Type              | Notes                                    |
|------------------------|-------------------|------------------------------------------|
| `url`                  | `String`          | Base URL of the node                     |
| `public_key`           | `Option<[u8;32]>` | Learned from the first push response     |
| `consecutive_failures` | `u32`             | Reset to 0 on any success                |
| `flagged_dead`         | `bool`            | Set when failures exceed `max_push_failures` |
| `registered_at_ns`     | `i64`             | Unix timestamp (ns) of registration      |

## Server configuration

| Flag                  | Default | Description                                           |
|-----------------------|---------|-------------------------------------------------------|
| `--threshold`         | `0`     | Minimum valid counter-sigs for a FinalSTH (0 = off)  |
| `--max-push-failures` | `6`     | Consecutive failures before a node is flagged dead   |
| `--push-timeout-ms`   | `5000`  | Per-attempt HTTP timeout when pushing to a node      |

## Node configuration

| Flag          | Default          | Description                                    |
|---------------|------------------|------------------------------------------------|
| `--listen`    | `0.0.0.0:8181`   | HTTP listen address                            |
| `--key-path`  | (required)       | Path to Ed25519 signing key (generated if absent) |

## Push retry behaviour

The server retries each push up to 4 attempts with exponential back-off starting
at 1 s. Push failures never block the main gRPC path — the push is fire-and-forget.
After `max_push_failures` consecutive failures the node is flagged dead and
excluded from future pushes until manually re-enabled.

## Outstanding work / future direction

- **Persistent node archive**: nodes currently store the STH archive in memory
  only. For true independence, nodes should persist their own record of what they
  counter-signed so they can be queried without relying on the server.
- **Direct node verification**: a client verification library could query nodes
  directly to cross-check `FinalSTH` records held by the server.
- **Node liveness endpoint**: a `/health` endpoint on the node to support
  load-balancer or monitoring probes.
- **Key rotation**: the node has no key-rotation mechanism. The server stores the
  public key observed in the first push response; a key change would require
  re-registration.

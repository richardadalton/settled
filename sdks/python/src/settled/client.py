"""
gRPC client for the Settled audit log server.
Proto stubs are regenerated via:
  ./scripts/gen-proto.sh
(which copies proto/settled.v1.proto to a dot-free temp filename so
protoc emits settled_v1_pb2.py rather than settled/v1_pb2.py).
"""
from __future__ import annotations

import grpc

from dataclasses import dataclass
from typing import AsyncIterator, Iterator


@dataclass
class AppendResult:
    seq: int
    timestamp_ns: int
    leaf_hash: bytes


@dataclass
class Entry:
    seq: int
    timestamp_ns: int
    key: bytes
    data: bytes
    leaf_hash: bytes


@dataclass
class SignedTreeHead:
    tree_size: int
    root_hash: bytes
    timestamp_ns: int
    signature: bytes
    public_key: bytes
    key_version: int


@dataclass
class InclusionProofResult:
    leaf_index: int
    tree_size: int
    proof: list[bytes]
    sth: SignedTreeHead


@dataclass
class ConsistencyProofResult:
    old_size: int
    new_size: int
    proof: list[bytes]
    old_sth: SignedTreeHead
    new_sth: SignedTreeHead


def _sth(raw) -> SignedTreeHead:
    return SignedTreeHead(
        tree_size=raw.tree_size,
        root_hash=bytes(raw.root_hash),
        timestamp_ns=raw.timestamp_ns,
        signature=bytes(raw.signature),
        public_key=bytes(raw.public_key),
        key_version=raw.key_version,
    )


class SettledClient:
    """Synchronous gRPC client for SettledLog."""

    def __init__(self, address: str) -> None:
        self._channel = grpc.insecure_channel(address)
        # Import generated stubs at runtime so the package is importable
        # even before codegen has been run (e.g. during verifier-only tests).
        from settled.proto import settled_v1_pb2_grpc  # type: ignore[import]
        self._stub = settled_v1_pb2_grpc.SettledLogStub(self._channel)

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> SettledClient:
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def append(self, key: bytes, data: bytes) -> AppendResult:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.Append(settled_v1_pb2.AppendRequest(key=key, data=data))
        return AppendResult(
            seq=res.seq,
            timestamp_ns=res.timestamp_ns,
            leaf_hash=bytes(res.leaf_hash),
        )

    def get(self, seq: int) -> Entry:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.Get(settled_v1_pb2.GetRequest(seq=seq))
        e = res.entry
        return Entry(
            seq=e.seq,
            timestamp_ns=e.timestamp_ns,
            key=bytes(e.key),
            data=bytes(e.data),
            leaf_hash=bytes(e.leaf_hash),
        )

    def get_latest(self, n: int = 1) -> list[Entry]:
        """Return the most-recent ``n`` entries (newest first).

        ``n == 0`` is treated as 1 by the server. Values above the
        server cap (currently 1000) are silently clamped. Returns an
        empty list if the log has no entries yet.
        """
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.GetLatest(settled_v1_pb2.GetLatestRequest(n=n))
        return [
            Entry(
                seq=e.seq,
                timestamp_ns=e.timestamp_ns,
                key=bytes(e.key),
                data=bytes(e.data),
                leaf_hash=bytes(e.leaf_hash),
            )
            for e in res.entries
        ]

    def get_sth(self, tree_size: int = 0) -> SignedTreeHead:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.GetSth(settled_v1_pb2.GetSthRequest(tree_size=tree_size))
        return _sth(res.sth)

    def inclusion_proof(self, seq: int, tree_size: int = 0) -> InclusionProofResult:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.InclusionProof(
            settled_v1_pb2.InclusionProofRequest(seq=seq, tree_size=tree_size)
        )
        return InclusionProofResult(
            leaf_index=res.leaf_index,
            tree_size=res.tree_size,
            proof=list(res.proof),
            sth=_sth(res.sth),
        )

    def consistency_proof(self, old_size: int, new_size: int = 0) -> ConsistencyProofResult:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.ConsistencyProof(
            settled_v1_pb2.ConsistencyProofRequest(old_size=old_size, new_size=new_size)
        )
        return ConsistencyProofResult(
            old_size=res.old_size,
            new_size=res.new_size,
            proof=list(res.proof),
            old_sth=_sth(res.old_sth),
            new_sth=_sth(res.new_sth),
        )

    def append_stream(
        self,
        entries: Iterator[tuple[bytes, bytes]],
        batch_size: int = 100,
    ) -> Iterator[AppendResult]:
        """Append entries in batches, yielding results in order."""
        batch: list[tuple[bytes, bytes]] = []
        for key, data in entries:
            batch.append((key, data))
            if len(batch) >= batch_size:
                yield from (self.append(k, d) for k, d in batch)
                batch = []
        yield from (self.append(k, d) for k, d in batch)

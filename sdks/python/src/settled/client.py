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
from typing import AsyncIterator, Iterator, Generator


@dataclass
class AppendResult:
    seq: int
    timestamp_ns: int
    leaf_hash: bytes
    key: bytes


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
class GetLatestResult:
    entries: list[Entry]
    total_available: int  # total entries in the log; > len(entries) means capped


@dataclass
class GetByKeyResult:
    entries: list[Entry]
    next_cursor: int  # 0 = no more pages


@dataclass
class ListEntriesResult:
    entries: list[Entry]
    next_cursor: int  # 0 = no more pages


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

    def __init__(self, address: str, api_key: str | None = None) -> None:
        self._channel = grpc.insecure_channel(address)
        # Import generated stubs at runtime so the package is importable
        # even before codegen has been run (e.g. during verifier-only tests).
        from settled.proto import settled_v1_pb2_grpc  # type: ignore[import]
        self._stub = settled_v1_pb2_grpc.SettledLogStub(self._channel)
        self._metadata = [("authorization", f"Bearer {api_key}")] if api_key else []

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> SettledClient:
        return self

    def __exit__(self, *_) -> None:
        self.close()

    def append(self, key: bytes, data: bytes) -> AppendResult:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.Append(settled_v1_pb2.AppendRequest(key=key, data=data), metadata=self._metadata)
        return AppendResult(
            seq=res.seq,
            timestamp_ns=res.timestamp_ns,
            leaf_hash=bytes(res.leaf_hash),
            key=bytes(res.key),
        )

    def get(self, seq: int) -> Entry:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.Get(settled_v1_pb2.GetRequest(seq=seq), metadata=self._metadata)
        e = res.entry
        return Entry(
            seq=e.seq,
            timestamp_ns=e.timestamp_ns,
            key=bytes(e.key),
            data=bytes(e.data),
            leaf_hash=bytes(e.leaf_hash),
        )

    def get_latest(self, n: int = 1) -> GetLatestResult:
        """Return the most-recent ``n`` entries (newest first).

        ``n == 0`` is treated as 1 by the server. Values above the server cap
        (1000) are silently clamped. Check ``total_available`` to detect
        truncation; use ``list_entries`` to page through older entries.
        """
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.GetLatest(settled_v1_pb2.GetLatestRequest(n=n), metadata=self._metadata)
        return GetLatestResult(
            entries=[
                Entry(
                    seq=e.seq,
                    timestamp_ns=e.timestamp_ns,
                    key=bytes(e.key),
                    data=bytes(e.data),
                    leaf_hash=bytes(e.leaf_hash),
                )
                for e in res.entries
            ],
            total_available=res.total_available,
        )

    def watch_entries(self, from_seq: int = 0) -> Generator[Entry, None, None]:
        """Stream entries via a server-side Watch RPC.

        ``from_seq > 0``: replays entries starting at that seq, then streams
        live ones.  ``from_seq == 0`` (default): yields only entries appended
        after the call is made.

        The generator blocks on each ``next()`` call until an entry arrives or
        the stream ends. Cancel by calling ``.close()`` on the generator.
        """
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        for e in self._stub.Watch(
            settled_v1_pb2.WatchRequest(from_seq=from_seq),
            metadata=self._metadata,
        ):
            yield Entry(
                seq=e.seq,
                timestamp_ns=e.timestamp_ns,
                key=bytes(e.key),
                data=bytes(e.data),
                leaf_hash=bytes(e.leaf_hash),
            )

    def batch_append(self, entries: list[tuple[bytes, bytes]]) -> list[AppendResult]:
        """Append multiple entries atomically.

        Seqs are assigned contiguously and written to the WAL in a single
        batch.  Capped at 1000 entries per call.  Returns one
        :class:`AppendResult` per entry in the same order.
        """
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        pb_entries = [
            settled_v1_pb2.AppendRequest(key=k, data=d) for k, d in entries
        ]
        res = self._stub.BatchAppend(
            settled_v1_pb2.BatchAppendRequest(entries=pb_entries),
            metadata=self._metadata,
        )
        return [
            AppendResult(
                seq=r.seq,
                timestamp_ns=r.timestamp_ns,
                leaf_hash=bytes(r.leaf_hash),
                key=bytes(r.key),
            )
            for r in res.entries
        ]

    def get_by_key(
        self,
        key: bytes,
        cursor: int = 0,
        limit: int = 0,
    ) -> GetByKeyResult:
        """Return all entries for an exact key match, with cursor-based pagination.

        ``cursor = 0`` starts from the beginning of the log. Pass
        ``next_cursor`` from the previous response to continue.
        ``limit = 0`` uses the server default (50); values above 1000 are clamped.
        ``next_cursor == 0`` in the response means no further pages.
        """
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.GetByKey(
            settled_v1_pb2.GetByKeyRequest(key=key, cursor=cursor, limit=limit),
            metadata=self._metadata,
        )
        return GetByKeyResult(
            entries=[
                Entry(
                    seq=e.seq,
                    timestamp_ns=e.timestamp_ns,
                    key=bytes(e.key),
                    data=bytes(e.data),
                    leaf_hash=bytes(e.leaf_hash),
                )
                for e in res.entries
            ],
            next_cursor=res.next_cursor,
        )

    def list_entries(
        self,
        from_seq: int = 0,
        to_seq: int = 0,
        cursor: int = 0,
        limit: int = 0,
    ) -> ListEntriesResult:
        """Return a page of entries in seq order within [from_seq, to_seq).

        ``to_seq = 0`` scans to the end of the log. Pass ``cursor = 0`` to
        start from ``from_seq``; pass ``next_cursor`` from the previous
        response to continue pagination. ``limit = 0`` uses the server default
        (50); values above 1000 are clamped.
        """
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.ListEntries(
            settled_v1_pb2.ListEntriesRequest(
                from_seq=from_seq, to_seq=to_seq, cursor=cursor, limit=limit
            ),
            metadata=self._metadata,
        )
        return ListEntriesResult(
            entries=[
                Entry(
                    seq=e.seq,
                    timestamp_ns=e.timestamp_ns,
                    key=bytes(e.key),
                    data=bytes(e.data),
                    leaf_hash=bytes(e.leaf_hash),
                )
                for e in res.entries
            ],
            next_cursor=res.next_cursor,
        )

    def get_sth(self, tree_size: int = 0) -> SignedTreeHead:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.GetSth(settled_v1_pb2.GetSthRequest(tree_size=tree_size), metadata=self._metadata)
        return _sth(res.sth)

    def inclusion_proof(self, seq: int, tree_size: int = 0) -> InclusionProofResult:
        from settled.proto import settled_v1_pb2  # type: ignore[import]
        res = self._stub.InclusionProof(
            settled_v1_pb2.InclusionProofRequest(seq=seq, tree_size=tree_size),
            metadata=self._metadata,
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
            settled_v1_pb2.ConsistencyProofRequest(old_size=old_size, new_size=new_size),
            metadata=self._metadata,
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

package io.settled.sdk;

import com.google.protobuf.ByteString;
import io.grpc.CallCredentials;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import settled.v1.SettledLogGrpc;
import settled.v1.SettledV1;
import settled.v1.SettledV1.*;

import io.grpc.stub.StreamObserver;
import java.io.Closeable;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

/**
 * Blocking gRPC client for the Settled audit-log server.
 */
public final class SettledClient implements Closeable {

    private final ManagedChannel channel;
    private final SettledLogGrpc.SettledLogBlockingStub stub;

    public SettledClient(String host) {
        this(host, null);
    }

    public SettledClient(String host, String apiKey) {
        this.channel = ManagedChannelBuilder.forTarget(host).usePlaintext().build();
        SettledLogGrpc.SettledLogBlockingStub s = SettledLogGrpc.newBlockingStub(channel);
        this.stub = apiKey != null ? s.withCallCredentials(new ApiKeyCredentials(apiKey)) : s;
    }

    private static final class ApiKeyCredentials extends CallCredentials {
        private static final Metadata.Key<String> AUTH_KEY =
                Metadata.Key.of("authorization", Metadata.ASCII_STRING_MARSHALLER);
        private final String bearer;

        ApiKeyCredentials(String apiKey) {
            this.bearer = "Bearer " + apiKey;
        }

        @Override
        public void applyRequestMetadata(RequestInfo ri, Executor ex, MetadataApplier applier) {
            ex.execute(() -> {
                Metadata headers = new Metadata();
                headers.put(AUTH_KEY, bearer);
                applier.apply(headers);
            });
        }
    }

    @Override
    public void close() {
        try {
            channel.shutdown().awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            channel.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // ── Data types ────────────────────────────────────────────────────────────

    public record AppendResult(long seq, long timestampNs, byte[] leafHash, byte[] key) {}

    public record Entry(long seq, long timestampNs, byte[] key, byte[] data, byte[] leafHash) {}

    public record Sth(
            long treeSize, byte[] rootHash, long timestampNs,
            byte[] signature, byte[] publicKey, int keyVersion) {}

    /** @param totalAvailable total entries in the log; greater than entries.size() means capped */
    public record GetLatestResult(List<Entry> entries, long totalAvailable) {}

    public record InclusionProofResult(
            long leafIndex, long treeSize, List<byte[]> proof, Sth sth) {}

    /** @param nextCursor pass as cursor in the next call; 0 = no more pages */
    public record ListEntriesResult(
            List<Entry> entries, long nextCursor) {}

    public record ConsistencyProofResult(
            long oldSize, long newSize, List<byte[]> proof,
            Sth oldSth, Sth newSth) {}

    // ── API ───────────────────────────────────────────────────────────────────

    /**
     * Stream entries via a server-side Watch RPC (async stub).
     * fromSeq &gt; 0 replays history from that seq then continues live.
     * fromSeq == 0 streams only entries appended after the call.
     * Results are delivered to {@code observer.onNext}; the stream ends via
     * {@code observer.onCompleted} or {@code observer.onError}.
     */
    public void watchEntries(long fromSeq, StreamObserver<Entry> observer) {
        SettledLogGrpc.newStub(channel).watch(
                WatchRequest.newBuilder().setFromSeq(fromSeq).build(),
                new io.grpc.stub.StreamObserver<SettledV1.Entry>() {
                    @Override public void onNext(SettledV1.Entry e) {
                        observer.onNext(new Entry(
                                e.getSeq(), e.getTimestampNs(),
                                e.getKey().toByteArray(), e.getData().toByteArray(),
                                e.getLeafHash().toByteArray()));
                    }
                    @Override public void onError(Throwable t) { observer.onError(t); }
                    @Override public void onCompleted() { observer.onCompleted(); }
                });
    }

    public AppendResult append(byte[] key, byte[] data) {
        AppendResponse r = stub.append(
                AppendRequest.newBuilder()
                        .setKey(ByteString.copyFrom(key))
                        .setData(ByteString.copyFrom(data))
                        .build());
        return new AppendResult(r.getSeq(), r.getTimestampNs(), r.getLeafHash().toByteArray(), r.getKey().toByteArray());
    }

    /**
     * Return the most-recent n entries (newest first). n=0 is treated as 1 by
     * the server. Values above the server cap (1000) are silently clamped;
     * check totalAvailable to detect truncation.
     */
    public GetLatestResult getLatest(int n) {
        GetLatestResponse r = stub.getLatest(GetLatestRequest.newBuilder().setN(n).build());
        List<Entry> entries = r.getEntriesList().stream()
                .map(e -> new Entry(e.getSeq(), e.getTimestampNs(),
                        e.getKey().toByteArray(), e.getData().toByteArray(),
                        e.getLeafHash().toByteArray()))
                .toList();
        return new GetLatestResult(entries, r.getTotalAvailable());
    }

    public Entry get(long seq) {
        GetResponse r = stub.get(GetRequest.newBuilder().setSeq(seq).build());
        SettledV1.Entry e = r.getEntry();
        return new Entry(e.getSeq(), e.getTimestampNs(),
                e.getKey().toByteArray(), e.getData().toByteArray(), e.getLeafHash().toByteArray());
    }

    /**
     * Return a seq-ordered page of entries within [fromSeq, toSeq).
     * toSeq == 0 scans to the end of the log. cursor == 0 starts from fromSeq;
     * pass nextCursor from the previous response to continue pagination.
     * limit == 0 uses the server default (50); values above 1000 are clamped.
     */
    public ListEntriesResult listEntries(long fromSeq, long toSeq, long cursor, int limit) {
        ListEntriesResponse r = stub.listEntries(
                ListEntriesRequest.newBuilder()
                        .setFromSeq(fromSeq)
                        .setToSeq(toSeq)
                        .setCursor(cursor)
                        .setLimit(limit)
                        .build());
        List<Entry> entries = r.getEntriesList().stream()
                .map(e -> new Entry(e.getSeq(), e.getTimestampNs(),
                        e.getKey().toByteArray(), e.getData().toByteArray(),
                        e.getLeafHash().toByteArray()))
                .toList();
        return new ListEntriesResult(entries, r.getNextCursor());
    }

    /** Pass treeSize == 0 to get the latest STH. */
    public Sth getSth(long treeSize) {
        GetSthResponse r = stub.getSth(GetSthRequest.newBuilder().setTreeSize(treeSize).build());
        return fromPb(r.getSth());
    }

    /** Pass treeSize == 0 to use the latest STH. */
    public InclusionProofResult inclusionProof(long seq, long treeSize) {
        InclusionProofResponse r = stub.inclusionProof(
                InclusionProofRequest.newBuilder().setSeq(seq).setTreeSize(treeSize).build());
        return new InclusionProofResult(
                r.getLeafIndex(), r.getTreeSize(),
                r.getProofList().stream().map(ByteString::toByteArray).toList(),
                fromPb(r.getSth()));
    }

    /** Pass newSize == 0 to use the latest STH. */
    public ConsistencyProofResult consistencyProof(long oldSize, long newSize) {
        ConsistencyProofResponse r = stub.consistencyProof(
                ConsistencyProofRequest.newBuilder().setOldSize(oldSize).setNewSize(newSize).build());
        return new ConsistencyProofResult(
                r.getOldSize(), r.getNewSize(),
                r.getProofList().stream().map(ByteString::toByteArray).toList(),
                fromPb(r.getOldSth()), fromPb(r.getNewSth()));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Sth fromPb(SettledV1.SignedTreeHead s) {
        return new Sth(
                s.getTreeSize(), s.getRootHash().toByteArray(), s.getTimestampNs(),
                s.getSignature().toByteArray(), s.getPublicKey().toByteArray(), s.getKeyVersion());
    }
}

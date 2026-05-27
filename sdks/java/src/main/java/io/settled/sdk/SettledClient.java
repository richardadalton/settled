package io.settled.sdk;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import settled.v1.SettledLogGrpc;
import settled.v1.SettledV1;
import settled.v1.SettledV1.*;

import java.io.Closeable;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Blocking gRPC client for the Settled audit-log server.
 */
public final class SettledClient implements Closeable {

    private final ManagedChannel channel;
    private final SettledLogGrpc.SettledLogBlockingStub stub;

    public SettledClient(String host) {
        this.channel = ManagedChannelBuilder.forTarget(host)
                .usePlaintext()
                .build();
        this.stub = SettledLogGrpc.newBlockingStub(channel);
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

    public record AppendResult(long seq, long timestampNs, byte[] leafHash) {}

    public record Entry(long seq, long timestampNs, byte[] key, byte[] data, byte[] leafHash) {}

    public record Sth(
            long treeSize, byte[] rootHash, long timestampNs,
            byte[] signature, byte[] publicKey, int keyVersion) {}

    public record InclusionProofResult(
            long leafIndex, long treeSize, List<byte[]> proof, Sth sth) {}

    public record ConsistencyProofResult(
            long oldSize, long newSize, List<byte[]> proof,
            Sth oldSth, Sth newSth) {}

    // ── API ───────────────────────────────────────────────────────────────────

    public AppendResult append(byte[] key, byte[] data) {
        AppendResponse r = stub.append(
                AppendRequest.newBuilder()
                        .setKey(ByteString.copyFrom(key))
                        .setData(ByteString.copyFrom(data))
                        .build());
        return new AppendResult(r.getSeq(), r.getTimestampNs(), r.getLeafHash().toByteArray());
    }

    public Entry get(long seq) {
        GetResponse r = stub.get(GetRequest.newBuilder().setSeq(seq).build());
        SettledV1.Entry e = r.getEntry();
        return new Entry(e.getSeq(), e.getTimestampNs(),
                e.getKey().toByteArray(), e.getData().toByteArray(), e.getLeafHash().toByteArray());
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

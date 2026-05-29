using Grpc.Net.Client;
using Settled.V1;

namespace Settled.Sdk;

public sealed class AppendResult
{
    public ulong Seq { get; init; }
    public long TimestampNs { get; init; }
    public byte[] LeafHash { get; init; } = [];
}

public sealed class Entry
{
    public ulong Seq { get; init; }
    public long TimestampNs { get; init; }
    public byte[] Key { get; init; } = [];
    public byte[] Data { get; init; } = [];
    public byte[] LeafHash { get; init; } = [];
}

public sealed class Sth
{
    public ulong TreeSize { get; init; }
    public byte[] RootHash { get; init; } = [];
    public long TimestampNs { get; init; }
    public byte[] Signature { get; init; } = [];
    public byte[] PublicKey { get; init; } = [];
    public uint KeyVersion { get; init; }
}

public sealed class InclusionProofResult
{
    public ulong LeafIndex { get; init; }
    public ulong TreeSize { get; init; }
    public IReadOnlyList<byte[]> Proof { get; init; } = [];
    public Sth Sth { get; init; } = new();
}

public sealed class ListEntriesResult
{
    public IReadOnlyList<Entry> Entries { get; init; } = [];
    /// <summary>Pass as cursor in the next call. 0 = no more pages.</summary>
    public ulong NextCursor { get; init; }
}

public sealed class ConsistencyProofResult
{
    public ulong OldSize { get; init; }
    public ulong NewSize { get; init; }
    public IReadOnlyList<byte[]> Proof { get; init; } = [];
    public Sth OldSth { get; init; } = new();
    public Sth NewSth { get; init; } = new();
}

public sealed class SettledClient : IDisposable
{
    private readonly GrpcChannel _channel;
    private readonly SettledLog.SettledLogClient _stub;
    private readonly Grpc.Core.Metadata _headers;

    public SettledClient(string address, string? apiKey = null)
    {
        _channel = GrpcChannel.ForAddress(address, new GrpcChannelOptions
        {
            Credentials = Grpc.Core.ChannelCredentials.Insecure,
        });
        _stub = new SettledLog.SettledLogClient(_channel);
        _headers = new Grpc.Core.Metadata();
        if (apiKey is not null)
            _headers.Add("authorization", $"Bearer {apiKey}");
    }

    public void Dispose() => _channel.Dispose();

    public async Task<AppendResult> AppendAsync(byte[] key, byte[] data, CancellationToken ct = default)
    {
        var res = await _stub.AppendAsync(new AppendRequest { Key = Google.Protobuf.ByteString.CopyFrom(key), Data = Google.Protobuf.ByteString.CopyFrom(data) }, headers: _headers, cancellationToken: ct);
        return new AppendResult { Seq = res.Seq, TimestampNs = res.TimestampNs, LeafHash = res.LeafHash.ToByteArray() };
    }

    public async Task<Entry> GetAsync(ulong seq, CancellationToken ct = default)
    {
        var res = await _stub.GetAsync(new GetRequest { Seq = seq }, headers: _headers, cancellationToken: ct);
        return MapEntry(res.Entry);
    }

    /// <summary>
    /// Returns a seq-ordered page of entries within [fromSeq, toSeq).
    /// toSeq=0 scans to the end of the log. cursor=0 starts from fromSeq;
    /// pass NextCursor from the previous response to continue pagination.
    /// limit=0 uses the server default (50); values above 1000 are clamped.
    /// </summary>
    public async Task<ListEntriesResult> ListEntriesAsync(
        ulong fromSeq = 0, ulong toSeq = 0, ulong cursor = 0, uint limit = 0,
        CancellationToken ct = default)
    {
        var res = await _stub.ListEntriesAsync(
            new ListEntriesRequest { FromSeq = fromSeq, ToSeq = toSeq, Cursor = cursor, Limit = limit },
            headers: _headers, cancellationToken: ct);
        return new ListEntriesResult
        {
            Entries = res.Entries.Select(MapEntry).ToArray(),
            NextCursor = res.NextCursor,
        };
    }

    /// <summary>
    /// Returns the most-recent <paramref name="n"/> entries (newest first).
    /// n=0 is treated as 1 by the server. Values above the server cap (1000) are silently clamped.
    /// </summary>
    public async Task<IReadOnlyList<Entry>> GetLatestAsync(uint n = 1, CancellationToken ct = default)
    {
        var res = await _stub.GetLatestAsync(new GetLatestRequest { N = n }, headers: _headers, cancellationToken: ct);
        return res.Entries.Select(MapEntry).ToArray();
    }

    /// <summary>Retrieve a Signed Tree Head. Pass treeSize=0 for the latest.</summary>
    public async Task<Sth> GetSthAsync(ulong treeSize = 0, CancellationToken ct = default)
    {
        var res = await _stub.GetSthAsync(new GetSthRequest { TreeSize = treeSize }, headers: _headers, cancellationToken: ct);
        return MapSth(res.Sth);
    }

    /// <summary>Return an inclusion proof for seq against the given tree size (0 = latest).</summary>
    public async Task<InclusionProofResult> InclusionProofAsync(ulong seq, ulong treeSize = 0, CancellationToken ct = default)
    {
        var res = await _stub.InclusionProofAsync(new InclusionProofRequest { Seq = seq, TreeSize = treeSize }, headers: _headers, cancellationToken: ct);
        return new InclusionProofResult
        {
            LeafIndex = res.LeafIndex,
            TreeSize = res.TreeSize,
            Proof = res.Proof.Select(b => b.ToByteArray()).ToArray(),
            Sth = MapSth(res.Sth),
        };
    }

    /// <summary>Return a consistency proof between two tree sizes (newSize=0 = latest).</summary>
    public async Task<ConsistencyProofResult> ConsistencyProofAsync(ulong oldSize, ulong newSize = 0, CancellationToken ct = default)
    {
        var res = await _stub.ConsistencyProofAsync(new ConsistencyProofRequest { OldSize = oldSize, NewSize = newSize }, headers: _headers, cancellationToken: ct);
        return new ConsistencyProofResult
        {
            OldSize = res.OldSize,
            NewSize = res.NewSize,
            Proof = res.Proof.Select(b => b.ToByteArray()).ToArray(),
            OldSth = MapSth(res.OldSth),
            NewSth = MapSth(res.NewSth),
        };
    }

    private static Entry MapEntry(Settled.V1.Entry e) => new()
    {
        Seq = e.Seq,
        TimestampNs = e.TimestampNs,
        Key = e.Key.ToByteArray(),
        Data = e.Data.ToByteArray(),
        LeafHash = e.LeafHash.ToByteArray(),
    };

    private static Sth MapSth(SignedTreeHead s) => new()
    {
        TreeSize = s.TreeSize,
        RootHash = s.RootHash.ToByteArray(),
        TimestampNs = s.TimestampNs,
        Signature = s.Signature.ToByteArray(),
        PublicKey = s.PublicKey.ToByteArray(),
        KeyVersion = s.KeyVersion,
    };
}

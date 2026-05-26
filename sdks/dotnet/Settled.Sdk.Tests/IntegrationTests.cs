using System.Net;
using System.Net.Sockets;
using Settled.Sdk;
using Xunit;

namespace Settled.Sdk.Tests;

/// <summary>
/// End-to-end integration tests. Spawns a real settled-server subprocess and
/// verifies the full client + verifier round-trip over gRPC.
///
/// Skipped automatically when target/{debug,release}/settled-server is not built.
/// Run only these tests: dotnet test --filter "Category=Integration"
/// </summary>
[Trait("Category", "Integration")]
public class IntegrationTests : IAsyncLifetime
{
    private static readonly string RepoRoot = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "../../../../../../"));

    private System.Diagnostics.Process? _server;
    private string _address = "";

    // ── Harness ───────────────────────────────────────────────────────────────

    private static string? FindServerBinary()
    {
        foreach (var rel in new[] { "target/release/settled-server", "target/debug/settled-server" })
        {
            var path = Path.Combine(RepoRoot, rel);
            if (File.Exists(path)) return path;
        }
        return null;
    }

    private static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    private static async Task WaitForPortAsync(string host, int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(host, port);
                return;
            }
            catch
            {
                await Task.Delay(100);
            }
        }
        throw new TimeoutException($"Server did not start on {host}:{port} within {timeout}");
    }

    public async Task InitializeAsync()
    {
        var binary = FindServerBinary();
        if (binary is null) return;

        var grpcPort = FreePort();
        var adminPort = FreePort();
        var dataDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(dataDir);

        _server = new System.Diagnostics.Process
        {
            StartInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = binary,
                Arguments = $"--data-dir {dataDir} --listen 127.0.0.1:{grpcPort} --admin-listen 127.0.0.1:{adminPort} --sth-interval-secs 1",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            }
        };
        _server.Start();
        _address = $"http://127.0.0.1:{grpcPort}";

        await WaitForPortAsync("127.0.0.1", grpcPort, TimeSpan.FromSeconds(15));
    }

    public Task DisposeAsync()
    {
        if (_server is not null && !_server.HasExited)
        {
            _server.Kill();
            _server.WaitForExit(5000);
        }
        _server?.Dispose();
        return Task.CompletedTask;
    }

    private static async Task<Sth> WaitForSthAsync(SettledClient client, ulong minSize)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var sth = await client.GetSthAsync(0);
                if (sth.TreeSize >= minSize) return sth;
            }
            catch { }
            await Task.Delay(100);
        }
        throw new TimeoutException($"No STH covering {minSize} entries within 5s");
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    [SkippableFact]
    public async Task AppendGetRoundTrip()
    {
        Skip.If(FindServerBinary() is null, "settled-server binary not built; run `cargo build -p settled-server`");
        using var client = new SettledClient(_address);

        for (ulong i = 0; i < 20; i++)
        {
            var res = await client.AppendAsync("k"u8.ToArray(), System.Text.Encoding.UTF8.GetBytes($"d-{i}"));
            Assert.Equal(i, res.Seq);
        }

        for (ulong i = 0; i < 20; i++)
        {
            var entry = await client.GetAsync(i);
            Assert.Equal(i, entry.Seq);
            Assert.Equal($"d-{i}", System.Text.Encoding.UTF8.GetString(entry.Data));
        }
    }

    [SkippableFact]
    public async Task GetLatestReturnsNewestFirst()
    {
        Skip.If(FindServerBinary() is null, "settled-server binary not built; run `cargo build -p settled-server`");
        using var client = new SettledClient(_address);

        for (var i = 0; i < 10; i++)
            await client.AppendAsync("k"u8.ToArray(), System.Text.Encoding.UTF8.GetBytes($"x-{i}"));

        var latest = await client.GetLatestAsync(5);
        Assert.Equal(new ulong[] { 9, 8, 7, 6, 5 }, latest.Select(e => e.Seq).ToArray());
        Assert.Equal("x-9", System.Text.Encoding.UTF8.GetString(latest[0].Data));

        // n=0 → server clamps to 1.
        var single = await client.GetLatestAsync(0);
        Assert.Single(single);
        Assert.Equal(9UL, single[0].Seq);
    }

    [SkippableFact]
    public async Task SignedTreeHeadVerifies()
    {
        Skip.If(FindServerBinary() is null, "settled-server binary not built; run `cargo build -p settled-server`");
        using var client = new SettledClient(_address);

        for (var i = 0; i < 5; i++)
            await client.AppendAsync("k"u8.ToArray(), System.Text.Encoding.UTF8.GetBytes($"d-{i}"));

        var sth = await WaitForSthAsync(client, 5);

        Assert.True(Verifier.VerifyTreeHead(sth.TreeSize, sth.RootHash, sth.TimestampNs, sth.Signature, sth.PublicKey));

        var tampered = (byte[])sth.RootHash.Clone();
        tampered[0] ^= 1;
        Assert.False(Verifier.VerifyTreeHead(sth.TreeSize, tampered, sth.TimestampNs, sth.Signature, sth.PublicKey));
    }

    [SkippableFact]
    public async Task InclusionProofVerifiesForEveryEntry()
    {
        Skip.If(FindServerBinary() is null, "settled-server binary not built; run `cargo build -p settled-server`");
        using var client = new SettledClient(_address);

        const int N = 15;
        var leaves = new byte[N][];
        for (var i = 0; i < N; i++)
        {
            var res = await client.AppendAsync("k"u8.ToArray(), System.Text.Encoding.UTF8.GetBytes($"e-{i}"));
            leaves[i] = res.LeafHash;
        }

        var sth = await WaitForSthAsync(client, N);

        for (ulong i = 0; i < N; i++)
        {
            var ip = await client.InclusionProofAsync(i, sth.TreeSize);
            Assert.True(
                Verifier.VerifyInclusion(leaves[i], i, sth.TreeSize, ip.Proof, sth.RootHash),
                $"inclusion proof for seq {i} must verify");
        }
    }

    [SkippableFact]
    public async Task ConsistencyProofVerifies()
    {
        Skip.If(FindServerBinary() is null, "settled-server binary not built; run `cargo build -p settled-server`");
        using var client = new SettledClient(_address);

        for (var i = 0; i < 10; i++)
            await client.AppendAsync("k"u8.ToArray(), System.Text.Encoding.UTF8.GetBytes($"a-{i}"));
        var sthOld = await WaitForSthAsync(client, 10);

        for (var i = 10; i < 25; i++)
            await client.AppendAsync("k"u8.ToArray(), System.Text.Encoding.UTF8.GetBytes($"b-{i}"));
        var sthNew = await WaitForSthAsync(client, 25);

        var cp = await client.ConsistencyProofAsync(sthOld.TreeSize, sthNew.TreeSize);
        Assert.True(
            Verifier.VerifyConsistency(sthOld.TreeSize, sthNew.TreeSize, cp.Proof, sthOld.RootHash, sthNew.RootHash),
            "consistency proof between two real STHs must verify");
    }
}

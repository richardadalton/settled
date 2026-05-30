/*
 * Settled .NET Demo
 *
 * Usage:
 *   dotnet run                              # append demo entries + show log
 *   dotnet run -- --skip-append            # show existing log
 *   dotnet run -- --verify                 # append + verify STH + inclusion proofs
 *   dotnet run -- --verify --consistency   # also verify consistency before→after append
 *   dotnet run -- --get 3                  # look up a single entry by seq
 *   dotnet run -- --get 3 --verify         # look up + verify its inclusion proof
 *   dotnet run -- --key "user:alice"       # fetch all entries for a key (paginated)
 *   dotnet run -- --batch                  # append all demo entries in one BatchAppend call
 *   dotnet run -- --watch                  # stream new entries via Watch RPC
 *   dotnet run -- --watch --verify         # stream + verify each new entry
 *   dotnet run -- --host localhost:50051   # connect to a non-default address
 */

using Settled.Sdk;
using System.CommandLine;
using System.Text;

const int ColSeq  = 4;
const int ColKey  = 20;
const int ColData = 20;
const int ColTime = 20;
const int ColHash = 18;

(string Key, string Data)[] demoEntries =
[
    ("user:alice",  "login"),
    ("order:1001",  "created"),
    ("order:1001",  "payment_received"),
    ("order:1001",  "shipped"),
    ("user:bob",    "login"),
    ("order:1002",  "created"),
];

var hostOpt        = new Option<string>("--host",         () => "localhost:50051", "gRPC address of the settled-server");
var skipAppendOpt  = new Option<bool>  ("--skip-append",  "Skip appending demo entries");
var verifyOpt      = new Option<bool>  ("--verify",       "Verify STH signature and inclusion proofs");
var consistencyOpt = new Option<bool>  ("--consistency",  "Also verify consistency proof before→after append (requires --verify)");
var getOpt         = new Option<int?>  ("--get",          "Fetch a single entry by sequence number");
var keyOpt         = new Option<string?>("--key",         "Fetch all entries for this key (paginated)");
var batchOpt       = new Option<bool>  ("--batch",        "Append all demo entries in one BatchAppend call");
var watchOpt       = new Option<bool>  ("--watch",        "Stream new entries via Watch RPC");

var root = new RootCommand("Settled .NET Demo")
{
    hostOpt, skipAppendOpt, verifyOpt, consistencyOpt, getOpt, keyOpt, batchOpt, watchOpt,
};

root.SetHandler(async ctx =>
{
    var host        = ctx.ParseResult.GetValueForOption(hostOpt)!;
    var skipAppend  = ctx.ParseResult.GetValueForOption(skipAppendOpt);
    var verify      = ctx.ParseResult.GetValueForOption(verifyOpt);
    var consistency = ctx.ParseResult.GetValueForOption(consistencyOpt);
    var getSeq      = ctx.ParseResult.GetValueForOption(getOpt);
    var key         = ctx.ParseResult.GetValueForOption(keyOpt);
    var batch       = ctx.ParseResult.GetValueForOption(batchOpt);
    var watch       = ctx.ParseResult.GetValueForOption(watchOpt);

    Console.WriteLine($"Connecting to {host} …\n");
    using var client = new SettledClient($"http://{host}");

    if (watch)
        await ModeWatch(client, verify);
    else if (getSeq is not null)
        await ModeGet(client, (ulong)getSeq.Value, verify);
    else if (key is not null)
        await ModeGetByKey(client, key);
    else if (batch)
        await ModeBatchAppend(client, demoEntries);
    else
        await ModeDefault(client, verify, consistency, skipAppend, demoEntries);
});

return await root.InvokeAsync(args);

// ── Formatting ─────────────────────────────────────────────────────────────────

static string FmtTime(long tsNs)
{
    var dt = DateTimeOffset.FromUnixTimeMilliseconds(tsNs / 1_000_000).UtcDateTime;
    return dt.ToString("HH:mm:ss.fff") + "Z";
}

static string FmtHash(byte[] h) => Convert.ToHexString(h)[..16].ToLower() + "…";

static string TableHeader(bool showProof) =>
    $"{"Seq",ColSeq}  {"Key",-ColKey}  {"Data",-ColData}  {"Time",-ColTime}  {"Leaf Hash",-ColHash}"
    + (showProof ? "  Proof" : "");

static string EntryRow(Entry e, string proofCol = "")
{
    var key  = Encoding.UTF8.GetString(e.Key);
    var data = Encoding.UTF8.GetString(e.Data);
    return $"{e.Seq,ColSeq}  {key,-ColKey}  {data,-ColData}  {FmtTime(e.TimestampNs),-ColTime}  {FmtHash(e.LeafHash),-ColHash}{proofCol}";
}

static void PrintTable(IReadOnlyList<Entry> entries, Dictionary<ulong, bool>? verified)
{
    var header = TableHeader(verified is not null);
    Console.WriteLine(header);
    Console.WriteLine(new string('-', header.Length));
    foreach (var e in entries)
    {
        var proof = verified is not null ? (verified.GetValueOrDefault(e.Seq) ? "  OK" : "  FAIL") : "";
        Console.WriteLine(EntryRow(e, proof));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static async Task<List<Entry>> FetchAllEntries(SettledClient client)
{
    var entries = new List<Entry>();
    ulong cursor = 0;
    while (true)
    {
        var page = await client.ListEntriesAsync(cursor: cursor);
        entries.AddRange(page.Entries);
        if (page.NextCursor == 0) break;
        cursor = page.NextCursor;
    }
    return entries;
}

static async Task<Sth> WaitForSth(SettledClient client, ulong minSize = 1)
{
    var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(10);
    while (DateTime.UtcNow < deadline)
    {
        try
        {
            var s = await client.GetSthAsync();
            if (s.TreeSize >= minSize) return s;
        }
        catch { }
        await Task.Delay(200);
    }
    throw new TimeoutException($"No STH covering {minSize} entries within 10s");
}

static async Task<Sth> CheckSth(SettledClient client, ulong minSize = 1)
{
    var sth = await WaitForSth(client, minSize);
    Console.Write("Verifying STH signature … ");
    var ok = Verifier.VerifyTreeHead(sth.TreeSize, sth.RootHash, sth.TimestampNs, sth.Signature, sth.PublicKey);
    Console.WriteLine(ok ? "OK" : "FAIL");
    if (!ok) Console.WriteLine("  Warning: STH signature invalid — results below may not be trustworthy.");
    return sth;
}

static async Task<Dictionary<ulong, bool>> CheckInclusions(SettledClient client, IReadOnlyList<Entry> entries, Sth sth)
{
    Console.Write($"Verifying inclusion proof{(entries.Count == 1 ? "" : "s")} for {entries.Count} entr{(entries.Count == 1 ? "y" : "ies")} … ");
    var results = new Dictionary<ulong, bool>();
    foreach (var e in entries)
    {
        var p = await client.InclusionProofAsync(e.Seq, sth.TreeSize);
        results[e.Seq] = Verifier.VerifyInclusion(e.LeafHash, p.LeafIndex, p.TreeSize, p.Proof, sth.RootHash);
    }
    var failed = results.Values.Count(v => !v);
    Console.WriteLine(failed == 0 ? "all OK" : $"{failed} FAILED");
    return results;
}

static async Task CheckConsistency(SettledClient client, Sth oldSth, Sth newSth)
{
    Console.Write($"Verifying consistency proof  {oldSth.TreeSize} → {newSth.TreeSize} … ");
    if (oldSth.TreeSize == newSth.TreeSize)
    {
        Console.WriteLine("nothing to prove (tree unchanged)");
        return;
    }
    var p = await client.ConsistencyProofAsync(oldSth.TreeSize, newSth.TreeSize);
    var ok = Verifier.VerifyConsistency(p.OldSize, p.NewSize, p.Proof, oldSth.RootHash, newSth.RootHash);
    Console.WriteLine(ok ? "OK" : "FAIL");
}

// ── Modes ──────────────────────────────────────────────────────────────────────

static async Task ModeGet(SettledClient client, ulong seq, bool doVerify)
{
    Entry e;
    try { e = await client.GetAsync(seq); }
    catch (Exception ex) { Console.Error.WriteLine($"Error fetching seq {seq}: {ex.Message}"); return; }

    string proofCol = "";
    if (doVerify)
    {
        var sth = await CheckSth(client, seq + 1);
        var p   = await client.InclusionProofAsync(seq, sth.TreeSize);
        var ok  = Verifier.VerifyInclusion(e.LeafHash, p.LeafIndex, p.TreeSize, p.Proof, sth.RootHash);
        proofCol = ok ? "  OK" : "  FAIL";
        Console.WriteLine();
    }

    var header = TableHeader(doVerify);
    Console.WriteLine(header);
    Console.WriteLine(new string('-', header.Length));
    Console.WriteLine(EntryRow(e, proofCol));
}

static async Task ModeGetByKey(SettledClient client, string key)
{
    var entries = new List<Entry>();
    ulong cursor = 0;
    while (true)
    {
        var page = await client.GetByKeyAsync(Encoding.UTF8.GetBytes(key), cursor: cursor);
        entries.AddRange(page.Entries);
        if (page.NextCursor == 0) break;
        cursor = page.NextCursor;
    }
    Console.WriteLine($"{entries.Count} entr{(entries.Count == 1 ? "y" : "ies")} for key \"{key}\":\n");
    var header = TableHeader(false);
    Console.WriteLine(header);
    Console.WriteLine(new string('-', header.Length));
    foreach (var e in entries) Console.WriteLine(EntryRow(e));
}

static async Task ModeBatchAppend(SettledClient client, (string Key, string Data)[] entries)
{
    Console.WriteLine($"Batch-appending {entries.Length} entries in one RPC call …");
    var results = await client.BatchAppendAsync(
        entries.Select(e => (Encoding.UTF8.GetBytes(e.Key), Encoding.UTF8.GetBytes(e.Data))));
    for (int i = 0; i < results.Count; i++)
        Console.WriteLine($"  seq={results[i].Seq}  key={entries[i].Key}  data={entries[i].Data}");
    Console.WriteLine($"\nAll {results.Count} entries assigned seqs {results[0].Seq}–{results[^1].Seq} in a single WAL write.");
}

static async Task ModeWatch(SettledClient client, bool doVerify)
{
    Console.WriteLine("Streaming new entries via Watch RPC … Ctrl-C to stop.\n");
    Console.WriteLine(TableHeader(doVerify));
    Console.WriteLine(new string('-', TableHeader(doVerify).Length));

    using var cts = new CancellationTokenSource();
    Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

    try
    {
        await foreach (var e in client.WatchEntriesAsync(fromSeq: 0, ct: cts.Token))
        {
            string proofCol = "";
            if (doVerify)
            {
                try
                {
                    var sth = await client.GetSthAsync(cancellationToken: cts.Token);
                    if (e.Seq < sth.TreeSize)
                    {
                        var p  = await client.InclusionProofAsync(e.Seq, sth.TreeSize, cts.Token);
                        var ok = Verifier.VerifyInclusion(e.LeafHash, p.LeafIndex, p.TreeSize, p.Proof, sth.RootHash);
                        proofCol = ok ? "  OK" : "  FAIL";
                    }
                }
                catch (OperationCanceledException) { break; }
            }
            Console.WriteLine(EntryRow(e, proofCol));
        }
    }
    catch (OperationCanceledException) { }

    Console.WriteLine("\nStopped.");
}

static async Task ModeDefault(SettledClient client, bool doVerify, bool doConsistency, bool skipAppend,
    (string Key, string Data)[] demoEntries)
{
    Sth? oldSth = doConsistency ? await WaitForSth(client) : null;

    if (!skipAppend)
    {
        Console.WriteLine("Appending demo entries …");
        foreach (var (key, data) in demoEntries)
        {
            var res = await client.AppendAsync(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(data));
            Console.WriteLine($"  appended seq={res.Seq}  key={key}  data={data}");
        }
        Console.WriteLine();
    }

    Sth sth;
    try { sth = await WaitForSth(client); }
    catch
    {
        Console.WriteLine("Log is empty.");
        return;
    }

    Console.WriteLine("Fetching audit trail …\n");
    var entries = await FetchAllEntries(client);

    Dictionary<ulong, bool>? verified = null;
    if (doVerify)
    {
        sth = await CheckSth(client, sth.TreeSize);
        verified = await CheckInclusions(client, entries, sth);
        if (doConsistency && oldSth is not null)
            await CheckConsistency(client, oldSth, sth);
        Console.WriteLine();
    }

    PrintTable(entries, verified);
    Console.WriteLine($"\n{entries.Count} entr{(entries.Count == 1 ? "y" : "ies")} in log.");
}

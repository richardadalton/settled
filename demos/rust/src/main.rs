/*
 * Settled Rust Demo
 *
 * Usage:
 *   cargo run --                                  # append demo entries + show log
 *   cargo run -- --skip-append                    # show existing log
 *   cargo run -- --verify                         # append + verify STH + inclusion proofs
 *   cargo run -- --verify --consistency           # also verify consistency before→after append
 *   cargo run -- --get 3                          # look up a single entry by seq
 *   cargo run -- --get 3 --verify                 # look up + verify its inclusion proof
 *   cargo run -- --key "user:alice"               # fetch all entries for a key (paginated)
 *   cargo run -- --watch                          # tail new entries as they arrive
 *   cargo run -- --watch --verify                 # tail + verify each new entry
 *   cargo run -- --host http://localhost:50051    # connect to a non-default address
 *   cargo run -- --append "my-key" "my-data"     # append a single entry
 */

use clap::Parser;
use settled_sdk::client::{Entry, SettledClient, SignedTreeHead};
use settled_sdk::verifier::{verify_consistency, verify_inclusion, verify_tree_head};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "settled-demo", about = "Settled Rust Demo")]
struct Args {
    #[arg(long, default_value = "http://localhost:50051", help = "gRPC address of settled-server")]
    host: String,

    #[arg(long, help = "Skip appending demo entries")]
    skip_append: bool,

    #[arg(long, help = "Verify STH signature and inclusion proofs")]
    verify: bool,

    #[arg(long, help = "Also verify consistency proof before→after append (requires --verify)")]
    consistency: bool,

    #[arg(long, value_name = "SEQ", help = "Fetch a single entry by sequence number")]
    get: Option<u64>,

    #[arg(long, help = "Tail new entries as they arrive")]
    watch: bool,

    #[arg(long, default_value = "2.0", value_name = "SECS", help = "Polling interval for --watch")]
    interval: f64,

    #[arg(long, value_names = ["KEY", "DATA"], num_args = 2, help = "Append a single entry")]
    append: Option<Vec<String>>,

    #[arg(long, value_name = "KEY", help = "Fetch all entries for this key (paginated)")]
    key: Option<String>,
}

// ── Formatting ────────────────────────────────────────────────────────────────

fn fmt_time(ts_ns: i64) -> String {
    let secs = ts_ns.unsigned_abs() / 1_000_000_000;
    let ms = (ts_ns.unsigned_abs() % 1_000_000_000) / 1_000_000;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

fn fmt_hash(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    format!("{}…", &hex[..hex.len().min(16)])
}

fn table_header(show_proof: bool) -> String {
    let mut h = format!(
        "{:>4}  {:<20}  {:<20}  {:<20}  {:<18}",
        "Seq", "Key", "Data", "Time", "Leaf Hash"
    );
    if show_proof {
        h.push_str("  Proof");
    }
    h
}

fn entry_row(e: &Entry, proof_col: &str) -> String {
    format!(
        "{:>4}  {:<20}  {:<20}  {:<20}  {:<18}{}",
        e.seq,
        String::from_utf8_lossy(&e.key),
        String::from_utf8_lossy(&e.data),
        fmt_time(e.timestamp_ns),
        fmt_hash(&e.leaf_hash),
        proof_col,
    )
}

fn print_table(entries: &[Entry], verified: Option<&HashMap<u64, bool>>) {
    let hdr = table_header(verified.is_some());
    println!("{hdr}");
    println!("{}", "-".repeat(hdr.len()));
    for e in entries {
        let proof_col = match verified {
            None => "",
            Some(v) => {
                if v.get(&e.seq).copied().unwrap_or(false) {
                    "  OK"
                } else {
                    "  FAIL"
                }
            }
        };
        println!("{}", entry_row(e, proof_col));
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn to32(b: &[u8]) -> [u8; 32] {
    b.try_into().expect("expected 32 bytes")
}

fn proof32(p: &[Vec<u8>]) -> Vec<[u8; 32]> {
    p.iter().map(|b| to32(b)).collect()
}

async fn wait_for_sth(
    c: &mut SettledClient,
    min_size: u64,
) -> Result<SignedTreeHead, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(sth) = c.get_sth(0).await {
            if sth.tree_size >= min_size {
                return Ok(sth);
            }
        }
        if Instant::now() > deadline {
            return Err(format!("no STH covering {min_size} entries within 10s").into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn check_sth(
    c: &mut SettledClient,
    min_size: u64,
) -> Result<SignedTreeHead, Box<dyn std::error::Error>> {
    let sth = wait_for_sth(c, min_size).await?;
    print!("Verifying STH signature … ");
    let ok = verify_tree_head(
        sth.tree_size,
        to32(&sth.root_hash),
        sth.timestamp_ns,
        &sth.signature,
        &sth.public_key,
    );
    if ok {
        println!("OK");
    } else {
        println!("FAIL");
        println!("  Warning: STH signature invalid — results below may not be trustworthy.");
    }
    Ok(sth)
}

async fn check_inclusions(
    c: &mut SettledClient,
    entries: &[Entry],
    sth: &SignedTreeHead,
) -> Result<HashMap<u64, bool>, Box<dyn std::error::Error>> {
    let noun = if entries.len() == 1 { "entry" } else { "entries" };
    print!("Verifying inclusion proof for {} {} … ", entries.len(), noun);

    let mut results = HashMap::new();
    for e in entries {
        let p = c.inclusion_proof(e.seq, sth.tree_size).await?;
        let ok = verify_inclusion(
            to32(&e.leaf_hash),
            p.leaf_index,
            p.tree_size,
            &proof32(&p.proof),
            to32(&sth.root_hash),
        );
        results.insert(e.seq, ok);
    }

    let failed = results.values().filter(|&&ok| !ok).count();
    if failed == 0 {
        println!("all OK");
    } else {
        println!("{failed} FAILED");
    }
    Ok(results)
}

async fn check_consistency(
    c: &mut SettledClient,
    old_sth: &SignedTreeHead,
    new_sth: &SignedTreeHead,
) -> Result<(), Box<dyn std::error::Error>> {
    print!(
        "Verifying consistency proof  {} → {} … ",
        old_sth.tree_size, new_sth.tree_size
    );
    if old_sth.tree_size == new_sth.tree_size {
        println!("nothing to prove (tree unchanged)");
        return Ok(());
    }
    let cp = c.consistency_proof(old_sth.tree_size, new_sth.tree_size).await?;
    let ok = verify_consistency(
        cp.old_size,
        cp.new_size,
        &proof32(&cp.proof),
        to32(&old_sth.root_hash),
        to32(&new_sth.root_hash),
    );
    println!("{}", if ok { "OK" } else { "FAIL" });
    Ok(())
}

// ── Modes ─────────────────────────────────────────────────────────────────────

async fn mode_default(
    c: &mut SettledClient,
    do_verify: bool,
    do_consistency: bool,
    skip_append: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let demo_entries = [
        ("user:alice", "login"),
        ("order:1001", "created"),
        ("order:1001", "payment_received"),
        ("order:1001", "shipped"),
        ("user:bob", "login"),
        ("order:1002", "created"),
    ];

    let old_sth = if do_consistency {
        c.get_sth(0).await.ok()
    } else {
        None
    };

    if !skip_append {
        println!("Appending demo entries …");
        for (key, data) in &demo_entries {
            let res = c
                .append(key.as_bytes().to_vec(), data.as_bytes().to_vec())
                .await?;
            println!("  appended seq={}  key={key}  data={data}", res.seq);
        }
        println!();
    }

    let sth = match wait_for_sth(c, 1).await {
        Ok(s) => s,
        Err(_) => {
            println!("Log is empty.");
            return Ok(());
        }
    };

    println!("Fetching audit trail …\n");
    let mut entries = Vec::new();
    let mut cursor = 0u64;
    loop {
        let page = c.list_entries(0, sth.tree_size, cursor, 0).await?;
        entries.extend(page.entries);
        if page.next_cursor == 0 {
            break;
        }
        cursor = page.next_cursor;
    }

    let verified = if do_verify {
        let sth = check_sth(c, sth.tree_size).await?;
        let v = check_inclusions(c, &entries, &sth).await?;
        if do_consistency {
            if let Some(old) = &old_sth {
                check_consistency(c, old, &sth).await?;
            }
        }
        println!();
        Some(v)
    } else {
        None
    };

    print_table(&entries, verified.as_ref());
    let noun = if entries.len() == 1 { "entry" } else { "entries" };
    println!("\n{} {noun} in log.", entries.len());
    Ok(())
}

async fn mode_get(
    c: &mut SettledClient,
    seq: u64,
    do_verify: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let e = c.get(seq).await?;

    let proof_col = if do_verify {
        let sth = check_sth(c, seq + 1).await?;
        let p = c.inclusion_proof(seq, sth.tree_size).await?;
        let ok = verify_inclusion(
            to32(&e.leaf_hash),
            p.leaf_index,
            p.tree_size,
            &proof32(&p.proof),
            to32(&sth.root_hash),
        );
        println!();
        if ok { "  OK".to_string() } else { "  FAIL".to_string() }
    } else {
        String::new()
    };

    let hdr = table_header(do_verify);
    println!("{hdr}");
    println!("{}", "-".repeat(hdr.len()));
    println!("{}", entry_row(&e, &proof_col));
    Ok(())
}

async fn mode_watch(
    c: &mut SettledClient,
    do_verify: bool,
    interval_secs: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Watching for new entries (polling every {interval_secs:.0}s) … Ctrl-C to stop.\n"
    );

    let mut seq = wait_for_sth(c, 1).await.map(|s| s.tree_size).unwrap_or(0);

    let hdr = table_header(do_verify);
    println!("{hdr}");
    println!("{}", "-".repeat(hdr.len()));

    let interval = Duration::from_secs_f64(interval_secs);
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        tokio::select! {
            _ = &mut ctrl_c => {
                println!("\nStopped.");
                return Ok(());
            }
            _ = tokio::time::sleep(interval) => {
                if let Ok(sth) = wait_for_sth(c, 1).await {
                    while seq < sth.tree_size {
                        if let Ok(e) = c.get(seq).await {
                            let proof_col = if do_verify {
                                if let Ok(p) = c.inclusion_proof(seq, sth.tree_size).await {
                                    let ok = verify_inclusion(
                                        to32(&e.leaf_hash),
                                        p.leaf_index,
                                        p.tree_size,
                                        &proof32(&p.proof),
                                        to32(&sth.root_hash),
                                    );
                                    if ok { "  OK".to_string() } else { "  FAIL".to_string() }
                                } else {
                                    String::new()
                                }
                            } else {
                                String::new()
                            };
                            println!("{}", entry_row(&e, &proof_col));
                        }
                        seq += 1;
                    }
                }
            }
        }
    }
}

async fn mode_append(
    c: &mut SettledClient,
    key: &str,
    data: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let res = c.append(key.as_bytes().to_vec(), data.as_bytes().to_vec()).await?;
    println!("appended  seq={}  key={key}  data={data}  leaf_hash={}", res.seq, fmt_hash(&res.leaf_hash));
    Ok(())
}

async fn mode_get_by_key(
    c: &mut SettledClient,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut all_entries: Vec<Entry> = Vec::new();
    let mut cursor = 0u64;
    loop {
        let result = c.get_by_key(key.as_bytes().to_vec(), cursor, 0).await?;
        all_entries.extend(result.entries);
        if result.next_cursor == 0 {
            break;
        }
        cursor = result.next_cursor;
    }

    let noun = if all_entries.len() == 1 { "entry" } else { "entries" };
    println!("{} {} for key \"{key}\":\n", all_entries.len(), noun);

    let hdr = table_header(false);
    println!("{hdr}");
    println!("{}", "-".repeat(hdr.len()));
    for e in &all_entries {
        println!("{}", entry_row(e, ""));
    }
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("Connecting to {} …\n", args.host);
    let mut c = match SettledClient::connect(args.host.clone()).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let result = if args.watch {
        mode_watch(&mut c, args.verify, args.interval).await
    } else if let Some(seq) = args.get {
        mode_get(&mut c, seq, args.verify).await
    } else if let Some(kv) = args.append {
        mode_append(&mut c, &kv[0], &kv[1]).await
    } else if let Some(key) = args.key {
        mode_get_by_key(&mut c, &key).await
    } else {
        mode_default(&mut c, args.verify, args.consistency, args.skip_append).await
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

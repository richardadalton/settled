//! Integration tests for the Rust SDK.
//!
//! Boots a real settled-server subprocess on an ephemeral port, talks to it
//! via SettledClient over real gRPC, and verifies proofs using the verifier.
//!
//! Skipped automatically when target/{release,debug}/settled-server is not built.
//! Build it first: `cargo build -p settled-server` from the repo root.

use settled_sdk::client::{SettledClient, SignedTreeHead};
use settled_sdk::verifier::{verify_consistency, verify_inclusion, verify_tree_head};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ── Test harness ─────────────────────────────────────────────────────────────

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn find_server() -> Option<PathBuf> {
    let root = repo_root();
    for rel in &[
        "target/release/settled-server",
        "target/debug/settled-server",
    ] {
        let p = root.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

struct ServerGuard {
    child: Child,
    data_dir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// Spawns settled-server on ephemeral ports. Returns (grpc_addr, guard).
/// Returns None and prints a skip message when the binary is not found.
fn start_server(test_name: &str) -> Option<(String, ServerGuard)> {
    let binary = match find_server() {
        Some(b) => b,
        None => {
            eprintln!("[{test_name}] SKIP: settled-server binary not found — run `cargo build -p settled-server` from repo root");
            return None;
        }
    };

    let grpc_port = free_port();
    let admin_port = free_port();
    let data_dir = std::env::temp_dir().join(format!("settled-sdk-test-{grpc_port}"));
    std::fs::create_dir_all(&data_dir).ok()?;

    let child = Command::new(&binary)
        .args([
            "--data-dir",
            data_dir.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{grpc_port}"),
            "--admin-listen",
            &format!("127.0.0.1:{admin_port}"),
            "--sth-interval-secs",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn settled-server");

    let tcp_addr = format!("127.0.0.1:{grpc_port}");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if Instant::now() > deadline {
            eprintln!("[{test_name}] SKIP: server did not start within 15s");
            return None;
        }
        if TcpStream::connect(&tcp_addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let grpc_addr = format!("http://127.0.0.1:{grpc_port}");
    Some((grpc_addr, ServerGuard { child, data_dir }))
}

async fn wait_for_sth(c: &mut SettledClient, min_size: u64) -> SignedTreeHead {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(sth) = c.get_sth(0).await {
            if sth.tree_size >= min_size {
                return sth;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no STH covering {min_size} entries within 5s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn to32(b: &[u8]) -> [u8; 32] {
    b.try_into().expect("expected 32 bytes")
}

fn proof32(p: &[Vec<u8>]) -> Vec<[u8; 32]> {
    p.iter().map(|b| to32(b)).collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_append_get_roundtrip() {
    let Some((addr, _guard)) = start_server("append_get_roundtrip") else {
        return;
    };
    let mut c = SettledClient::connect(addr).await.unwrap();

    for i in 0u64..20 {
        let res = c
            .append(b"k".to_vec(), format!("d-{i}").into_bytes())
            .await
            .unwrap();
        assert_eq!(res.seq, i, "unexpected seq for entry {i}");
    }
    for i in 0u64..20 {
        let entry = c.get(i).await.unwrap();
        assert_eq!(entry.data, format!("d-{i}").into_bytes());
    }
}

#[tokio::test]
async fn test_get_latest_newest_first() {
    let Some((addr, _guard)) = start_server("get_latest_newest_first") else {
        return;
    };
    let mut c = SettledClient::connect(addr).await.unwrap();

    for i in 0..10 {
        c.append(b"k".to_vec(), format!("x-{i}").into_bytes())
            .await
            .unwrap();
    }

    let got = c.get_latest(5).await.unwrap();
    assert_eq!(got.entries.len(), 5);
    assert_eq!(got.total_available, 10);
    for (i, e) in got.entries.iter().enumerate() {
        assert_eq!(e.seq, 9 - i as u64);
    }
    assert_eq!(got.entries[0].data, b"x-9");

    let one = c.get_latest(0).await.unwrap();
    assert_eq!(one.entries.len(), 1);
    assert_eq!(one.entries[0].seq, 9);
}

#[tokio::test]
async fn test_sth_verifies() {
    let Some((addr, _guard)) = start_server("sth_verifies") else {
        return;
    };
    let mut c = SettledClient::connect(addr).await.unwrap();

    for i in 0..5 {
        c.append(b"k".to_vec(), format!("d-{i}").into_bytes())
            .await
            .unwrap();
    }
    let sth = wait_for_sth(&mut c, 5).await;

    assert!(
        verify_tree_head(
            sth.tree_size,
            to32(&sth.root_hash),
            sth.timestamp_ns,
            &sth.signature,
            &sth.public_key
        ),
        "STH signature must verify",
    );

    let mut tampered = sth.root_hash.clone();
    tampered[0] ^= 1;
    assert!(
        !verify_tree_head(
            sth.tree_size,
            to32(&tampered),
            sth.timestamp_ns,
            &sth.signature,
            &sth.public_key
        ),
        "tampered root must fail",
    );
}

#[tokio::test]
async fn test_inclusion_proof_verifies() {
    let Some((addr, _guard)) = start_server("inclusion_proof_verifies") else {
        return;
    };
    let mut c = SettledClient::connect(addr).await.unwrap();

    const N: u64 = 15;
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    for i in 0..N {
        let res = c
            .append(b"k".to_vec(), format!("e-{i}").into_bytes())
            .await
            .unwrap();
        leaves.push(to32(&res.leaf_hash));
    }

    let sth = wait_for_sth(&mut c, N).await;
    let root = to32(&sth.root_hash);

    for i in 0..N {
        let ip = c.inclusion_proof(i, sth.tree_size).await.unwrap();
        assert!(
            verify_inclusion(
                leaves[i as usize],
                i,
                sth.tree_size,
                &proof32(&ip.proof),
                root
            ),
            "inclusion proof for seq {i} must verify",
        );
    }
}

#[tokio::test]
async fn test_consistency_proof_verifies() {
    let Some((addr, _guard)) = start_server("consistency_proof_verifies") else {
        return;
    };
    let mut c = SettledClient::connect(addr).await.unwrap();

    for i in 0..10 {
        c.append(b"k".to_vec(), format!("a-{i}").into_bytes())
            .await
            .unwrap();
    }
    let sth_old = wait_for_sth(&mut c, 10).await;

    for i in 10..25 {
        c.append(b"k".to_vec(), format!("b-{i}").into_bytes())
            .await
            .unwrap();
    }
    let sth_new = wait_for_sth(&mut c, 25).await;

    let cp = c
        .consistency_proof(sth_old.tree_size, sth_new.tree_size)
        .await
        .unwrap();
    assert!(
        verify_consistency(
            sth_old.tree_size,
            sth_new.tree_size,
            &proof32(&cp.proof),
            to32(&sth_old.root_hash),
            to32(&sth_new.root_hash),
        ),
        "consistency proof must verify",
    );
}

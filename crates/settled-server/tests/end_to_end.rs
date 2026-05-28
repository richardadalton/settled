//! End-to-end integration tests for `settled-server`.
//!
//! Each test spins up a real server in-process on an ephemeral port,
//! talks to it over real gRPC via the published Rust SDK (`settled-sdk`),
//! and validates correctness of every public RPC. No mocks; no shortcuts.
//! Storage goes through RocksDB in a fresh `tempfile::TempDir` per test.

use std::net::SocketAddr;
use std::time::Duration;

use settled_sdk::verifier::{leaf_hash, verify_consistency, verify_inclusion, verify_tree_head};
use settled_sdk::{SettledClient, SignedTreeHead};
use settled_server::proto::settled_log_server::SettledLogServer;
use settled_server::{AppState, Config, SettledService};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Boots a real `settled-server` on `127.0.0.1:0` (ephemeral port) backed
/// by a fresh `TempDir`. Returns the bound address, the temp dir guard
/// (must be kept alive for the test's lifetime), a connected SDK client, and
/// the STH-task shutdown sender (drop it to stop the task cleanly).
async fn boot() -> (SocketAddr, TempDir, SettledClient, tokio::sync::watch::Sender<bool>) {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let key_path = data_dir.join("signing.key");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let config = Config {
        data_dir,
        key_path,
        listen: addr,
        admin_listen: "127.0.0.1:0".parse().unwrap(),
        sth_interval_secs: 1,
        api_key: None,
    };

    let state = AppState::build(config).await.expect("AppState::build");

    let (sth_tx, sth_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(settled_server::sth_task::run(state.clone(), sth_rx));

    let incoming = TcpListenerStream::new(listener);
    let svc = SettledService::new(state);
    tokio::spawn(async move {
        Server::builder()
            .add_service(SettledLogServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server task");
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = SettledClient::connect(format!("http://{addr}"))
        .await
        .expect("client connect");

    (addr, tmp, client, sth_tx)
}

/// Polls `get_sth(0)` until an STH of at least `min_size` is published,
/// or panics after ~5 seconds.
async fn wait_for_sth(client: &mut SettledClient, min_size: u64) -> SignedTreeHead {
    for _ in 0..50 {
        if let Ok(sth) = client.get_sth(0).await {
            if sth.tree_size >= min_size {
                return sth;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for STH covering at least {min_size} entries");
}

fn b32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32-byte hash")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn append_returns_monotonic_seqs_and_correct_leaf_hash() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    for i in 0..50u64 {
        let data = format!("payload-{i}").into_bytes();
        let res = client
            .append(format!("k-{i}").into_bytes(), data.clone())
            .await
            .expect("append");

        assert_eq!(res.seq, i, "seq must be 0-based and gap-free");
        assert_eq!(
            res.leaf_hash.as_slice(),
            leaf_hash(&data),
            "server-returned leaf_hash must match SDK leaf_hash",
        );
    }
}

#[tokio::test]
async fn get_round_trips_data_unchanged() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    let payloads: Vec<Vec<u8>> = (0..20).map(|i| format!("entry-{i}").into_bytes()).collect();

    for p in &payloads {
        client
            .append(b"k".to_vec(), p.clone())
            .await
            .expect("append");
    }

    for (i, expected) in payloads.iter().enumerate() {
        let entry = client.get(i as u64).await.expect("get");
        assert_eq!(entry.seq, i as u64);
        assert_eq!(&entry.data, expected, "data must round-trip unchanged");
    }
}

#[tokio::test]
async fn get_unknown_seq_returns_not_found() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    let err = client.get(99_999).await.expect_err("expected NotFound");
    let settled_sdk::ClientError::Rpc(status) = err else {
        panic!("expected RPC error, got {err:?}");
    };
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn concurrent_appends_have_unique_gap_free_seqs() {
    let (addr, _tmp, _seed, _sth) = boot().await;
    const N: u64 = 100;

    let mut set = JoinSet::new();
    for i in 0..N {
        let endpoint = format!("http://{addr}");
        set.spawn(async move {
            let mut c = SettledClient::connect(endpoint).await.unwrap();
            c.append(b"k".to_vec(), format!("d-{i}").into_bytes())
                .await
                .unwrap()
                .seq
        });
    }

    let mut seqs = Vec::with_capacity(N as usize);
    while let Some(r) = set.join_next().await {
        seqs.push(r.unwrap());
    }
    seqs.sort_unstable();
    let expected: Vec<u64> = (0..N).collect();
    assert_eq!(seqs, expected, "every seq from 0..N must appear exactly once");
}

#[tokio::test]
async fn get_latest_returns_newest_first_and_clamps_zero_to_one() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    for i in 0..10u64 {
        client
            .append(b"k".to_vec(), format!("p-{i}").into_bytes())
            .await
            .expect("append");
    }

    let entries = client.get_latest(5).await.expect("get_latest");
    assert_eq!(entries.len(), 5);
    let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![9, 8, 7, 6, 5], "newest-first ordering");
    assert_eq!(entries[0].data, b"p-9");

    let entries = client.get_latest(0).await.expect("get_latest n=0");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, 9);

    let entries = client.get_latest(1000).await.expect("get_latest oversize");
    assert_eq!(entries.len(), 10);
    assert_eq!(entries[0].seq, 9, "still newest-first");
    assert_eq!(entries.last().unwrap().seq, 0);
}

#[tokio::test]
async fn get_latest_on_empty_log_returns_no_entries() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    let entries = client.get_latest(5).await.expect("get_latest");
    assert!(entries.is_empty(), "empty log must return no entries");
}

#[tokio::test]
async fn signed_tree_head_signature_verifies() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    for i in 0..10u64 {
        client
            .append(b"k".to_vec(), format!("d-{i}").into_bytes())
            .await
            .expect("append");
    }

    let sth = wait_for_sth(&mut client, 10).await;

    assert!(
        verify_tree_head(sth.tree_size, b32(&sth.root_hash), sth.timestamp_ns, &sth.signature, &sth.public_key),
        "STH signature must verify with embedded public key",
    );

    assert!(
        !verify_tree_head(sth.tree_size + 1, b32(&sth.root_hash), sth.timestamp_ns, &sth.signature, &sth.public_key),
        "tampered tree_size must fail verification",
    );

    let mut bad_root = b32(&sth.root_hash);
    bad_root[0] ^= 0x01;
    assert!(
        !verify_tree_head(sth.tree_size, bad_root, sth.timestamp_ns, &sth.signature, &sth.public_key),
        "tampered root must fail verification",
    );
}

#[tokio::test]
async fn inclusion_proof_verifies_against_sdk() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    let n: u64 = 30;
    let mut leaf_hashes: Vec<[u8; 32]> = Vec::with_capacity(n as usize);
    for i in 0..n {
        let data = format!("entry-{i}").into_bytes();
        let res = client
            .append(b"k".to_vec(), data)
            .await
            .expect("append");
        leaf_hashes.push(b32(&res.leaf_hash));
    }

    let sth = wait_for_sth(&mut client, n).await;
    let root = b32(&sth.root_hash);

    for i in 0..n {
        let res = client
            .inclusion_proof(i, sth.tree_size)
            .await
            .expect("inclusion_proof");

        let path: Vec<[u8; 32]> = res.proof.iter().map(|p| b32(p)).collect();

        assert!(
            verify_inclusion(leaf_hashes[i as usize], i, sth.tree_size, &path, root),
            "inclusion proof for seq {i} must verify",
        );
    }
}

#[tokio::test]
async fn consistency_proof_between_two_sths_verifies() {
    let (_addr, _tmp, mut client, _sth) = boot().await;

    for i in 0..20u64 {
        client
            .append(b"k".to_vec(), format!("first-{i}").into_bytes())
            .await
            .expect("append");
    }
    let sth_old = wait_for_sth(&mut client, 20).await;

    for i in 20..50u64 {
        client
            .append(b"k".to_vec(), format!("second-{i}").into_bytes())
            .await
            .expect("append");
    }
    let sth_new = wait_for_sth(&mut client, 50).await;

    let res = client
        .consistency_proof(sth_old.tree_size, sth_new.tree_size)
        .await
        .expect("consistency_proof");

    let path: Vec<[u8; 32]> = res.proof.iter().map(|p| b32(p)).collect();

    assert!(
        verify_consistency(
            sth_old.tree_size,
            sth_new.tree_size,
            &path,
            b32(&sth_old.root_hash),
            b32(&sth_new.root_hash),
        ),
        "consistency proof between two real STHs must verify",
    );
}

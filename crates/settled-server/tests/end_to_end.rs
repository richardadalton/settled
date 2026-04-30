//! End-to-end integration tests for `settled-server`.
//!
//! Each test spins up a real server in-process on an ephemeral port,
//! talks to it over real gRPC via a real `tonic` client, and validates
//! correctness of every public RPC. No mocks; no shortcuts. Storage
//! goes through RocksDB in a fresh `tempfile::TempDir` per test.
//!
//! These tests close the gap previously identified in the project: the
//! server crate had zero tests despite hosting the most stateful and
//! concurrent code in the project.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use settled_core::{hash::leaf_hash, proof, sth};
use settled_server::proto::settled_log_client::SettledLogClient;
use settled_server::proto::settled_log_server::SettledLogServer;
use settled_server::proto::{
    AppendRequest, ConsistencyProofRequest, GetLatestRequest, GetRequest, GetSthRequest,
    InclusionProofRequest, SignedTreeHead as ProtoSth,
};
use settled_server::{AppState, Config, SettledService};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

/// Boots a real `settled-server` on `127.0.0.1:0` (ephemeral port) backed
/// by a fresh `TempDir`. Returns the bound address, the temp dir guard
/// (must be kept alive for the test's lifetime), and a connected gRPC
/// client. The STH task is started with a 1-second interval.
async fn boot() -> (SocketAddr, TempDir, SettledLogClient<Channel>) {
    let tmp = TempDir::new().expect("tempdir");
    let data_dir = tmp.path().to_path_buf();
    let key_path = data_dir.join("signing.key");

    // Bind first so we know the port the server will accept on.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let config = Config {
        data_dir,
        key_path,
        listen: addr,
        // Admin HTTP isn't exercised by these tests; bind to an unused
        // ephemeral port so it never collides.
        admin_listen: "127.0.0.1:0".parse().unwrap(),
        sth_interval_secs: 1,
    };

    let state = AppState::build(config).await.expect("AppState::build");

    // STH task — periodically signs the latest root.
    tokio::spawn(settled_server::sth_task::run(state.clone()));

    // gRPC server.
    let incoming = TcpListenerStream::new(listener);
    let svc = SettledService::new(state);
    tokio::spawn(async move {
        Server::builder()
            .add_service(SettledLogServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .expect("server task");
    });

    // Brief delay; tonic's `connect()` retries internally but giving the
    // server a tick to install the listener avoids spurious flakes.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let endpoint = format!("http://{addr}");
    let client = SettledLogClient::connect(endpoint)
        .await
        .expect("client connect");

    (addr, tmp, client)
}

/// Polls `GetSth(0)` until an STH of at least `min_size` is published,
/// or panics after ~5 seconds. The STH task fires every 1s in tests.
async fn wait_for_sth(client: &mut SettledLogClient<Channel>, min_size: u64) -> ProtoSth {
    for _ in 0..50 {
        if let Ok(res) = client
            .get_sth(GetSthRequest { tree_size: 0 })
            .await
        {
            if let Some(sth) = res.into_inner().sth {
                if sth.tree_size >= min_size {
                    return sth;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for STH covering at least {min_size} entries");
}

fn to_array_32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32-byte hash")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn append_returns_monotonic_seqs_and_correct_leaf_hash() {
    let (_addr, _tmp, mut client) = boot().await;

    for i in 0..50u64 {
        let key = format!("k-{i}").into_bytes();
        let data = format!("payload-{i}").into_bytes();
        let res = client
            .append(AppendRequest {
                key: key.clone(),
                data: data.clone(),
            })
            .await
            .expect("append")
            .into_inner();

        assert_eq!(res.seq, i, "seq must be 0-based and gap-free");
        // Server hashes the data field per docs/wire-format.md.
        assert_eq!(
            res.leaf_hash.as_slice(),
            leaf_hash(&data),
            "server-returned leaf_hash must match settled-core::leaf_hash",
        );
    }
}

#[tokio::test]
async fn get_round_trips_data_unchanged() {
    let (_addr, _tmp, mut client) = boot().await;

    let payloads: Vec<Vec<u8>> = (0..20)
        .map(|i| format!("entry-{i}").into_bytes())
        .collect();

    for p in &payloads {
        client
            .append(AppendRequest {
                key: b"k".to_vec(),
                data: p.clone(),
            })
            .await
            .expect("append");
    }

    for (i, expected) in payloads.iter().enumerate() {
        let got = client
            .get(GetRequest { seq: i as u64 })
            .await
            .expect("get")
            .into_inner();
        let entry = got.entry.expect("entry present");
        assert_eq!(entry.seq, i as u64);
        assert_eq!(entry.data, *expected, "data must round-trip unchanged");
    }
}

#[tokio::test]
async fn get_unknown_seq_returns_not_found() {
    let (_addr, _tmp, mut client) = boot().await;

    let err = client
        .get(GetRequest { seq: 99_999 })
        .await
        .expect_err("expected NotFound");
    assert_eq!(err.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn concurrent_appends_have_unique_gap_free_seqs() {
    let (addr, _tmp, _seed) = boot().await;
    const N: u64 = 100;

    // Each task connects its own client to exercise real concurrent paths.
    let mut set = JoinSet::new();
    for i in 0..N {
        let endpoint = format!("http://{addr}");
        set.spawn(async move {
            let mut c = SettledLogClient::connect(endpoint).await.unwrap();
            let res = c
                .append(AppendRequest {
                    key: b"k".to_vec(),
                    data: format!("d-{i}").into_bytes(),
                })
                .await
                .unwrap()
                .into_inner();
            res.seq
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
    let (_addr, _tmp, mut client) = boot().await;

    // Append "p-0" .. "p-9".
    for i in 0..10u64 {
        client
            .append(AppendRequest {
                key: b"k".to_vec(),
                data: format!("p-{i}").into_bytes(),
            })
            .await
            .expect("append");
    }

    // n = 5 → newest 5 in newest-first order.
    let res = client
        .get_latest(GetLatestRequest { n: 5 })
        .await
        .expect("get_latest")
        .into_inner();
    assert_eq!(res.entries.len(), 5);
    let seqs: Vec<u64> = res.entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, vec![9, 8, 7, 6, 5], "newest-first ordering");
    assert_eq!(res.entries[0].data, b"p-9");

    // n = 0 → server treats as 1 (the single newest entry).
    let res = client
        .get_latest(GetLatestRequest { n: 0 })
        .await
        .expect("get_latest")
        .into_inner();
    assert_eq!(res.entries.len(), 1);
    assert_eq!(res.entries[0].seq, 9);

    // n exceeds the log size → returns whatever exists, no error.
    let res = client
        .get_latest(GetLatestRequest { n: 1000 })
        .await
        .expect("get_latest")
        .into_inner();
    assert_eq!(res.entries.len(), 10);
    assert_eq!(res.entries[0].seq, 9, "still newest-first");
    assert_eq!(res.entries.last().unwrap().seq, 0);
}

#[tokio::test]
async fn get_latest_on_empty_log_returns_no_entries() {
    let (_addr, _tmp, mut client) = boot().await;

    let res = client
        .get_latest(GetLatestRequest { n: 5 })
        .await
        .expect("get_latest")
        .into_inner();
    assert!(res.entries.is_empty(), "empty log must return no entries");
}

#[tokio::test]
async fn signed_tree_head_signature_verifies() {
    let (_addr, _tmp, mut client) = boot().await;

    // Need at least one entry so the STH task signs something.
    for i in 0..10u64 {
        client
            .append(AppendRequest {
                key: b"k".to_vec(),
                data: format!("d-{i}").into_bytes(),
            })
            .await
            .expect("append");
    }

    let sth = wait_for_sth(&mut client, 10).await;

    let pk = VerifyingKey::from_bytes(&to_array_32(&sth.public_key))
        .expect("valid public key");
    let sig = Signature::from_slice(&sth.signature).expect("64-byte signature");
    let root = to_array_32(&sth.root_hash);

    assert!(
        sth::verify_tree_head(&pk, sth.tree_size, &root, sth.timestamp_ns, &sig),
        "STH signature must verify with embedded public key",
    );

    // Negative: tampering with any signed field must invalidate the signature.
    assert!(
        !sth::verify_tree_head(&pk, sth.tree_size + 1, &root, sth.timestamp_ns, &sig),
        "tampered tree_size must fail verification",
    );
    let mut bad_root = root;
    bad_root[0] ^= 0x01;
    assert!(
        !sth::verify_tree_head(&pk, sth.tree_size, &bad_root, sth.timestamp_ns, &sig),
        "tampered root must fail verification",
    );
}

#[tokio::test]
async fn inclusion_proof_verifies_against_settled_core() {
    let (_addr, _tmp, mut client) = boot().await;

    let n: u64 = 30;
    let mut leaf_hashes = Vec::with_capacity(n as usize);
    for i in 0..n {
        let data = format!("entry-{i}").into_bytes();
        let res = client
            .append(AppendRequest {
                key: b"k".to_vec(),
                data: data.clone(),
            })
            .await
            .expect("append")
            .into_inner();
        leaf_hashes.push(to_array_32(&res.leaf_hash));
    }

    // STH must cover all entries before we can request proofs at tree_size = 0.
    let sth = wait_for_sth(&mut client, n).await;
    let root = to_array_32(&sth.root_hash);

    // Verify a proof for every single entry, not just a sample. Catches
    // any off-by-one in the path-construction code that a sampled test
    // might miss.
    for i in 0..n {
        let res = client
            .inclusion_proof(InclusionProofRequest {
                seq: i,
                tree_size: sth.tree_size,
            })
            .await
            .expect("inclusion_proof")
            .into_inner();

        let path: Vec<[u8; 32]> = res.proof.iter().map(|p| to_array_32(p)).collect();

        assert!(
            proof::verify_inclusion(
                &leaf_hashes[i as usize],
                i,
                sth.tree_size,
                &path,
                &root,
            ),
            "inclusion proof for seq {i} must verify",
        );
    }
}

#[tokio::test]
async fn consistency_proof_between_two_sths_verifies() {
    let (_addr, _tmp, mut client) = boot().await;

    // Build a tree of size 20, capture the STH.
    for i in 0..20u64 {
        client
            .append(AppendRequest {
                key: b"k".to_vec(),
                data: format!("first-{i}").into_bytes(),
            })
            .await
            .expect("append");
    }
    let sth_old = wait_for_sth(&mut client, 20).await;

    // Grow to 50, capture the new STH.
    for i in 20..50u64 {
        client
            .append(AppendRequest {
                key: b"k".to_vec(),
                data: format!("second-{i}").into_bytes(),
            })
            .await
            .expect("append");
    }
    let sth_new = wait_for_sth(&mut client, 50).await;

    let res = client
        .consistency_proof(ConsistencyProofRequest {
            old_size: sth_old.tree_size,
            new_size: sth_new.tree_size,
        })
        .await
        .expect("consistency_proof")
        .into_inner();

    let path: Vec<[u8; 32]> = res.proof.iter().map(|p| to_array_32(p)).collect();

    assert!(
        proof::verify_consistency(
            sth_old.tree_size,
            sth_new.tree_size,
            &path,
            &to_array_32(&sth_old.root_hash),
            &to_array_32(&sth_new.root_hash),
        ),
        "consistency proof between two real STHs must verify",
    );
}


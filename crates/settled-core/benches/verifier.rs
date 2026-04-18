use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use settled_core::hash::{leaf_hash, node_hash};
use settled_core::proof::{inclusion_proof, consistency_proof, verify_consistency, verify_inclusion};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
        .collect()
}

fn tree_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    settled_core::merkle::mth(leaves).unwrap()
}

// ── Hashing ───────────────────────────────────────────────────────────────────

fn bench_hashing(c: &mut Criterion) {
    let data = [0x42u8; 64];
    let left = [0xaau8; 32];
    let right = [0xbbu8; 32];

    let mut g = c.benchmark_group("hashing");
    g.throughput(Throughput::Elements(1));

    g.bench_function("leaf_hash/64B", |b| {
        b.iter(|| leaf_hash(black_box(&data)))
    });

    g.bench_function("node_hash", |b| {
        b.iter(|| node_hash(black_box(&left), black_box(&right)))
    });

    g.finish();
}

// ── Inclusion proof verification ──────────────────────────────────────────────

fn bench_verify_inclusion(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify_inclusion");
    g.throughput(Throughput::Elements(1));

    for size in [8usize, 64, 512, 1024] {
        let leaves = make_leaves(size);
        let root = tree_root(&leaves);
        // Proof for the middle leaf (deepest path in most cases).
        let idx = size / 2;
        let proof = inclusion_proof(&leaves, idx).unwrap();

        g.bench_with_input(BenchmarkId::new("tree_size", size), &size, |b, _| {
            b.iter(|| {
                verify_inclusion(
                    black_box(&leaves[idx]),
                    black_box(idx as u64),
                    black_box(size as u64),
                    black_box(&proof),
                    black_box(&root),
                )
            })
        });
    }

    g.finish();
}

// ── Consistency proof verification ────────────────────────────────────────────

fn bench_verify_consistency(c: &mut Criterion) {
    let mut g = c.benchmark_group("verify_consistency");
    g.throughput(Throughput::Elements(1));

    // (old_size, new_size) pairs — representative transitions.
    let cases: &[(usize, usize)] = &[
        (1, 2),
        (4, 8),
        (7, 8),
        (64, 128),
        (512, 1024),
    ];

    for &(old, new) in cases {
        let leaves = make_leaves(new);
        let old_root = tree_root(&leaves[..old]);
        let new_root = tree_root(&leaves);
        let proof = consistency_proof(&leaves, old).unwrap();
        let label = format!("{old}→{new}");

        g.bench_with_input(BenchmarkId::new("sizes", &label), &label, |b, _| {
            b.iter(|| {
                verify_consistency(
                    black_box(old as u64),
                    black_box(new as u64),
                    black_box(&proof),
                    black_box(&old_root),
                    black_box(&new_root),
                )
            })
        });
    }

    g.finish();
}

// ── Proof generation ──────────────────────────────────────────────────────────

fn bench_proof_generation(c: &mut Criterion) {
    let mut g = c.benchmark_group("proof_generation");
    g.throughput(Throughput::Elements(1));

    for size in [64usize, 1024] {
        let leaves = make_leaves(size);
        let idx = size / 2;

        g.bench_with_input(BenchmarkId::new("inclusion/tree_size", size), &size, |b, _| {
            b.iter(|| inclusion_proof(black_box(&leaves), black_box(idx)).unwrap())
        });

        g.bench_with_input(BenchmarkId::new("consistency/tree_size", size), &size, |b, _| {
            let old = size / 2;
            b.iter(|| consistency_proof(black_box(&leaves), black_box(old)).unwrap())
        });
    }

    g.finish();
}

criterion_group!(
    benches,
    bench_hashing,
    bench_verify_inclusion,
    bench_verify_consistency,
    bench_proof_generation,
);
criterion_main!(benches);

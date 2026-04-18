"""Test vector suite for the Settled Python SDK verifier."""
import json
from pathlib import Path

import pytest

from settled.verifier import (
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
    verify_tree_head,
)

VECTORS = Path(__file__).parent.parent.parent.parent / "test-vectors"


def load(name: str):
    return json.loads((VECTORS / name).read_text())


def h(s: str) -> bytes:
    return bytes.fromhex(s)


# ── Leaf hashes ───────────────────────────────────────────────────────────────

class TestLeafHash:
    @pytest.mark.parametrize("v", load("leaf-hashes.json"), ids=lambda v: v["description"])
    def test_vectors(self, v):
        assert leaf_hash(h(v["input_hex"])).hex() == v["hash_hex"]


# ── Node hashes ───────────────────────────────────────────────────────────────

class TestNodeHash:
    @pytest.mark.parametrize(
        "v", [v for v in load("node-hashes.json") if "hash_hex" in v],
        ids=lambda v: v["description"],
    )
    def test_vectors(self, v):
        assert node_hash(h(v["left_hex"]), h(v["right_hex"])).hex() == v["hash_hex"]

    def test_non_commutative(self):
        vectors = load("node-hashes.json")
        for v in vectors:
            if "swapped_hash_hex" in v:
                ab = node_hash(h(v["left_hex"]), h(v["right_hex"]))
                ba = node_hash(h(v["right_hex"]), h(v["left_hex"]))
                assert ab != ba
                assert ba.hex() == v["swapped_hash_hex"]


# ── Inclusion proofs ──────────────────────────────────────────────────────────

class TestVerifyInclusion:
    @pytest.mark.parametrize(
        "v", load("inclusion-proofs.json"),
        ids=lambda v: f"size={v['tree_size']} idx={v['leaf_index']}",
    )
    def test_valid(self, v):
        assert verify_inclusion(
            h(v["leaf_hash_hex"]),
            v["leaf_index"],
            v["tree_size"],
            [h(p) for p in v["proof_hex"]],
            h(v["root_hex"]),
        )

    def test_negative_cases(self):
        cases = load("negative-cases.json")
        for name, v in cases.items():
            if not name.startswith("inclusion_"):
                continue
            result = verify_inclusion(
                h(v["leaf_hash_hex"]),
                v["leaf_index"],
                v["tree_size"],
                [h(p) for p in v["proof_hex"]],
                h(v["root_hex"]),
            )
            assert result == v["expected_result"], f"negative case {name!r} failed"


# ── Consistency proofs ────────────────────────────────────────────────────────

class TestVerifyConsistency:
    @pytest.mark.parametrize(
        "v", load("consistency-proofs.json"),
        ids=lambda v: f"old={v['old_size']} new={v['new_size']}",
    )
    def test_valid(self, v):
        assert verify_consistency(
            v["old_size"],
            v["new_size"],
            [h(p) for p in v["proof_hex"]],
            h(v["old_root_hex"]),
            h(v["new_root_hex"]),
        )

    def test_negative_cases(self):
        cases = load("negative-cases.json")
        for name, v in cases.items():
            if not name.startswith("consistency_"):
                continue
            result = verify_consistency(
                v["old_size"],
                v["new_size"],
                [h(p) for p in v["proof_hex"]],
                h(v["old_root_hex"]),
                h(v["new_root_hex"]),
            )
            assert result == v["expected_result"], f"negative case {name!r} failed"


# ── Signed Tree Heads ─────────────────────────────────────────────────────────

class TestVerifyTreeHead:
    @pytest.mark.parametrize("v", load("signed-tree-heads.json"), ids=lambda v: v["description"])
    def test_valid(self, v):
        assert verify_tree_head(
            v["tree_size"],
            h(v["root_hash_hex"]),
            v["timestamp_ns"],
            h(v["signature_hex"]),
            h(v["public_key_hex"]),
        )

    @pytest.mark.parametrize("v", load("signed-tree-heads.json"), ids=lambda v: v["description"])
    def test_tampered_tree_size_fails(self, v):
        assert not verify_tree_head(
            v["tree_size"] + 1,
            h(v["root_hash_hex"]),
            v["timestamp_ns"],
            h(v["signature_hex"]),
            h(v["public_key_hex"]),
        )

    @pytest.mark.parametrize("v", load("signed-tree-heads.json"), ids=lambda v: v["description"])
    def test_tampered_root_fails(self, v):
        root = bytearray(h(v["root_hash_hex"]))
        root[0] ^= 0xFF
        assert not verify_tree_head(
            v["tree_size"],
            bytes(root),
            v["timestamp_ns"],
            h(v["signature_hex"]),
            h(v["public_key_hex"]),
        )

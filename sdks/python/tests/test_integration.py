"""End-to-end integration tests for the Python SDK.

These tests boot a real ``settled-server`` binary as a subprocess, talk
to it via the Python ``SettledClient``, and verify proofs locally with
the Python verifier. They close the loop between the Rust server and
the Python SDK end-to-end — exactly the kind of test that catches wire-
format drift (e.g. stale proto stubs).

Skipped automatically when:
  - ``cargo`` is not on PATH (so the test won't break headless CI that
    only has Python), or
  - the server binary cannot be built/found.

Run only the integration tests:    pytest -m integration
Skip the integration tests:        pytest -m "not integration"
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from contextlib import closing
from pathlib import Path

import pytest

from settled.client import SettledClient
from settled.verifier import verify_consistency, verify_inclusion, verify_tree_head

REPO_ROOT = Path(__file__).resolve().parents[3]
SERVER_BIN_DEBUG = REPO_ROOT / "target" / "debug" / "settled-server"
SERVER_BIN_RELEASE = REPO_ROOT / "target" / "release" / "settled-server"


pytestmark = pytest.mark.integration


# ─────────────────────────────────────────────────────────────────────────────
# Test harness
# ─────────────────────────────────────────────────────────────────────────────

def _find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _server_binary() -> Path:
    """Locate (or build) the settled-server binary.

    Prefers an existing artifact to keep test startup fast. Falls back to
    a debug ``cargo build`` if neither debug nor release artifact exists.
    """
    if SERVER_BIN_RELEASE.exists():
        return SERVER_BIN_RELEASE
    if SERVER_BIN_DEBUG.exists():
        return SERVER_BIN_DEBUG
    if shutil.which("cargo") is None:
        pytest.skip("cargo not on PATH; cannot build settled-server for integration test")
    subprocess.run(
        ["cargo", "build", "-p", "settled-server"],
        cwd=REPO_ROOT,
        check=True,
    )
    if not SERVER_BIN_DEBUG.exists():
        pytest.skip("cargo build succeeded but binary not found at expected path")
    return SERVER_BIN_DEBUG


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with closing(socket.create_connection((host, port), timeout=0.2)):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not start listening on {host}:{port} within {timeout}s")


@pytest.fixture
def live_server(tmp_path):
    """Spawn settled-server on an ephemeral port. Tears down on test exit."""
    binary = _server_binary()
    grpc_port = _find_free_port()
    admin_port = _find_free_port()
    data_dir = tmp_path / "data"

    proc = subprocess.Popen(
        [
            str(binary),
            "--data-dir", str(data_dir),
            "--listen", f"127.0.0.1:{grpc_port}",
            "--admin-listen", f"127.0.0.1:{admin_port}",
            "--sth-interval-secs", "1",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        try:
            _wait_for_port("127.0.0.1", grpc_port)
        except RuntimeError as e:
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            proc.kill()
            proc.wait()
            raise RuntimeError(f"{e}\nserver stderr:\n{stderr}") from None
        yield f"127.0.0.1:{grpc_port}"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _wait_for_sth(client: SettledClient, min_size: int, timeout: float = 5.0):
    """Poll GetSth(0) until the latest STH covers ``min_size`` entries."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sth = client.get_sth(0)
            if sth.tree_size >= min_size:
                return sth
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"no STH covering {min_size} entries within {timeout}s")


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_append_round_trips_via_grpc(live_server):
    with SettledClient(live_server) as c:
        for i in range(20):
            res = c.append(b"k", f"d-{i}".encode())
            assert res.seq == i, "server must assign monotonic seqs from 0"

        for i in range(20):
            entry = c.get(i)
            assert entry.seq == i
            assert entry.data == f"d-{i}".encode(), "data must round-trip unchanged"


def test_get_latest_returns_newest_first(live_server):
    with SettledClient(live_server) as c:
        for i in range(10):
            c.append(b"k", f"x-{i}".encode())

        latest = c.get_latest(5)
        assert [e.seq for e in latest] == [9, 8, 7, 6, 5]
        assert latest[0].data == b"x-9"

        # n=1 default behaviour
        single = c.get_latest()
        assert len(single) == 1
        assert single[0].seq == 9


def test_signed_tree_head_signature_verifies(live_server):
    with SettledClient(live_server) as c:
        for i in range(5):
            c.append(b"k", f"d-{i}".encode())

        sth = _wait_for_sth(c, 5)

        assert verify_tree_head(
            sth.tree_size, sth.root_hash, sth.timestamp_ns,
            sth.signature, sth.public_key,
        ), "STH signature must verify with the embedded public key"

        # Negative case: tampered root must fail.
        tampered = bytes([sth.root_hash[0] ^ 1]) + sth.root_hash[1:]
        assert not verify_tree_head(
            sth.tree_size, tampered, sth.timestamp_ns,
            sth.signature, sth.public_key,
        ), "tampered root must fail signature verification"


def test_inclusion_proof_verifies_against_python_verifier(live_server):
    """Server-generated proof must verify locally with the Python verifier.

    This is the critical end-to-end correctness test: it proves the
    server's gRPC wire format and the Python SDK's wire format agree.
    """
    with SettledClient(live_server) as c:
        leaves = []
        for i in range(15):
            res = c.append(b"k", f"e-{i}".encode())
            leaves.append(res.leaf_hash)

        sth = _wait_for_sth(c, 15)

        for i in range(15):
            proof = c.inclusion_proof(i, sth.tree_size)
            assert verify_inclusion(
                leaves[i], i, sth.tree_size, proof.proof, sth.root_hash,
            ), f"inclusion proof for seq {i} must verify"


def test_consistency_proof_between_two_sths_verifies(live_server):
    with SettledClient(live_server) as c:
        for i in range(10):
            c.append(b"k", f"a-{i}".encode())
        sth_old = _wait_for_sth(c, 10)

        for i in range(10, 25):
            c.append(b"k", f"b-{i}".encode())
        sth_new = _wait_for_sth(c, 25)

        cp = c.consistency_proof(sth_old.tree_size, sth_new.tree_size)

        assert verify_consistency(
            sth_old.tree_size, sth_new.tree_size,
            cp.proof, sth_old.root_hash, sth_new.root_hash,
        ), "consistency proof between two real STHs must verify"


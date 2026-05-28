#!/usr/bin/env python3
"""Cross-SDK interoperability test.

Starts a real settled-server, appends entries via the Python SDK, then
verifies those same entries using the Go, TypeScript, and Rust SDK verifiers.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

from settled.client import SettledClient

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER_BIN_DEBUG = REPO_ROOT / "target" / "debug" / "settled-server"
SERVER_BIN_RELEASE = REPO_ROOT / "target" / "release" / "settled-server"
N_ENTRIES = 10


def _find_free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _server_binary() -> Path:
    if SERVER_BIN_RELEASE.exists():
        return SERVER_BIN_RELEASE
    if SERVER_BIN_DEBUG.exists():
        return SERVER_BIN_DEBUG
    if shutil.which("cargo") is None:
        sys.exit("cargo not on PATH; cannot build settled-server")
    subprocess.run(
        ["cargo", "build", "--release", "-p", "settled-server"],
        cwd=REPO_ROOT,
        check=True,
    )
    if not SERVER_BIN_RELEASE.exists():
        sys.exit("cargo build succeeded but binary not found")
    return SERVER_BIN_RELEASE


def _wait_for_port(host: str, port: int, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with closing(socket.create_connection((host, port), timeout=0.2)):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"server did not start on {host}:{port} within {timeout}s")


def _wait_for_sth(client: SettledClient, min_size: int, timeout: float = 10.0):
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


def _collect_interop_data(addr: str) -> dict:
    with SettledClient(addr) as c:
        entries = []
        for i in range(N_ENTRIES):
            data = f"interop-{i}".encode()
            res = c.append(b"test", data)
            entries.append({
                "seq": res.seq,
                "data_hex": data.hex(),
                "leaf_hash_hex": res.leaf_hash.hex(),
            })

        sth = _wait_for_sth(c, N_ENTRIES)

        inclusion_proofs = []
        for entry in entries:
            proof = c.inclusion_proof(entry["seq"], sth.tree_size)
            inclusion_proofs.append({
                "seq": entry["seq"],
                "leaf_hash_hex": entry["leaf_hash_hex"],
                "proof_hex": [p.hex() for p in proof.proof],
            })

        return {
            "entries": entries,
            "sth": {
                "tree_size": sth.tree_size,
                "root_hash_hex": sth.root_hash.hex(),
                # Store as string too so TypeScript BigInt conversion is lossless.
                "timestamp_ns": sth.timestamp_ns,
                "timestamp_ns_str": str(sth.timestamp_ns),
                "signature_hex": sth.signature.hex(),
                "public_key_hex": sth.public_key.hex(),
                "key_version": sth.key_version,
            },
            "inclusion_proofs": inclusion_proofs,
        }


def main() -> int:
    binary = _server_binary()
    grpc_port = _find_free_port()
    admin_port = _find_free_port()

    with tempfile.TemporaryDirectory() as tmp:
        data_dir = Path(tmp) / "data"
        interop_file = Path(tmp) / "interop.json"

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
                raise RuntimeError(f"{e}\nserver stderr:\n{stderr}") from None

            interop_data = _collect_interop_data(f"127.0.0.1:{grpc_port}")
            interop_file.write_text(json.dumps(interop_data, indent=2))
            print(f"Interop data written to {interop_file}")
            print(f"  entries={len(interop_data['entries'])} tree_size={interop_data['sth']['tree_size']}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

        env = {**os.environ, "INTEROP_DATA": str(interop_file)}
        failures: list[str] = []

        print("\n── Go SDK ───────────────────────────────────────────────────")
        r = subprocess.run(
            ["go", "test", "./verifier/...", "-run", "TestInteropVerify", "-v"],
            cwd=REPO_ROOT / "sdks" / "go",
            env=env,
        )
        if r.returncode != 0:
            failures.append("Go")

        print("\n── TypeScript SDK ───────────────────────────────────────────")
        r = subprocess.run(
            ["npx", "vitest", "run", "tests/interop.test.ts"],
            cwd=REPO_ROOT / "sdks" / "typescript",
            env=env,
        )
        if r.returncode != 0:
            failures.append("TypeScript")

        if shutil.which("cargo"):
            print("\n── Rust SDK ─────────────────────────────────────────────────")
            r = subprocess.run(
                ["cargo", "test", "--test", "interop_test", "--", "--nocapture"],
                cwd=REPO_ROOT / "sdks" / "rust",
                env=env,
            )
            if r.returncode != 0:
                failures.append("Rust")

    if failures:
        print(f"\nINTEROP FAILED: {', '.join(failures)}", file=sys.stderr)
        return 1

    print("\nAll cross-SDK interop tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

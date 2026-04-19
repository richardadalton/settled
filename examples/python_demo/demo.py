#!/usr/bin/env python3
"""
Settled Python Demo

Usage:
    python demo.py                            # append demo entries + show log
    python demo.py --skip-append              # show existing log
    python demo.py --verify                   # append + verify STH + inclusion proofs
    python demo.py --verify --consistency     # also verify consistency before→after append
    python demo.py --get 3                    # look up a single entry by seq
    python demo.py --get 3 --verify           # look up + verify its inclusion proof
    python demo.py --watch                    # tail new entries as they arrive
    python demo.py --watch --verify           # tail + verify each new entry
"""

import argparse
import sys
import time
from datetime import datetime, timezone

from settled import SettledClient, verify_consistency, verify_inclusion, verify_tree_head


DEMO_ENTRIES = [
    ("user:alice",  "login"),
    ("order:1001",  "created"),
    ("order:1001",  "payment_received"),
    ("order:1001",  "shipped"),
    ("user:bob",    "login"),
    ("order:1002",  "created"),
]

COL_SEQ   = 4
COL_KEY   = 20
COL_DATA  = 20
COL_TIME  = 16
COL_HASH  = 18


def fmt_time(ts_ns: int) -> str:
    dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
    return dt.strftime("%H:%M:%S.%f")[:-3] + "Z"


def fmt_hash(h: bytes) -> str:
    return h.hex()[:16] + "…"


def decode(b: bytes | str) -> str:
    return b.decode() if isinstance(b, bytes) else b


def table_header(show_proof: bool = False) -> str:
    h = (
        f"{'Seq':>{COL_SEQ}}  {'Key':<{COL_KEY}}  {'Data':<{COL_DATA}}  "
        f"{'Time':>{COL_TIME}}  {'Leaf Hash':<{COL_HASH}}"
    )
    if show_proof:
        h += "  Proof"
    return h


def entry_row(e, proof_col: str = "") -> str:
    return (
        f"{e.seq:>{COL_SEQ}}  {decode(e.key):<{COL_KEY}}  {decode(e.data):<{COL_DATA}}  "
        f"{fmt_time(e.timestamp_ns):>{COL_TIME}}  {fmt_hash(e.leaf_hash):<{COL_HASH}}{proof_col}"
    )


def print_table(entries: list, verified: dict[int, bool] | None = None) -> None:
    show_proof = verified is not None
    header = table_header(show_proof)
    print(header)
    print("-" * len(header))
    for e in entries:
        proof_col = ""
        if show_proof:
            proof_col = "  OK" if verified.get(e.seq) else "  FAIL"
        print(entry_row(e, proof_col))


# ── Verification helpers ───────────────────────────────────────────────────────

def check_sth(sth) -> bool:
    print("Verifying STH signature … ", end="", flush=True)
    ok = verify_tree_head(
        sth.tree_size, sth.root_hash, sth.timestamp_ns, sth.signature, sth.public_key
    )
    print("OK" if ok else "FAIL")
    if not ok:
        print("  Warning: STH signature invalid — results below may not be trustworthy.")
    return ok


def check_inclusions(client: SettledClient, entries: list, sth) -> dict[int, bool]:
    n = len(entries)
    print(f"Verifying inclusion proof{'s' if n != 1 else ''} for {n} entr{'y' if n == 1 else 'ies'} … ", end="", flush=True)
    results: dict[int, bool] = {}
    for e in entries:
        p = client.inclusion_proof(e.seq, sth.tree_size)
        results[e.seq] = verify_inclusion(e.leaf_hash, p.leaf_index, p.tree_size, p.proof, sth.root_hash)
    all_ok = all(results.values())
    print("all OK" if all_ok else f"{sum(1 for v in results.values() if not v)} FAILED")
    return results


def check_consistency(client: SettledClient, old_sth, new_sth) -> None:
    print(
        f"Verifying consistency proof  {old_sth.tree_size} → {new_sth.tree_size} … ",
        end="", flush=True,
    )
    if old_sth.tree_size == new_sth.tree_size:
        print("nothing to prove (tree unchanged)")
        return
    p = client.consistency_proof(old_sth.tree_size, new_sth.tree_size)
    ok = verify_consistency(
        p.old_size, p.new_size, p.proof, old_sth.root_hash, new_sth.root_hash
    )
    print("OK" if ok else "FAIL")


# ── Modes ─────────────────────────────────────────────────────────────────────

def mode_get(client: SettledClient, seq: int, do_verify: bool) -> None:
    try:
        e = client.get(seq)
    except Exception as exc:
        print(f"Error fetching seq {seq}: {exc}")
        sys.exit(1)

    proof_col = ""
    if do_verify:
        sth = client.get_sth()
        check_sth(sth)
        p = client.inclusion_proof(seq, sth.tree_size)
        ok = verify_inclusion(e.leaf_hash, p.leaf_index, p.tree_size, p.proof, sth.root_hash)
        proof_col = "  OK" if ok else "  FAIL"
        print()

    header = table_header(do_verify)
    print(header)
    print("-" * len(header))
    print(entry_row(e, proof_col))


def mode_watch(client: SettledClient, do_verify: bool, interval: float) -> None:
    print(f"Watching for new entries (polling every {interval}s) … Ctrl-C to stop.\n")
    sth = client.get_sth()
    seq = sth.tree_size

    print(table_header(do_verify))
    print("-" * len(table_header(do_verify)))

    try:
        while True:
            sth = client.get_sth()
            while seq < sth.tree_size:
                e = client.get(seq)
                proof_col = ""
                if do_verify:
                    p = client.inclusion_proof(seq, sth.tree_size)
                    ok = verify_inclusion(e.leaf_hash, p.leaf_index, p.tree_size, p.proof, sth.root_hash)
                    proof_col = "  OK" if ok else "  FAIL"
                print(entry_row(e, proof_col))
                seq += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")


def mode_default(client: SettledClient, do_verify: bool, do_consistency: bool, skip_append: bool) -> None:
    old_sth = client.get_sth() if do_consistency else None

    if not skip_append:
        print("Appending demo entries …")
        for key, data in DEMO_ENTRIES:
            result = client.append(key.encode(), data.encode())
            print(f"  appended seq={result.seq}  key={key!r}  data={data!r}")
        print()

    sth = client.get_sth()
    if sth.tree_size == 0:
        print("Log is empty.")
        sys.exit(0)

    print("Fetching audit trail …\n")
    entries = [client.get(seq) for seq in range(sth.tree_size)]

    verified = None
    if do_verify:
        check_sth(sth)
        verified = check_inclusions(client, entries, sth)
        if do_consistency and old_sth is not None:
            check_consistency(client, old_sth, sth)
        print()

    print_table(entries, verified)
    print(f"\n{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} in log.")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Settled Python Demo")
    parser.add_argument("--host", default="localhost:50051")
    parser.add_argument("--skip-append", action="store_true", help="Skip appending demo entries")
    parser.add_argument("--verify", action="store_true", help="Verify STH + inclusion proofs")
    parser.add_argument("--consistency", action="store_true", help="Verify consistency proof before→after append (requires --verify)")
    parser.add_argument("--get", type=int, metavar="SEQ", help="Fetch a single entry by sequence number")
    parser.add_argument("--watch", action="store_true", help="Tail new entries as they arrive")
    parser.add_argument("--interval", type=float, default=2.0, metavar="SECS", help="Polling interval for --watch (default: 2)")
    args = parser.parse_args()

    print(f"Connecting to {args.host} …\n")

    with SettledClient(args.host) as client:
        if args.watch:
            mode_watch(client, args.verify, args.interval)
        elif args.get is not None:
            mode_get(client, args.get, args.verify)
        else:
            mode_default(client, args.verify, args.consistency, args.skip_append)


if __name__ == "__main__":
    main()

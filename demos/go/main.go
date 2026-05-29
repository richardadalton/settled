/*
 * Settled Go Demo
 *
 * Usage:
 *   go run .                              # append demo entries + show log
 *   go run . -skip-append                 # show existing log
 *   go run . -verify                      # append + verify STH + inclusion proofs
 *   go run . -verify -consistency         # also verify consistency before→after append
 *   go run . -get 3                       # look up a single entry by seq
 *   go run . -get 3 -verify               # look up + verify its inclusion proof
 *   go run . -key "user:alice"            # fetch all entries for a key (paginated)
 *   go run . -watch                       # tail new entries as they arrive
 *   go run . -watch -verify               # tail + verify each new entry
 *   go run . -host localhost:50051        # connect to a non-default address
 */
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/richardadalton/settled/sdks/go/client"
	"github.com/richardadalton/settled/sdks/go/verifier"
)

const (
	colSeq  = 4
	colKey  = 20
	colData = 20
	colTime = 20
	colHash = 18
)

func main() {
	host          := flag.String("host", "localhost:50051", "gRPC address of the settled-server")
	skipAppend    := flag.Bool("skip-append", false, "Skip appending demo entries")
	doVerify      := flag.Bool("verify", false, "Verify STH signature and inclusion proofs")
	doConsistency := flag.Bool("consistency", false, "Also verify consistency proof before→after append (requires -verify)")
	getSeq        := flag.Int64("get", -1, "Fetch a single entry by sequence number")
	keyFlag       := flag.String("key", "", "Fetch all entries for this key (paginated)")
	doWatch       := flag.Bool("watch", false, "Tail new entries as they arrive")
	interval      := flag.Float64("interval", 2.0, "Polling interval in seconds for -watch")
	flag.Parse()

	fmt.Printf("Connecting to %s …\n\n", *host)
	c, err := client.New(*host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()

	ctx := context.Background()

	switch {
	case *doWatch:
		modeWatch(ctx, c, *doVerify, *interval)
	case *getSeq >= 0:
		modeGet(ctx, c, uint64(*getSeq), *doVerify)
	case *keyFlag != "":
		modeGetByKey(ctx, c, *keyFlag)
	default:
		modeDefault(ctx, c, *doVerify, *doConsistency, *skipAppend)
	}
}

// ── Formatting ─────────────────────────────────────────────────────────────────

func fmtTime(tsNs int64) string {
	return time.Unix(0, tsNs).UTC().Format("15:04:05.000") + "Z"
}

func fmtHash(h []byte) string {
	return hex.EncodeToString(h)[:16] + "…"
}

func tableHeader(showProof bool) string {
	h := fmt.Sprintf("%*s  %-*s  %-*s  %-*s  %-*s",
		colSeq, "Seq",
		colKey, "Key",
		colData, "Data",
		colTime, "Time",
		colHash, "Leaf Hash",
	)
	if showProof {
		h += "  Proof"
	}
	return h
}

func entryRow(e client.Entry, proofCol string) string {
	return fmt.Sprintf("%*d  %-*s  %-*s  %-*s  %-*s%s",
		colSeq, e.Seq,
		colKey, string(e.Key),
		colData, string(e.Data),
		colTime, fmtTime(e.TimestampNs),
		colHash, fmtHash(e.LeafHash),
		proofCol,
	)
}

func printTable(entries []client.Entry, verified map[uint64]bool) {
	hdr := tableHeader(verified != nil)
	fmt.Println(hdr)
	fmt.Println(strings.Repeat("-", len(hdr)))
	for _, e := range entries {
		proofCol := ""
		if verified != nil {
			if verified[e.Seq] {
				proofCol = "  OK"
			} else {
				proofCol = "  FAIL"
			}
		}
		fmt.Println(entryRow(e, proofCol))
	}
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func to32(b []byte) [32]byte {
	var arr [32]byte
	copy(arr[:], b)
	return arr
}

func proofTo32(p [][]byte) [][32]byte {
	out := make([][32]byte, len(p))
	for i, h := range p {
		out[i] = to32(h)
	}
	return out
}

func waitForSth(ctx context.Context, c *client.SettledClient, minSize uint64) (*client.SignedTreeHead, error) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		sth, err := c.GetSth(ctx, 0)
		if err == nil && sth.TreeSize >= minSize {
			return sth, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("no STH covering %d entries within 10s", minSize)
}

func checkSth(ctx context.Context, c *client.SettledClient, minSize uint64) (*client.SignedTreeHead, error) {
	sth, err := waitForSth(ctx, c, minSize)
	if err != nil {
		return nil, err
	}
	fmt.Print("Verifying STH signature … ")
	ok := verifier.VerifyTreeHead(sth.TreeSize, to32(sth.RootHash), sth.TimestampNs, sth.Signature, sth.PublicKey)
	if ok {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL")
		fmt.Println("  Warning: STH signature invalid — results below may not be trustworthy.")
	}
	return sth, nil
}

func checkInclusions(ctx context.Context, c *client.SettledClient, entries []client.Entry, sth *client.SignedTreeHead) (map[uint64]bool, error) {
	noun := "entries"
	if len(entries) == 1 {
		noun = "entry"
	}
	fmt.Printf("Verifying inclusion proof for %d %s … ", len(entries), noun)
	results := make(map[uint64]bool, len(entries))
	for _, e := range entries {
		p, err := c.InclusionProof(ctx, e.Seq, sth.TreeSize)
		if err != nil {
			return nil, err
		}
		results[e.Seq] = verifier.VerifyInclusion(to32(e.LeafHash), p.LeafIndex, p.TreeSize, proofTo32(p.Proof), to32(sth.RootHash))
	}
	failed := 0
	for _, ok := range results {
		if !ok {
			failed++
		}
	}
	if failed == 0 {
		fmt.Println("all OK")
	} else {
		fmt.Printf("%d FAILED\n", failed)
	}
	return results, nil
}

func checkConsistency(ctx context.Context, c *client.SettledClient, oldSth, newSth *client.SignedTreeHead) error {
	fmt.Printf("Verifying consistency proof  %d → %d … ", oldSth.TreeSize, newSth.TreeSize)
	if oldSth.TreeSize == newSth.TreeSize {
		fmt.Println("nothing to prove (tree unchanged)")
		return nil
	}
	p, err := c.ConsistencyProof(ctx, oldSth.TreeSize, newSth.TreeSize)
	if err != nil {
		return err
	}
	ok := verifier.VerifyConsistency(p.OldSize, p.NewSize, proofTo32(p.Proof), to32(oldSth.RootHash), to32(newSth.RootHash))
	if ok {
		fmt.Println("OK")
	} else {
		fmt.Println("FAIL")
	}
	return nil
}

// ── Modes ───────────────────────────────────────────────────────────────────

func modeGet(ctx context.Context, c *client.SettledClient, seq uint64, doVerify bool) {
	e, err := c.Get(ctx, seq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching seq %d: %v\n", seq, err)
		return
	}

	proofCol := ""
	if doVerify {
		sth, err := checkSth(ctx, c, seq+1)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		p, err := c.InclusionProof(ctx, seq, sth.TreeSize)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		ok := verifier.VerifyInclusion(to32(e.LeafHash), p.LeafIndex, p.TreeSize, proofTo32(p.Proof), to32(sth.RootHash))
		if ok {
			proofCol = "  OK"
		} else {
			proofCol = "  FAIL"
		}
		fmt.Println()
	}

	hdr := tableHeader(doVerify)
	fmt.Println(hdr)
	fmt.Println(strings.Repeat("-", len(hdr)))
	fmt.Println(entryRow(*e, proofCol))
}

func modeWatch(ctx context.Context, c *client.SettledClient, doVerify bool, intervalSecs float64) {
	fmt.Printf("Watching for new entries (polling every %.0fs) … Ctrl-C to stop.\n\n", intervalSecs)

	var seq uint64
	if sth, err := waitForSth(ctx, c, 1); err == nil {
		seq = sth.TreeSize
	}

	hdr := tableHeader(doVerify)
	fmt.Println(hdr)
	fmt.Println(strings.Repeat("-", len(hdr)))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	tick := time.NewTicker(time.Duration(float64(time.Second) * intervalSecs))
	defer tick.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Println("\nStopped.")
			return
		case <-tick.C:
			sth, err := waitForSth(ctx, c, 1)
			if err != nil {
				continue
			}
			for seq < sth.TreeSize {
				e, err := c.Get(ctx, seq)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n", err)
					break
				}
				proofCol := ""
				if doVerify {
					p, err := c.InclusionProof(ctx, seq, sth.TreeSize)
					if err == nil {
						ok := verifier.VerifyInclusion(to32(e.LeafHash), p.LeafIndex, p.TreeSize, proofTo32(p.Proof), to32(sth.RootHash))
						if ok {
							proofCol = "  OK"
						} else {
							proofCol = "  FAIL"
						}
					}
				}
				fmt.Println(entryRow(*e, proofCol))
				seq++
			}
		}
	}
}

func modeGetByKey(ctx context.Context, c *client.SettledClient, key string) {
	var all []client.Entry
	var cursor uint64
	for {
		res, err := c.GetByKey(ctx, []byte(key), cursor, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return
		}
		all = append(all, res.Entries...)
		if res.NextCursor == 0 {
			break
		}
		cursor = res.NextCursor
	}

	noun := "entries"
	if len(all) == 1 {
		noun = "entry"
	}
	fmt.Printf("%d %s for key %q:\n\n", len(all), noun, key)

	hdr := tableHeader(false)
	fmt.Println(hdr)
	fmt.Println(strings.Repeat("-", len(hdr)))
	for _, e := range all {
		fmt.Println(entryRow(e, ""))
	}
}

func modeDefault(ctx context.Context, c *client.SettledClient, doVerify, doConsistency, skipAppend bool) {
	demoEntries := [][2]string{
		{"user:alice", "login"},
		{"order:1001", "created"},
		{"order:1001", "payment_received"},
		{"order:1001", "shipped"},
		{"user:bob", "login"},
		{"order:1002", "created"},
	}

	var oldSth *client.SignedTreeHead
	if doConsistency {
		if s, err := waitForSth(ctx, c, 1); err == nil {
			oldSth = s
		}
	}

	if !skipAppend {
		fmt.Println("Appending demo entries …")
		for _, kv := range demoEntries {
			res, err := c.Append(ctx, []byte(kv[0]), []byte(kv[1]))
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				return
			}
			fmt.Printf("  appended seq=%d  key=%s  data=%s\n", res.Seq, kv[0], kv[1])
		}
		fmt.Println()
	}

	sth, err := waitForSth(ctx, c, 1)
	if err != nil {
		fmt.Println("Log is empty.")
		return
	}

	fmt.Println("Fetching audit trail …\n")
	entries := make([]client.Entry, 0, sth.TreeSize)
	for s := uint64(0); s < sth.TreeSize; s++ {
		e, err := c.Get(ctx, s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return
		}
		entries = append(entries, *e)
	}

	var verified map[uint64]bool
	if doVerify {
		sth, err = checkSth(ctx, c, sth.TreeSize)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		verified, err = checkInclusions(ctx, c, entries, sth)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if doConsistency && oldSth != nil {
			if err := checkConsistency(ctx, c, oldSth, sth); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}
		fmt.Println()
	}

	printTable(entries, verified)
	noun := "entries"
	if len(entries) == 1 {
		noun = "entry"
	}
	fmt.Printf("\n%d %s in log.\n", len(entries), noun)
}

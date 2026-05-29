// End-to-end integration tests for the Go SDK.
//
// Boots a real settled-server subprocess on an ephemeral port, talks
// to it via the Go SettledClient over real gRPC, and verifies proofs
// locally using the Go verifier package.
//
// Skipped when:
//   - testing.Short() is set, or
//   - target/{debug,release}/settled-server is not built.
//
// Run only:    go test ./client -run Integration
// Skip:        go test -short ./...
package client_test

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/richardadalton/settled/sdks/go/client"
	"github.com/richardadalton/settled/sdks/go/verifier"
)

// ── Test harness ────────────────────────────────────────────────────────────

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// .../sdks/go/client/integration_test.go → repo root is 3 levels up
	// (file dir is .../sdks/go/client).
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func findServerBinary(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	for _, p := range []string{
		filepath.Join(root, "target", "release", "settled-server"),
		filepath.Join(root, "target", "debug", "settled-server"),
	} {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	t.Skip("settled-server binary not built; run `cargo build -p settled-server` from the repo root")
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return &net.OpError{Op: "dial", Err: syscall.ETIMEDOUT}
}

// startServer spawns settled-server on an ephemeral port. Returns the
// gRPC address. Cleanup is registered with t.Cleanup.
func startServer(t *testing.T) string {
	t.Helper()

	if testing.Short() {
		t.Skip("integration test skipped under -short")
	}

	binary := findServerBinary(t)
	grpcPort := freePort(t)
	adminPort := freePort(t)
	dataDir := t.TempDir()

	cmd := exec.Command(
		binary,
		"--data-dir", dataDir,
		"--listen", "127.0.0.1:"+strconv.Itoa(grpcPort),
		"--admin-listen", "127.0.0.1:"+strconv.Itoa(adminPort),
		"--sth-interval-secs", "1",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	cmd.Stdout = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}

	addr := "127.0.0.1:" + strconv.Itoa(grpcPort)
	if err := waitForPort(addr, 15*time.Second); err != nil {
		buf := make([]byte, 4096)
		n, _ := stderr.Read(buf)
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		t.Fatalf("server did not start: %v\nstderr:\n%s", err, buf[:n])
	}

	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	return addr
}

func waitForSth(t *testing.T, c *client.SettledClient, minSize uint64) *client.SignedTreeHead {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		sth, err := c.GetSth(ctx, 0)
		cancel()
		if err == nil && sth.TreeSize >= minSize {
			return sth
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no STH covering %d entries within 5s", minSize)
	return nil
}

func to32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

func proofTo32s(p [][]byte) [][32]byte {
	out := make([][32]byte, len(p))
	for i, b := range p {
		out[i] = to32(b)
	}
	return out
}

// ── Tests ───────────────────────────────────────────────────────────────────

func TestIntegration_AppendGetRoundTrip(t *testing.T) {
	addr := startServer(t)
	c, err := client.New(addr)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()
	ctx := context.Background()

	for i := uint64(0); i < 20; i++ {
		res, err := c.Append(ctx, []byte("k"), []byte("d-"+strconv.FormatUint(i, 10)))
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if res.Seq != i {
			t.Fatalf("seq: got %d want %d", res.Seq, i)
		}
	}

	for i := uint64(0); i < 20; i++ {
		entry, err := c.Get(ctx, i)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		want := "d-" + strconv.FormatUint(i, 10)
		if string(entry.Data) != want {
			t.Fatalf("data: got %q want %q", entry.Data, want)
		}
	}
}

func TestIntegration_GetLatestNewestFirst(t *testing.T) {
	addr := startServer(t)
	c, _ := client.New(addr)
	defer c.Close()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_, err := c.Append(ctx, []byte("k"), []byte("x-"+strconv.Itoa(i)))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	got, err := c.GetLatest(ctx, 5)
	if err != nil {
		t.Fatalf("get_latest: %v", err)
	}
	want := []uint64{9, 8, 7, 6, 5}
	if len(got.Entries) != len(want) {
		t.Fatalf("len: got %d want %d", len(got.Entries), len(want))
	}
	if got.TotalAvailable != 10 {
		t.Fatalf("total_available: got %d want 10", got.TotalAvailable)
	}
	for i, e := range got.Entries {
		if e.Seq != want[i] {
			t.Fatalf("seqs[%d]: got %d want %d", i, e.Seq, want[i])
		}
	}
	if string(got.Entries[0].Data) != "x-9" {
		t.Fatalf("newest data: got %q", got.Entries[0].Data)
	}

	// n=0 → server clamps to 1 (single newest entry).
	one, err := c.GetLatest(ctx, 0)
	if err != nil {
		t.Fatalf("get_latest(0): %v", err)
	}
	if len(one.Entries) != 1 || one.Entries[0].Seq != 9 {
		t.Fatalf("n=0 should return [9], got %+v", one)
	}
}

func TestIntegration_SignedTreeHeadVerifies(t *testing.T) {
	addr := startServer(t)
	c, _ := client.New(addr)
	defer c.Close()
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := c.Append(ctx, []byte("k"), []byte("d-"+strconv.Itoa(i)))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	sth := waitForSth(t, c, 5)

	if !verifier.VerifyTreeHead(sth.TreeSize, to32(sth.RootHash), sth.TimestampNs, sth.Signature, sth.PublicKey) {
		t.Fatal("STH signature must verify")
	}

	// Negative: tampered root.
	tampered := make([]byte, 32)
	copy(tampered, sth.RootHash)
	tampered[0] ^= 1
	if verifier.VerifyTreeHead(sth.TreeSize, to32(tampered), sth.TimestampNs, sth.Signature, sth.PublicKey) {
		t.Fatal("tampered root must fail verification")
	}
}

func TestIntegration_InclusionProofVerifiesAgainstVerifier(t *testing.T) {
	addr := startServer(t)
	c, _ := client.New(addr)
	defer c.Close()
	ctx := context.Background()

	const N = 15
	leaves := make([][32]byte, N)
	for i := 0; i < N; i++ {
		res, err := c.Append(ctx, []byte("k"), []byte("e-"+strconv.Itoa(i)))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		leaves[i] = to32(res.LeafHash)
	}

	sth := waitForSth(t, c, N)
	root := to32(sth.RootHash)

	for i := uint64(0); i < N; i++ {
		ip, err := c.InclusionProof(ctx, i, sth.TreeSize)
		if err != nil {
			t.Fatalf("inclusion_proof(%d): %v", i, err)
		}
		ok := verifier.VerifyInclusion(leaves[i], i, sth.TreeSize, proofTo32s(ip.Proof), root)
		if !ok {
			t.Fatalf("inclusion proof for seq %d must verify", i)
		}
	}
}

func TestIntegration_ConsistencyProofVerifies(t *testing.T) {
	addr := startServer(t)
	c, _ := client.New(addr)
	defer c.Close()
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		_, _ = c.Append(ctx, []byte("k"), []byte("a-"+strconv.Itoa(i)))
	}
	sthOld := waitForSth(t, c, 10)

	for i := 10; i < 25; i++ {
		_, _ = c.Append(ctx, []byte("k"), []byte("b-"+strconv.Itoa(i)))
	}
	sthNew := waitForSth(t, c, 25)

	cp, err := c.ConsistencyProof(ctx, sthOld.TreeSize, sthNew.TreeSize)
	if err != nil {
		t.Fatalf("consistency_proof: %v", err)
	}
	ok := verifier.VerifyConsistency(
		sthOld.TreeSize, sthNew.TreeSize,
		proofTo32s(cp.Proof),
		to32(sthOld.RootHash), to32(sthNew.RootHash),
	)
	if !ok {
		t.Fatal("consistency proof between two real STHs must verify")
	}
}


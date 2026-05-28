package verifier_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/richardadalton/settled/sdks/go/verifier"
)

func vectorsDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "../../../test-vectors")
}

func loadJSON(name string) []byte {
	data, err := os.ReadFile(filepath.Join(vectorsDir(), name))
	if err != nil {
		panic(fmt.Sprintf("cannot read %s: %v", name, err))
	}
	return data
}

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func b32(s string) [32]byte {
	var out [32]byte
	copy(out[:], h(s))
	return out
}

func proofs(hexes []string) [][32]byte {
	out := make([][32]byte, len(hexes))
	for i, s := range hexes {
		out[i] = b32(s)
	}
	return out
}

// ── Leaf hashes ───────────────────────────────────────────────────────────────

func TestLeafHash(t *testing.T) {
	var vectors []struct {
		Description string `json:"description"`
		InputHex    string `json:"input_hex"`
		HashHex     string `json:"hash_hex"`
	}
	json.Unmarshal(loadJSON("leaf-hashes.json"), &vectors)

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			got := verifier.LeafHash(h(v.InputHex))
			if hex.EncodeToString(got[:]) != v.HashHex {
				t.Fatalf("got %x, want %s", got, v.HashHex)
			}
		})
	}
}

// ── Node hashes ───────────────────────────────────────────────────────────────

func TestNodeHash(t *testing.T) {
	var vectors []struct {
		Description    string `json:"description"`
		LeftHex        string `json:"left_hex"`
		RightHex       string `json:"right_hex"`
		HashHex        string `json:"hash_hex"`
		SwappedHashHex string `json:"swapped_hash_hex"`
	}
	json.Unmarshal(loadJSON("node-hashes.json"), &vectors)

	for _, v := range vectors {
		v := v
		if v.HashHex != "" {
			t.Run(v.Description, func(t *testing.T) {
				got := verifier.NodeHash(b32(v.LeftHex), b32(v.RightHex))
				if hex.EncodeToString(got[:]) != v.HashHex {
					t.Fatalf("got %x, want %s", got, v.HashHex)
				}
			})
		}
		if v.SwappedHashHex != "" {
			t.Run(v.Description+" non-commutative", func(t *testing.T) {
				ab := verifier.NodeHash(b32(v.LeftHex), b32(v.RightHex))
				ba := verifier.NodeHash(b32(v.RightHex), b32(v.LeftHex))
				if ab == ba {
					t.Fatal("node_hash must not be commutative")
				}
				if hex.EncodeToString(ba[:]) != v.SwappedHashHex {
					t.Fatalf("swapped: got %x, want %s", ba, v.SwappedHashHex)
				}
			})
		}
	}
}

// ── Inclusion proofs ──────────────────────────────────────────────────────────

func TestVerifyInclusion(t *testing.T) {
	var vectors []struct {
		TreeSize    uint64   `json:"tree_size"`
		LeafIndex   uint64   `json:"leaf_index"`
		LeafHashHex string   `json:"leaf_hash_hex"`
		ProofHex    []string `json:"proof_hex"`
		RootHex     string   `json:"root_hex"`
	}
	json.Unmarshal(loadJSON("inclusion-proofs.json"), &vectors)

	for _, v := range vectors {
		v := v
		t.Run(fmt.Sprintf("size=%d idx=%d", v.TreeSize, v.LeafIndex), func(t *testing.T) {
			ok := verifier.VerifyInclusion(b32(v.LeafHashHex), v.LeafIndex, v.TreeSize, proofs(v.ProofHex), b32(v.RootHex))
			if !ok {
				t.Fatal("verify_inclusion returned false")
			}
		})
	}
}

// ── Consistency proofs ────────────────────────────────────────────────────────

func TestVerifyConsistency(t *testing.T) {
	var vectors []struct {
		OldSize    uint64   `json:"old_size"`
		NewSize    uint64   `json:"new_size"`
		OldRootHex string   `json:"old_root_hex"`
		NewRootHex string   `json:"new_root_hex"`
		ProofHex   []string `json:"proof_hex"`
	}
	json.Unmarshal(loadJSON("consistency-proofs.json"), &vectors)

	for _, v := range vectors {
		v := v
		t.Run(fmt.Sprintf("old=%d new=%d", v.OldSize, v.NewSize), func(t *testing.T) {
			ok := verifier.VerifyConsistency(v.OldSize, v.NewSize, proofs(v.ProofHex), b32(v.OldRootHex), b32(v.NewRootHex))
			if !ok {
				t.Fatal("verify_consistency returned false")
			}
		})
	}
}

// ── Signed Tree Heads ─────────────────────────────────────────────────────────

func TestVerifyTreeHead(t *testing.T) {
	var vectors []struct {
		Description  string `json:"description"`
		TreeSize     uint64 `json:"tree_size"`
		RootHashHex  string `json:"root_hash_hex"`
		TimestampNs  int64  `json:"timestamp_ns"`
		SignatureHex string `json:"signature_hex"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	json.Unmarshal(loadJSON("signed-tree-heads.json"), &vectors)

	for _, v := range vectors {
		v := v
		t.Run(v.Description, func(t *testing.T) {
			ok := verifier.VerifyTreeHead(v.TreeSize, b32(v.RootHashHex), v.TimestampNs, h(v.SignatureHex), h(v.PublicKeyHex))
			if !ok {
				t.Fatal("verify_tree_head returned false")
			}
		})
		t.Run(v.Description+" tampered tree_size fails", func(t *testing.T) {
			ok := verifier.VerifyTreeHead(v.TreeSize+1, b32(v.RootHashHex), v.TimestampNs, h(v.SignatureHex), h(v.PublicKeyHex))
			if ok {
				t.Fatal("expected false for tampered tree_size")
			}
		})
		t.Run(v.Description+" tampered root fails", func(t *testing.T) {
			root := b32(v.RootHashHex)
			root[0] ^= 0xFF
			ok := verifier.VerifyTreeHead(v.TreeSize, root, v.TimestampNs, h(v.SignatureHex), h(v.PublicKeyHex))
			if ok {
				t.Fatal("expected false for tampered root")
			}
		})
	}
}

// ── Sequential STH verification ───────────────────────────────────────────────

func TestVerifyTreeHeadSequential(t *testing.T) {
	var vectors []struct {
		Description  string `json:"description"`
		TreeSize     uint64 `json:"tree_size"`
		RootHashHex  string `json:"root_hash_hex"`
		TimestampNs  int64  `json:"timestamp_ns"`
		SignatureHex string `json:"signature_hex"`
		PublicKeyHex string `json:"public_key_hex"`
	}
	json.Unmarshal(loadJSON("signed-tree-heads.json"), &vectors)

	// Consecutive pairs must pass (timestamps are strictly increasing).
	for i := 0; i+1 < len(vectors); i++ {
		prev, curr := vectors[i], vectors[i+1]
		name := fmt.Sprintf("%s after %s", curr.Description, prev.Description)
		t.Run(name, func(t *testing.T) {
			ok := verifier.VerifyTreeHeadSequential(
				curr.TreeSize, b32(curr.RootHashHex), curr.TimestampNs,
				h(curr.SignatureHex), h(curr.PublicKeyHex), prev.TimestampNs,
			)
			if !ok {
				t.Fatal("expected true for sequential pair")
			}
		})
	}

	// Equal timestamp must fail.
	v := vectors[0]
	t.Run("equal timestamp fails", func(t *testing.T) {
		ok := verifier.VerifyTreeHeadSequential(
			v.TreeSize, b32(v.RootHashHex), v.TimestampNs,
			h(v.SignatureHex), h(v.PublicKeyHex), v.TimestampNs,
		)
		if ok {
			t.Fatal("expected false for equal timestamp")
		}
	})
}

// ── Negative cases ────────────────────────────────────────────────────────────

func TestNegativeCases(t *testing.T) {
	var cases map[string]struct {
		LeafHashHex         string   `json:"leaf_hash_hex"`
		LeafIndex           uint64   `json:"leaf_index"`
		TreeSize            uint64   `json:"tree_size"`
		ProofHex            []string `json:"proof_hex"`
		RootHex             string   `json:"root_hex"`
		OldSize             uint64   `json:"old_size"`
		NewSize             uint64   `json:"new_size"`
		OldRootHex          string   `json:"old_root_hex"`
		NewRootHex          string   `json:"new_root_hex"`
		RootHashHex         string   `json:"root_hash_hex"`
		TimestampNs         int64    `json:"timestamp_ns"`
		SignatureHex        string   `json:"signature_hex"`
		PublicKeyHex        string   `json:"public_key_hex"`
		PreviousTimestampNs int64    `json:"previous_timestamp_ns"`
		ExpectedResult      bool     `json:"expected_result"`
	}
	json.Unmarshal(loadJSON("negative-cases.json"), &cases)

	for name, v := range cases {
		name, v := name, v
		if len(name) > 10 && name[:10] == "inclusion_" {
			t.Run(name, func(t *testing.T) {
				got := verifier.VerifyInclusion(b32(v.LeafHashHex), v.LeafIndex, v.TreeSize, proofs(v.ProofHex), b32(v.RootHex))
				if got != v.ExpectedResult {
					t.Fatalf("got %v, want %v", got, v.ExpectedResult)
				}
			})
		} else if len(name) > 12 && name[:12] == "consistency_" {
			t.Run(name, func(t *testing.T) {
				got := verifier.VerifyConsistency(v.OldSize, v.NewSize, proofs(v.ProofHex), b32(v.OldRootHex), b32(v.NewRootHex))
				if got != v.ExpectedResult {
					t.Fatalf("got %v, want %v", got, v.ExpectedResult)
				}
			})
		} else if len(name) > 21 && name[:21] == "tree_head_sequential_" {
			t.Run(name, func(t *testing.T) {
				got := verifier.VerifyTreeHeadSequential(
					v.TreeSize, b32(v.RootHashHex), v.TimestampNs,
					h(v.SignatureHex), h(v.PublicKeyHex), v.PreviousTimestampNs,
				)
				if got != v.ExpectedResult {
					t.Fatalf("got %v, want %v", got, v.ExpectedResult)
				}
			})
		}
	}
}

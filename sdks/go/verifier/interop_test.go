package verifier_test

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/richardadalton/settled/sdks/go/verifier"
)

func TestInteropVerify(t *testing.T) {
	path := os.Getenv("INTEROP_DATA")
	if path == "" {
		t.Skip("INTEROP_DATA not set; run scripts/interop_test.py to generate")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var d struct {
		Entries []struct {
			Seq         int    `json:"seq"`
			DataHex     string `json:"data_hex"`
			LeafHashHex string `json:"leaf_hash_hex"`
		} `json:"entries"`
		Sth struct {
			TreeSize     uint64 `json:"tree_size"`
			RootHashHex  string `json:"root_hash_hex"`
			TimestampNs  int64  `json:"timestamp_ns"`
			SignatureHex string `json:"signature_hex"`
			PublicKeyHex string `json:"public_key_hex"`
		} `json:"sth"`
		InclusionProofs []struct {
			Seq         int      `json:"seq"`
			LeafHashHex string   `json:"leaf_hash_hex"`
			ProofHex    []string `json:"proof_hex"`
		} `json:"inclusion_proofs"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("parse interop data: %v", err)
	}

	t.Run("sth_signature", func(t *testing.T) {
		ok := verifier.VerifyTreeHead(
			d.Sth.TreeSize, b32(d.Sth.RootHashHex), d.Sth.TimestampNs,
			h(d.Sth.SignatureHex), h(d.Sth.PublicKeyHex),
		)
		if !ok {
			t.Fatal("STH signature verification failed")
		}
	})

	for _, ip := range d.InclusionProofs {
		ip := ip
		t.Run(fmt.Sprintf("inclusion_seq%d", ip.Seq), func(t *testing.T) {
			ok := verifier.VerifyInclusion(
				b32(ip.LeafHashHex), uint64(ip.Seq), d.Sth.TreeSize,
				proofs(ip.ProofHex), b32(d.Sth.RootHashHex),
			)
			if !ok {
				t.Fatalf("inclusion proof for seq %d failed", ip.Seq)
			}
		})
	}

	for _, entry := range d.Entries {
		entry := entry
		t.Run(fmt.Sprintf("leaf_hash_seq%d", entry.Seq), func(t *testing.T) {
			dataBytes, err := hex.DecodeString(entry.DataHex)
			if err != nil {
				t.Fatalf("bad data_hex: %v", err)
			}
			got := verifier.LeafHash(dataBytes)
			if hex.EncodeToString(got[:]) != entry.LeafHashHex {
				t.Fatalf("leaf hash mismatch: got %x, want %s", got, entry.LeafHashHex)
			}
		})
	}
}

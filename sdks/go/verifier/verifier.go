// Package verifier implements RFC 6962 Merkle tree proof verification and
// Ed25519 Signed Tree Head verification for the Settled audit log.
// See docs/wire-format.md for the canonical specification.
package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
)

// LeafHash returns SHA-256(0x00 || data).
func LeafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash returns SHA-256(0x01 || left || right).
func NodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// k returns the largest power of 2 strictly less than n. Requires n > 1.
func k(n uint64) uint64 {
	p := uint64(1)
	for p*2 < n {
		p <<= 1
	}
	return p
}

// VerifyInclusion verifies an RFC 6962 inclusion proof.
// Returns true iff leafHash at leafIndex in a tree of treeSize with the given
// proof elements produces root.
func VerifyInclusion(leafHash [32]byte, leafIndex, treeSize uint64, proof [][32]byte, root [32]byte) bool {
	if treeSize == 0 || leafIndex >= treeSize {
		return false
	}

	fn := leafIndex
	sn := treeSize - 1
	r := leafHash

	for _, step := range proof {
		if sn == 0 {
			return false
		}
		if (fn&1) != 0 || fn == sn {
			r = NodeHash(step, r)
			for fn != 0 && (fn&1) == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, step)
		}
		fn >>= 1
		sn >>= 1
	}

	return sn == 0 && r == root
}

// VerifyConsistency verifies an RFC 6962 consistency proof.
func VerifyConsistency(oldSize, newSize uint64, proof [][32]byte, oldRoot, newRoot [32]byte) bool {
	if oldSize == newSize {
		return len(proof) == 0 && oldRoot == newRoot
	}
	if oldSize == 0 || oldSize > newSize {
		return false
	}

	idx := 0
	next := func() (*[32]byte, bool) {
		if idx >= len(proof) {
			return nil, false
		}
		h := proof[idx]
		idx++
		return &h, true
	}

	computedOld, computedNew, ok := verifySubproof(oldSize, newSize, oldRoot, next, true)
	if !ok {
		return false
	}
	return idx == len(proof) && computedOld == oldRoot && computedNew == newRoot
}

func verifySubproof(
	m, n uint64,
	oldRoot [32]byte,
	next func() (*[32]byte, bool),
	b bool,
) (computedOld, computedNew [32]byte, ok bool) {
	if m == n {
		if b {
			return oldRoot, oldRoot, true
		}
		h, exists := next()
		if !exists {
			return [32]byte{}, [32]byte{}, false
		}
		return *h, *h, true
	}
	split := k(n)
	if m <= split {
		lo, ln, ok2 := verifySubproof(m, split, oldRoot, next, b)
		if !ok2 {
			return [32]byte{}, [32]byte{}, false
		}
		rh, exists := next()
		if !exists {
			return [32]byte{}, [32]byte{}, false
		}
		return lo, NodeHash(ln, *rh), true
	}
	ro, rn, ok2 := verifySubproof(m-split, n-split, oldRoot, next, false)
	if !ok2 {
		return [32]byte{}, [32]byte{}, false
	}
	lh, exists := next()
	if !exists {
		return [32]byte{}, [32]byte{}, false
	}
	return NodeHash(*lh, ro), NodeHash(*lh, rn), true
}

// SigningPayload returns the canonical 48-byte payload for an STH signature.
// Encoding: tree_size (u64 BE) || root_hash (32 bytes) || timestamp_ns (i64 BE).
// See docs/wire-format.md §5.2.
func SigningPayload(treeSize uint64, rootHash [32]byte, timestampNs int64) [48]byte {
	var buf [48]byte
	binary.BigEndian.PutUint64(buf[0:8], treeSize)
	copy(buf[8:40], rootHash[:])
	binary.BigEndian.PutUint64(buf[40:48], uint64(timestampNs))
	return buf
}

// KeyRecord is a key chain record returned by GET /api/keys.
type KeyRecord struct {
	Version               uint32
	PublicKey             []byte
	ActivatedAtTreeSize   uint64
}

// VerifyTreeHeadWithChain verifies an STH against a key chain.
// It finds the record whose Version matches keyVersion and verifies the
// signature with that record's PublicKey.
func VerifyTreeHeadWithChain(treeSize uint64, rootHash [32]byte, timestampNs int64, signature []byte, keyVersion uint32, chain []KeyRecord) bool {
	for _, r := range chain {
		if r.Version == keyVersion {
			return VerifyTreeHead(treeSize, rootHash, timestampNs, signature, r.PublicKey)
		}
	}
	return false
}

// VerifyTreeHead verifies the Ed25519 signature on a Signed Tree Head.
// publicKey must be the raw 32-byte Ed25519 public key.
func VerifyTreeHead(treeSize uint64, rootHash [32]byte, timestampNs int64, signature, publicKey []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	payload := SigningPayload(treeSize, rootHash, timestampNs)
	return ed25519.Verify(ed25519.PublicKey(publicKey), payload[:], signature)
}

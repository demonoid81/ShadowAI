package chain

import (
	"bytes"
	"encoding/hex"
	"errors"
)

// MerkleProofSibling is one node in a Merkle inclusion proof.
type MerkleProofSibling struct {
	// Side is "left" or "right" — where the sibling sits relative to the
	// current node when computing the parent hash.
	Side    string `json:"side"`
	HashHex string `json:"hash_hex"`
}

// GenerateMerkleProof generates an inclusion proof for the leaf at leafIdx
// in the given set of hashes (ordered, same order used to compute Merkle root).
//
// The proof is a list of siblings: applying them bottom-up reconstructs the
// root. Verify with VerifyMerkleProof(hashes[leafIdx], proof, root).
func GenerateMerkleProof(hashes [][]byte, leafIdx int) ([]MerkleProofSibling, error) {
	if len(hashes) == 0 {
		return nil, errors.New("merkle proof: empty hashes")
	}
	if leafIdx < 0 || leafIdx >= len(hashes) {
		return nil, errors.New("merkle proof: leafIdx out of range")
	}
	if len(hashes) == 1 {
		// Single-leaf tree: no siblings needed; root == leaf.
		return []MerkleProofSibling{}, nil
	}

	var proof []MerkleProofSibling
	level := make([][]byte, len(hashes))
	copy(level, hashes)
	idx := leafIdx

	for len(level) > 1 {
		var sib MerkleProofSibling
		if idx%2 == 0 {
			// Left child — sibling is on the right.
			sibIdx := idx + 1
			if sibIdx >= len(level) {
				sibIdx = idx // last node duplicated
			}
			sib = MerkleProofSibling{Side: "right", HashHex: hex.EncodeToString(level[sibIdx])}
		} else {
			// Right child — sibling is on the left.
			sib = MerkleProofSibling{Side: "left", HashHex: hex.EncodeToString(level[idx-1])}
		}
		proof = append(proof, sib)

		// Advance to next level.
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, merklePair(left, right))
		}
		level = next
		idx = idx / 2
	}
	return proof, nil
}

// VerifyMerkleProof reconstructs the Merkle root from leafHash + siblings and
// compares with expectedRoot. Returns true iff the leaf is included in the tree.
func VerifyMerkleProof(leafHashHex string, siblings []MerkleProofSibling, expectedRootHex string) bool {
	leafBytes, err := hex.DecodeString(leafHashHex)
	if err != nil {
		return false
	}
	expectedRoot, err := hex.DecodeString(expectedRootHex)
	if err != nil {
		return false
	}
	if len(siblings) == 0 {
		// Single-leaf tree: root == leaf.
		return bytes.Equal(leafBytes, expectedRoot)
	}

	current := leafBytes
	for _, sib := range siblings {
		sibBytes, err := hex.DecodeString(sib.HashHex)
		if err != nil {
			return false
		}
		if sib.Side == "left" {
			current = merklePair(sibBytes, current)
		} else {
			current = merklePair(current, sibBytes)
		}
	}
	return bytes.Equal(current, expectedRoot)
}

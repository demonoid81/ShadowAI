package chain

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestMerkleProof_TwoLeaves — proof for each leaf in a 2-leaf tree.
func TestMerkleProof_TwoLeaves(t *testing.T) {
	L0 := bytes.Repeat([]byte{0xAA}, 32)
	L1 := bytes.Repeat([]byte{0xBB}, 32)
	hashes := [][]byte{L0, L1}
	root := ComputeMerkleRoot(hashes)
	rootHex := hex.EncodeToString(root)

	for idx, leaf := range hashes {
		proof, err := GenerateMerkleProof(hashes, idx)
		if err != nil {
			t.Fatalf("GenerateMerkleProof(%d): %v", idx, err)
		}
		if !VerifyMerkleProof(hex.EncodeToString(leaf), proof, rootHex) {
			t.Errorf("VerifyMerkleProof failed for leaf %d", idx)
		}
	}
}

// TestMerkleProof_FourLeaves — proof for each leaf in a balanced 4-leaf tree.
func TestMerkleProof_FourLeaves(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		bytes.Repeat([]byte{0x04}, 32),
	}
	root := ComputeMerkleRoot(hashes)
	rootHex := hex.EncodeToString(root)

	for idx, leaf := range hashes {
		proof, err := GenerateMerkleProof(hashes, idx)
		if err != nil {
			t.Fatalf("GenerateMerkleProof(%d): %v", idx, err)
		}
		if !VerifyMerkleProof(hex.EncodeToString(leaf), proof, rootHex) {
			t.Errorf("VerifyMerkleProof failed for leaf %d", idx)
		}
	}
}

// TestMerkleProof_OddLeaves — 5 leaves (last duplicated in tree).
func TestMerkleProof_OddLeaves(t *testing.T) {
	hashes := make([][]byte, 5)
	for i := range hashes {
		hashes[i] = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}
	root := ComputeMerkleRoot(hashes)
	rootHex := hex.EncodeToString(root)

	for idx, leaf := range hashes {
		proof, err := GenerateMerkleProof(hashes, idx)
		if err != nil {
			t.Fatalf("GenerateMerkleProof(%d): %v", idx, err)
		}
		if !VerifyMerkleProof(hex.EncodeToString(leaf), proof, rootHex) {
			t.Errorf("VerifyMerkleProof failed for leaf %d (5-leaf tree)", idx)
		}
	}
}

// TestMerkleProof_SingleLeaf — single leaf tree: root == leaf, no siblings.
func TestMerkleProof_SingleLeaf(t *testing.T) {
	leaf := bytes.Repeat([]byte{0xFF}, 32)
	root := ComputeMerkleRoot([][]byte{leaf})
	proof, err := GenerateMerkleProof([][]byte{leaf}, 0)
	if err != nil {
		t.Fatalf("GenerateMerkleProof: %v", err)
	}
	if len(proof) != 0 {
		t.Errorf("single leaf: expected 0 siblings, got %d", len(proof))
	}
	if !VerifyMerkleProof(hex.EncodeToString(leaf), proof, hex.EncodeToString(root)) {
		t.Error("single leaf verify failed")
	}
}

// TestMerkleProof_TamperedLeafFails — tampered leaf does not verify.
func TestMerkleProof_TamperedLeafFails(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		bytes.Repeat([]byte{0x04}, 32),
	}
	root := ComputeMerkleRoot(hashes)
	rootHex := hex.EncodeToString(root)
	proof, _ := GenerateMerkleProof(hashes, 2)

	// Tamper: use wrong leaf hash.
	tampered := bytes.Repeat([]byte{0xFF}, 32)
	if VerifyMerkleProof(hex.EncodeToString(tampered), proof, rootHex) {
		t.Error("tampered leaf should fail verification")
	}
}

// TestMerkleProof_WrongRootFails — correct proof against wrong root fails.
func TestMerkleProof_WrongRootFails(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
	}
	proof, _ := GenerateMerkleProof(hashes, 0)
	wrongRoot := hex.EncodeToString(bytes.Repeat([]byte{0xDE}, 32))
	if VerifyMerkleProof(hex.EncodeToString(hashes[0]), proof, wrongRoot) {
		t.Error("wrong root should fail verification")
	}
}

// TestMerkleProof_TruncatedSiblingsFails — missing sibling breaks the proof.
func TestMerkleProof_TruncatedSiblingsFails(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
		bytes.Repeat([]byte{0x04}, 32),
	}
	root := ComputeMerkleRoot(hashes)
	rootHex := hex.EncodeToString(root)
	proof, _ := GenerateMerkleProof(hashes, 0)

	// Truncate: remove last sibling.
	truncated := proof[:len(proof)-1]
	if VerifyMerkleProof(hex.EncodeToString(hashes[0]), truncated, rootHex) {
		t.Error("truncated proof should fail verification")
	}
}

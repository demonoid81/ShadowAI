package chain

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestComputeMerkleRoot_Empty — nil для пустого списка.
func TestComputeMerkleRoot_Empty(t *testing.T) {
	if root := ComputeMerkleRoot(nil); root != nil {
		t.Errorf("empty: want nil, got %x", root)
	}
	if root := ComputeMerkleRoot([][]byte{}); root != nil {
		t.Errorf("empty slice: want nil, got %x", root)
	}
}

// TestComputeMerkleRoot_Single — root single leaf = сам лист.
func TestComputeMerkleRoot_Single(t *testing.T) {
	leaf := []byte("hash_32_bytes_padded_to_length!!")
	root := ComputeMerkleRoot([][]byte{leaf})
	if !bytes.Equal(root, leaf) {
		t.Errorf("single leaf: root=%x, want leaf=%x", root, leaf)
	}
}

// TestComputeMerkleRoot_TwoLeaves — parent = SHA256(left||right).
func TestComputeMerkleRoot_TwoLeaves(t *testing.T) {
	left := []byte("left_leaf_hash_32bytes!!!!!!!!!!!")[:32]
	right := []byte("right_leaf_hash_32bytes!!!!!!!!!")[:32]
	root := ComputeMerkleRoot([][]byte{left, right})

	h := sha256.New()
	h.Write(left)
	h.Write(right)
	want := h.Sum(nil)
	if !bytes.Equal(root, want) {
		t.Errorf("two leaves: root=%x, want=%x", root, want)
	}
}

// TestComputeMerkleRoot_OddLeaves — нечётное количество листьев, последний
// дублируется.
func TestComputeMerkleRoot_OddLeaves(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 32)
	b := bytes.Repeat([]byte{0x02}, 32)
	c := bytes.Repeat([]byte{0x03}, 32)
	root := ComputeMerkleRoot([][]byte{a, b, c})

	// Manual: pair(a,b) → ab; pair(c,c) → cc; pair(ab,cc) → root.
	ab := merklePair(a, b)
	cc := merklePair(c, c)
	want := merklePair(ab, cc)
	if !bytes.Equal(root, want) {
		t.Errorf("odd leaves: root=%x, want=%x", root, want)
	}
}

// TestComputeMerkleRoot_Deterministic — одинаковые inputs → одинаковый root.
func TestComputeMerkleRoot_Deterministic(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0xAA}, 32),
		bytes.Repeat([]byte{0xBB}, 32),
		bytes.Repeat([]byte{0xCC}, 32),
		bytes.Repeat([]byte{0xDD}, 32),
	}
	r1 := ComputeMerkleRoot(hashes)
	r2 := ComputeMerkleRoot(hashes)
	if !bytes.Equal(r1, r2) {
		t.Error("non-deterministic")
	}
}

// TestComputeMerkleRoot_OrderSensitive — root меняется если порядок
// листьев изменился.
func TestComputeMerkleRoot_OrderSensitive(t *testing.T) {
	a := bytes.Repeat([]byte{0x01}, 32)
	b := bytes.Repeat([]byte{0x02}, 32)
	r1 := ComputeMerkleRoot([][]byte{a, b})
	r2 := ComputeMerkleRoot([][]byte{b, a})
	if bytes.Equal(r1, r2) {
		t.Error("order-insensitive Merkle — verifier won't detect reordering")
	}
}

// TestComputeMerkleRoot_DeletionDetection — удаление листа меняет root.
// Это ключевой W3 property: verifier без chain_secret детектирует
// удалённые rows через несовпадение Merkle root.
func TestComputeMerkleRoot_DeletionDetection(t *testing.T) {
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
	}
	full := ComputeMerkleRoot(hashes)
	// Simulated: row 2 deleted.
	withoutRow2 := ComputeMerkleRoot([][]byte{hashes[0], hashes[2]})
	if bytes.Equal(full, withoutRow2) {
		t.Error("deletion not detected by Merkle root change")
	}
}

package chain

import (
	"crypto/sha256"
)

// ComputeMerkleRoot строит binary Merkle tree из list'а leaf-хэшей
// и возвращает root hash (32 bytes).
//
// Конструкция:
//   - Leaves — row_hash значения (уже HMAC-SHA256, 32 bytes каждый).
//     Используются напрямую как leaf nodes без повторного хэширования,
//     чтобы verifier мог пересчитать root из stored row_hash'ей без
//     chain_secret (RFC §8.4 W3 tier).
//   - Parent = SHA-256(left_child || right_child).
//   - Нечётное число nodes → последний дублируется (standard Merkle padding).
//
// Возвращает nil если hashes пустой (нет новых chained rows).
func ComputeMerkleRoot(hashes [][]byte) []byte {
	if len(hashes) == 0 {
		return nil
	}
	// Start with a copy of the leaf nodes as current level.
	level := make([][]byte, len(hashes))
	copy(level, hashes)

	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // duplicate if odd
			if i+1 < len(level) {
				right = level[i+1]
			}
			parent := merklePair(left, right)
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}

// merklePair computes SHA-256(left || right).
func merklePair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

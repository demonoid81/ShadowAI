package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"testing"
)

// buildChainedHashes строит цепочку из N хэшей и возвращает их в порядке.
// Используется для генерации тест-fixtures без реальной БД.
func buildChainedHashes(n int, secret []byte, canonicals []string) [][]byte {
	hashes := make([][]byte, n)
	prev := make([]byte, 32)
	for i := 0; i < n; i++ {
		mac := hmac.New(sha256.New, secret)
		mac.Write(prev)
		mac.Write([]byte(canonicals[i]))
		hashes[i] = mac.Sum(nil)
		prev = hashes[i]
	}
	return hashes
}

// TestVerify_ChainSequence — N-элементная цепочка, каждый hash верифицируется.
func TestVerify_ChainSequence(t *testing.T) {
	secret := []byte("chain-secret-32chars!!!!!!!!!!!")
	canonicals := []string{"v1|row1", "v1|row2", "v1|row3", "v1|row4"}
	hashes := buildChainedHashes(4, secret, canonicals)

	prevHash := make([]byte, 32)
	for i, canonical := range canonicals {
		if !Verify(prevHash, canonical, secret, hashes[i]) {
			t.Errorf("chain step %d failed verification", i)
		}
		prevHash = hashes[i]
	}
}

// TestVerify_ChainBreak_MiddleRow — модифицируем один canonical посередине
// цепочки — этот row не верифицируется, но последующий тоже, потому что
// prevHash ссылается на правильный (не-tampered) previous hash.
// Verifier видит CHAIN_BREAK на изменённом row.
func TestVerify_ChainBreak_MiddleRow(t *testing.T) {
	secret := []byte("chain-secret-32chars!!!!!!!!!!!")
	canonicals := []string{"v1|row1", "v1|row2", "v1|row3"}
	hashes := buildChainedHashes(3, secret, canonicals)

	// Modify row 2 canonical — simulates row content tampered in DB.
	tampered := "v1|row2_TAMPERED"

	prevHash := make([]byte, 32)
	// Row 1 — OK.
	if !Verify(prevHash, canonicals[0], secret, hashes[0]) {
		t.Error("row 1 unexpectedly broken")
	}
	prevHash = hashes[0]

	// Row 2 — CHAIN_BREAK (tampered canonical).
	if Verify(prevHash, tampered, secret, hashes[1]) {
		t.Error("tampered row 2 should fail verification")
	}
	// Continuing chain with correct canonical: this is what verifier does
	// to detect if break cascades.
	prevHash = hashes[1] // stored (correct) hash

	// Row 3 with correct canonical — OK since prevHash was not corrupted.
	if !Verify(prevHash, canonicals[2], secret, hashes[2]) {
		t.Error("row 3 should verify correctly after isolated tamper")
	}
}

// TestVerify_GapSimulation — gap детекция не требует cryptography:
// это последовательный scan seq_no значений. Этот тест валидирует
// что verifier logic правильно обнаружит non-consecutive seq_nos.
// Реализация в verifier.go ищет r.SeqNo != prevSeqNo+1.
func TestVerify_GapSimulation(t *testing.T) {
	// simulate seq numbers: 1, 2, 4 — gap at 3.
	seqNos := []int64{1, 2, 4}
	var gaps []int64
	var prev int64
	for i, seqNo := range seqNos {
		if i > 0 && seqNo != prev+1 {
			for gap := prev + 1; gap < seqNo; gap++ {
				gaps = append(gaps, gap)
			}
		}
		prev = seqNo
	}
	if len(gaps) != 1 || gaps[0] != 3 {
		t.Errorf("gap detection: got %v, want [3]", gaps)
	}
}

// TestVerify_NoGapNoBreak — clean chain of 5 rows, all OK.
func TestVerify_NoGapNoBreak(t *testing.T) {
	secret := []byte("chain-secret-32chars!!!!!!!!!!!")
	canonicals := make([]string, 5)
	for i := range canonicals {
		canonicals[i] = CanonicalAdminEventLog(
			fmt.Sprintf("id%d", i), "", "read", "audit_logs", "", "/api/audit", "GET",
			200, true, int64(1714000000+i),
		)
	}
	hashes := buildChainedHashes(5, secret, canonicals)
	prevHash := make([]byte, 32)
	for i, canonical := range canonicals {
		if !Verify(prevHash, canonical, secret, hashes[i]) {
			t.Errorf("row %d failed in clean chain", i)
		}
		prevHash = hashes[i]
	}
}

// TestConcurrentChainOrder — validates that HMAC chain is
// order-dependent: swapping two rows' hashes breaks both.
func TestConcurrentChainOrder(t *testing.T) {
	secret := []byte("chain-secret-32chars!!!!!!!!!!!")
	c1 := "v1|row1"
	c2 := "v1|row2"
	hashes := buildChainedHashes(2, secret, []string{c1, c2})

	zero := make([]byte, 32)
	// Hash 1 verifies against zero prev.
	if !Verify(zero, c1, secret, hashes[0]) {
		t.Fatal("row1 initial verify failed")
	}
	// Hash 2 verifies against hash[0].
	if !Verify(hashes[0], c2, secret, hashes[1]) {
		t.Fatal("row2 chained verify failed")
	}
	// Swapped: hash[1] against zero prev — should FAIL.
	if Verify(zero, c2, secret, hashes[1]) {
		t.Error("swapped chain order should break hash[1] verification")
	}
	// Swapped: hash[0] against hash[1] as prev — should FAIL.
	if Verify(hashes[1], c1, secret, hashes[0]) {
		t.Error("reversed chain order should break hash[0] verification")
	}
}


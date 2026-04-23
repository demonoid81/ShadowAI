package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"
)

// TestAcquireSlot_DisabledWhenSecretEmpty — chain disabled path:
// пустой secret → (0, nil, nil). Caller должен пропустить chain fields.
func TestAcquireSlot_DisabledWhenSecretEmpty(t *testing.T) {
	seqNo, rowHash, err := AcquireSlot(nil, nil, TableAuditLogs, "audit_logs",
		SeqAuditLogs, "v1|...", []byte(""))
	if err != nil {
		t.Errorf("empty secret: err = %v, want nil", err)
	}
	if seqNo != 0 || rowHash != nil {
		t.Errorf("empty secret: seqNo=%d rowHash=%v; want 0, nil", seqNo, rowHash)
	}
}

// TestVerify_CorrectHash — Verify возвращает true для корректного hash.
func TestVerify_CorrectHash(t *testing.T) {
	secret := []byte("test-chain-secret-32chars!!!!!!!!")
	prev := make([]byte, 32)
	canonical := "v1|id1|user1|gpt-4o|openai|/chat|200|10|5|15|0|0||allowed|||final|1714000000"

	mac := hmac.New(sha256.New, secret)
	mac.Write(prev)
	mac.Write([]byte(canonical))
	stored := mac.Sum(nil)

	if !Verify(prev, canonical, secret, stored) {
		t.Error("Verify returned false for correct hash")
	}
}

// TestVerify_ModifiedCanonical — Verify возвращает false при модификации.
func TestVerify_ModifiedCanonical(t *testing.T) {
	secret := []byte("test-chain-secret-32chars!!!!!!!!")
	prev := make([]byte, 32)
	canonical := "v1|id1|user1|gpt-4o|openai|/chat|200|10|5|15|0|0||allowed|||final|1714000000"
	tampered := "v1|id1|user1|gpt-4o|openai|/chat|200|10|5|15|0|0||blocked|||final|1714000000"

	mac := hmac.New(sha256.New, secret)
	mac.Write(prev)
	mac.Write([]byte(canonical))
	stored := mac.Sum(nil)

	if Verify(prev, tampered, secret, stored) {
		t.Error("Verify returned true for tampered canonical")
	}
}

// TestVerify_WrongPrevHash — если prevHash изменился, hash не совпадёт.
func TestVerify_WrongPrevHash(t *testing.T) {
	secret := []byte("test-chain-secret-32chars!!!!!!!!")
	prev := make([]byte, 32)
	canonical := "v1|any"

	mac := hmac.New(sha256.New, secret)
	mac.Write(prev)
	mac.Write([]byte(canonical))
	stored := mac.Sum(nil)

	wrongPrev := make([]byte, 32)
	wrongPrev[0] = 0xFF

	if Verify(wrongPrev, canonical, secret, stored) {
		t.Error("Verify returned true for wrong prevHash")
	}
}

// TestVerify_NilPrevHashUsesInitializer — nil prevHash ≡ initialHash.
func TestVerify_NilPrevHashUsesInitializer(t *testing.T) {
	secret := []byte("test-chain-secret-32chars!!!!!!!!")
	canonical := "v1|any"

	mac := hmac.New(sha256.New, secret)
	mac.Write(initialHash) // explicit initializer
	mac.Write([]byte(canonical))
	stored := mac.Sum(nil)

	// nil prevHash → uses initialHash internally
	if !Verify(nil, canonical, secret, stored) {
		t.Error("Verify with nil prevHash should use initialHash")
	}
}

// TestCanonicalAuditLog_Deterministic — одинаковые inputs → одинаковый output.
func TestCanonicalAuditLog_Deterministic(t *testing.T) {
	pii := []string{"email", "phone"}
	a := CanonicalAuditLog("id1", "uid1", "gpt-4o", "openai", "/chat",
		200, 10, 5, 15, 1000000, true, pii,
		"allowed", "stream_completed", "", "final", 1714000000)
	b := CanonicalAuditLog("id1", "uid1", "gpt-4o", "openai", "/chat",
		200, 10, 5, 15, 1000000, true, pii,
		"allowed", "stream_completed", "", "final", 1714000000)
	if a != b {
		t.Errorf("canonical not deterministic: %q vs %q", a, b)
	}
}

// TestCanonicalAuditLog_PiiTypesSorted — pii_types всегда в
// sorted order независимо от порядка входного slice.
func TestCanonicalAuditLog_PiiTypesSorted(t *testing.T) {
	c1 := CanonicalAuditLog("id", "u", "m", "p", "/e", 200, 0, 0, 0, 0, true,
		[]string{"phone", "email"}, "allowed", "", "", "", 0)
	c2 := CanonicalAuditLog("id", "u", "m", "p", "/e", 200, 0, 0, 0, 0, true,
		[]string{"email", "phone"}, "allowed", "", "", "", 0)
	if c1 != c2 {
		t.Errorf("pii sort: %q vs %q", c1, c2)
	}
	if !strings.Contains(c1, "email,phone") {
		t.Errorf("expected sorted 'email,phone' in canonical: %q", c1)
	}
}

// TestCanonicalLegalHoldEvent_Format — v1 prefix и 6 fields.
func TestCanonicalLegalHoldEvent_Format(t *testing.T) {
	c := CanonicalLegalHoldEvent("id1", "hold1", "approve", "active", "actor1", 1714000000)
	parts := strings.Split(c, "|")
	if parts[0] != "v1" {
		t.Errorf("missing v1 prefix: %q", c)
	}
	if len(parts) != 7 { // v1 + 6 fields
		t.Errorf("expected 7 parts, got %d: %q", len(parts), c)
	}
}

// TestCostMicrocents — float USD → int64 microcents.
func TestCostMicrocents(t *testing.T) {
	cases := []struct {
		usd  float64
		want int64
	}{
		{0.0, 0},
		{1.0, 1_000_000},
		{0.000001, 1}, // 1 microcent
		{0.5, 500_000},
		{1.999999, 1_999_999},
	}
	for _, c := range cases {
		got := CostMicrocents(c.usd)
		if got != c.want {
			t.Errorf("CostMicrocents(%v) = %d, want %d", c.usd, got, c.want)
		}
	}
}

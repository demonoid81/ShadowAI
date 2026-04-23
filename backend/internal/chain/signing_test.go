package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

)

func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func testAnchorRecord() *AnchorRecord {
	return &AnchorRecord{
		ID:         "test-id",
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      10,
		RowCount:   10,
		MerkleRoot: bytes.Repeat([]byte{0xAB}, 32),
		CreatedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
		SinkName:   "file://",
		SinkRef:    "/var/anchors.ndjson",
	}
}

// TestManifestCanonical_Deterministic — одинаковые inputs → одинаковый canonical.
func TestManifestCanonical_Deterministic(t *testing.T) {
	a := testAnchorRecord()
	a.PubKeyID = "ed25519-k1"
	c1 := ManifestCanonical(a)
	c2 := ManifestCanonical(a)
	if c1 != c2 {
		t.Errorf("canonical not deterministic: %q vs %q", c1, c2)
	}
}

// TestManifestCanonical_FieldSensitivity — изменение любого поля меняет canonical.
func TestManifestCanonical_FieldSensitivity(t *testing.T) {
	base := testAnchorRecord()
	base.PubKeyID = "ed25519-k1"
	baseCanon := ManifestCanonical(base)

	cases := []struct {
		name   string
		mutate func(*AnchorRecord)
	}{
		{"table", func(a *AnchorRecord) { a.TableName = "other" }},
		{"seq_lo", func(a *AnchorRecord) { a.SeqLo = 2 }},
		{"seq_hi", func(a *AnchorRecord) { a.SeqHi = 11 }},
		{"row_count", func(a *AnchorRecord) { a.RowCount = 99 }},
		{"merkle_root", func(a *AnchorRecord) { a.MerkleRoot[0] ^= 0xFF }},
		{"created_at", func(a *AnchorRecord) { a.CreatedAt = a.CreatedAt.Add(time.Second) }},
		{"sink_name", func(a *AnchorRecord) { a.SinkName = "immudb://" }},
		{"sink_ref", func(a *AnchorRecord) { a.SinkRef = "other" }},
		{"pubkey_id", func(a *AnchorRecord) { a.PubKeyID = "ed25519-k2" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := *base
			a.MerkleRoot = append([]byte(nil), base.MerkleRoot...)
			c.mutate(&a)
			if ManifestCanonical(&a) == baseCanon {
				t.Errorf("canonical unchanged after mutating %s", c.name)
			}
		})
	}
}

// TestSignAnchor_VerifyAnchorSignature_HappyPath — sign + verify roundtrip.
func TestSignAnchor_VerifyAnchorSignature_HappyPath(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	a := testAnchorRecord()
	if err := SignAnchor(a, priv, "ed25519-k1"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}
	if a.PubKeyID != "ed25519-k1" {
		t.Errorf("PubKeyID = %q, want ed25519-k1", a.PubKeyID)
	}
	if len(a.Signature) == 0 {
		t.Fatal("Signature is empty")
	}
	if !VerifyAnchorSignature(a, pub) {
		t.Error("VerifyAnchorSignature returned false for valid signature")
	}
}

// TestVerifyAnchorSignature_TamperedRecord — изменение любого поля после
// подписи делает подпись невалидной.
func TestVerifyAnchorSignature_TamperedRecord(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	a := testAnchorRecord()
	_ = SignAnchor(a, priv, "ed25519-k1")

	// Tamper MerkleRoot.
	tampered := *a
	tampered.MerkleRoot = append([]byte(nil), a.MerkleRoot...)
	tampered.MerkleRoot[0] ^= 0xFF
	if VerifyAnchorSignature(&tampered, pub) {
		t.Error("tampered merkle_root: signature should fail")
	}

	// Tamper sink_ref.
	tampered2 := *a
	tampered2.SinkRef = "malicious"
	if VerifyAnchorSignature(&tampered2, pub) {
		t.Error("tampered sink_ref: signature should fail")
	}
}

// TestVerifyAnchorSignature_WrongKey — wrong public key → verify fails.
func TestVerifyAnchorSignature_WrongKey(t *testing.T) {
	_, priv1 := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)

	a := testAnchorRecord()
	_ = SignAnchor(a, priv1, "ed25519-k1")

	if VerifyAnchorSignature(a, pub2) {
		t.Error("wrong public key should fail verification")
	}
}

// TestVerifyAnchorSignature_NoSignature — empty signature → false.
func TestVerifyAnchorSignature_NoSignature(t *testing.T) {
	pub, _ := generateTestKeyPair(t)
	a := testAnchorRecord() // no signature
	if VerifyAnchorSignature(a, pub) {
		t.Error("unsigned anchor should return false")
	}
}

// TestParsePrivateKey_RoundTrip — encode → decode → sign → verify.
func TestParsePrivateKey_RoundTrip(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	b64 := base64.StdEncoding.EncodeToString(priv)

	parsed, err := ParsePrivateKey(b64)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	a := testAnchorRecord()
	_ = SignAnchor(a, parsed, "k1")
	if !VerifyAnchorSignature(a, pub) {
		t.Error("signature with parsed private key failed to verify")
	}
}

// TestParsePublicKey_RoundTrip — encode → decode → verify.
func TestParsePublicKey_RoundTrip(t *testing.T) {
	pub, priv := generateTestKeyPair(t)
	b64 := base64.StdEncoding.EncodeToString(pub)

	parsed, err := ParsePublicKey(b64)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	a := testAnchorRecord()
	_ = SignAnchor(a, priv, "k1")
	if !VerifyAnchorSignature(a, parsed) {
		t.Error("signature failed with round-trip parsed public key")
	}
}

// TestSeedOnlyPrivateKey — 32-byte seed input.
func TestSeedOnlyPrivateKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := priv.Seed()
	seedB64 := base64.StdEncoding.EncodeToString(seed)

	parsed, err := ParsePrivateKey(seedB64)
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	a := testAnchorRecord()
	_ = SignAnchor(a, parsed, "k1")
	if !VerifyAnchorSignature(a, pub) {
		t.Error("seed-derived private key failed verification")
	}
}

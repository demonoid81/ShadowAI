package chain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

// MockImmuDBClient — test double for ImmuDBClient.
type MockImmuDBClient struct {
	store map[string][]byte
	txID  uint64
}

func NewMockImmuDBClient() *MockImmuDBClient {
	return &MockImmuDBClient{store: make(map[string][]byte)}
}

func (m *MockImmuDBClient) Set(_ context.Context, key string, value []byte) (uint64, error) {
	m.txID++
	m.store[key] = value
	return m.txID, nil
}

func (m *MockImmuDBClient) Get(_ context.Context, key string) ([]byte, error) {
	v, ok := m.store[key]
	if !ok {
		return nil, &notFoundError{key: key}
	}
	return v, nil
}

type notFoundError struct{ key string }

func (e *notFoundError) Error() string { return "key not found: " + e.key }

func testSignedAnchor(t *testing.T, priv ed25519.PrivateKey) *AnchorRecord {
	t.Helper()
	a := &AnchorRecord{
		TableName:  "audit_logs",
		SeqLo:      1,
		SeqHi:      10,
		RowCount:   10,
		MerkleRoot: bytes.Repeat([]byte{0xAB}, 32),
		CreatedAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
	}
	sink := &ImmuDBSink{database: "shadowai"}
	a.SinkName = sink.Name()
	a.SinkRef = sink.BuildRef(a)
	if priv != nil {
		_ = SignAnchor(a, priv, "ed25519-k1")
	}
	return a
}

// TestImmuDBSink_BuildRef — deterministic ref format.
func TestImmuDBSink_BuildRef(t *testing.T) {
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")
	a := &AnchorRecord{TableName: "audit_logs", SeqLo: 101, SeqHi: 140}
	ref := sink.BuildRef(a)
	expected := "immudb://shadowai/audit_logs/101-140"
	if ref != expected {
		t.Errorf("BuildRef = %q, want %q", ref, expected)
	}
}

// TestImmuDBKeyFromRef — key derived from ref.
func TestImmuDBKeyFromRef(t *testing.T) {
	ref := "immudb://shadowai/audit_logs/101-140"
	key := immudbKeyFromRef(ref)
	expected := "shadowai/anchors/audit_logs/101-140"
	if key != expected {
		t.Errorf("key = %q, want %q", key, expected)
	}
}

// TestImmuDBSink_WriteManifest — Write stores manifest under correct key.
func TestImmuDBSink_WriteManifest(t *testing.T) {
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")
	a := testSignedAnchor(t, nil)

	manifest, _ := MarshalSignedManifest(a)
	ref := sink.BuildRef(a)
	if err := sink.Write(context.Background(), manifest, ref); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Check it's stored under the right key.
	key := immudbKeyFromRef(ref)
	stored := client.store[key]
	if !bytes.Equal(stored, manifest) {
		t.Errorf("stored manifest mismatch: got %q, want %q", stored, manifest)
	}
}

// TestMarshalUnmarshalSignedManifest_Roundtrip — serialize + deserialize.
func TestMarshalUnmarshalSignedManifest_Roundtrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	a := testSignedAnchor(t, priv)

	data, err := MarshalSignedManifest(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	b, err := UnmarshalSignedManifest(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if b.TableName != a.TableName || b.SeqLo != a.SeqLo || b.SeqHi != a.SeqHi ||
		b.RowCount != a.RowCount || b.PubKeyID != a.PubKeyID {
		t.Errorf("roundtrip mismatch: %+v vs %+v", a, b)
	}
	if !bytes.Equal(b.MerkleRoot, a.MerkleRoot) {
		t.Error("MerkleRoot mismatch after roundtrip")
	}
	if !bytes.Equal(b.Signature, a.Signature) {
		t.Errorf("Signature mismatch: got %x want %x", b.Signature, a.Signature)
	}
}

// TestVerifyImmuDBSinkRecord_Match — stored manifest matches anchor + sig verifies.
func TestVerifyImmuDBSinkRecord_Match(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")

	a := testSignedAnchor(t, priv)
	manifest, _ := MarshalSignedManifest(a)
	ref := sink.BuildRef(a)
	_ = sink.Write(context.Background(), manifest, ref)

	ok, err := VerifyImmuDBSinkRecord(context.Background(), sink, a, pub)
	if err != nil {
		t.Fatalf("VerifyImmuDBSinkRecord: %v", err)
	}
	if !ok {
		t.Error("expected match, got false")
	}
}

// TestVerifyImmuDBSinkRecord_TamperedPayload — tampered merkle_root fails.
func TestVerifyImmuDBSinkRecord_TamperedPayload(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub, _, _ := ed25519.GenerateKey(rand.Reader) // use a key that doesn't match the signature
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")

	a := testSignedAnchor(t, priv)
	manifest, _ := MarshalSignedManifest(a)

	// Tamper: flip first bytes of merkle_root_hex in the JSON.
	tampered := bytes.Replace(manifest, []byte(hex.EncodeToString(a.MerkleRoot)[:4]), []byte("0000"), 1)
	ref := sink.BuildRef(a)
	key := immudbKeyFromRef(ref)
	client.store[key] = tampered

	ok, err := VerifyImmuDBSinkRecord(context.Background(), sink, a, pub)
	if err != nil {
		t.Logf("tampered payload: err=%v (acceptable — unmarshal or field mismatch)", err)
	}
	// Must be false: tampered merkle_root != DB anchor's merkle_root.
	if ok {
		t.Error("tampered manifest should fail verification, got ok=true")
	}
}

// TestVerifyImmuDBSinkRecord_UnsignedManifestRejectedWhenPubKeySet — Fix #3:
// if pubKey provided but manifest has no signature, verification must fail.
func TestVerifyImmuDBSinkRecord_UnsignedManifestRejectedWhenPubKeySet(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")

	// Anchor with NO signature.
	a := testSignedAnchor(t, nil)
	manifest, _ := MarshalSignedManifest(a) // no signature
	ref := sink.BuildRef(a)
	_ = sink.Write(context.Background(), manifest, ref)

	ok, err := VerifyImmuDBSinkRecord(context.Background(), sink, a, pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("unsigned manifest should fail when pubKey is set")
	}
}

// TestVerifyImmuDBSinkRecord_UnsignedOKWithoutPubKey — unsigned manifest
// passes if no pubKey provided (legacy pre-W4.1 anchors).
func TestVerifyImmuDBSinkRecord_UnsignedOKWithoutPubKey(t *testing.T) {
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")

	a := testSignedAnchor(t, nil)
	manifest, _ := MarshalSignedManifest(a)
	ref := sink.BuildRef(a)
	_ = sink.Write(context.Background(), manifest, ref)

	ok, err := VerifyImmuDBSinkRecord(context.Background(), sink, a, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("unsigned manifest should pass when no pubKey required")
	}
}

// TestVerifyImmuDBSinkRecord_SinkRefMismatch — mismatched sink_ref fails.
func TestVerifyImmuDBSinkRecord_SinkRefMismatch(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")

	// Write anchor with original sink_ref.
	a := testSignedAnchor(t, priv)
	manifest, _ := MarshalSignedManifest(a)
	ref := sink.BuildRef(a)
	_ = sink.Write(context.Background(), manifest, ref)

	// DB anchor has different sink_ref (simulates tampering).
	aTampered := *a
	aTampered.SinkRef = "immudb://shadowai/audit_logs/999-1000"
	aTampered.Signature = a.Signature // keep original sig

	ok, _ := VerifyImmuDBSinkRecord(context.Background(), sink, &aTampered, pub)
	// Should fail: sink_ref in manifest != DB anchor sink_ref (which we changed).
	if ok {
		t.Error("sink_ref mismatch should fail verification")
	}
}

// TestVerifyImmuDBSinkRecord_WrongSignature — wrong public key → sig fails.
func TestVerifyImmuDBSinkRecord_WrongSignature(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")

	a := testSignedAnchor(t, priv1)
	manifest, _ := MarshalSignedManifest(a)
	ref := sink.BuildRef(a)
	_ = sink.Write(context.Background(), manifest, ref)

	ok, err := VerifyImmuDBSinkRecord(context.Background(), sink, a, pub2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("wrong pubkey: expected false, got true")
	}
}

// TestImmuDBSink_DeterministicKey — same anchor always maps to same immudb key.
func TestImmuDBSink_DeterministicKey(t *testing.T) {
	client := NewMockImmuDBClient()
	sink := NewImmuDBSink(client, "shadowai")
	a := &AnchorRecord{TableName: "audit_logs", SeqLo: 50, SeqHi: 75}

	ref1 := sink.BuildRef(a)
	ref2 := sink.BuildRef(a)
	if ref1 != ref2 {
		t.Errorf("non-deterministic BuildRef: %q vs %q", ref1, ref2)
	}
	k1, k2 := immudbKeyFromRef(ref1), immudbKeyFromRef(ref2)
	if k1 != k2 {
		t.Errorf("non-deterministic key: %q vs %q", k1, k2)
	}
}

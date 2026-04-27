package chain

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// SigningKeyring tests
// ---------------------------------------------------------------------------

// TestSigningKeyring_OldKeyPassesOldAnchor — DoD: old anchor with old key passes.
func TestSigningKeyring_OldKeyPassesOldAnchor(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)

	a := testAnchorRecord()
	if err := SignAnchor(a, priv1, "ed25519-v1"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}

	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{
		"ed25519-v1": pub1,
	}, nil)

	pub, ok := keyring.LookupSigningKey("ed25519-v1")
	if !ok {
		t.Fatal("ed25519-v1 not found in keyring")
	}
	if !VerifyAnchorSignature(a, pub) {
		t.Error("old anchor with old key should pass")
	}
}

// TestSigningKeyring_NewKeyPassesNewAnchor — DoD: new anchor with new key passes.
func TestSigningKeyring_NewKeyPassesNewAnchor(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)
	pub2, priv2 := generateTestKeyPair(t)

	oldAnchor := testAnchorRecord()
	oldAnchor.SeqLo, oldAnchor.SeqHi = 1, 100
	if err := SignAnchor(oldAnchor, priv1, "ed25519-v1"); err != nil {
		t.Fatalf("sign old: %v", err)
	}

	newAnchor := testAnchorRecord()
	newAnchor.SeqLo, newAnchor.SeqHi = 101, 200
	if err := SignAnchor(newAnchor, priv2, "ed25519-v2"); err != nil {
		t.Fatalf("sign new: %v", err)
	}

	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{
		"ed25519-v1": pub1,
		"ed25519-v2": pub2,
	}, nil)

	pubOld, _ := keyring.LookupSigningKey("ed25519-v1")
	if !VerifyAnchorSignature(oldAnchor, pubOld) {
		t.Error("old anchor with old key should pass")
	}
	pubNew, _ := keyring.LookupSigningKey("ed25519-v2")
	if !VerifyAnchorSignature(newAnchor, pubNew) {
		t.Error("new anchor with new key should pass")
	}
}

// TestSigningKeyring_WrongKeyFails — DoD: wrong key fails verification.
func TestSigningKeyring_WrongKeyFails(t *testing.T) {
	_, priv1 := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t) // wrong key

	a := testAnchorRecord()
	if err := SignAnchor(a, priv1, "ed25519-v1"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}

	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{
		"ed25519-v1": pub2, // deliberately wrong key for this id
	}, nil)

	pub, ok := keyring.LookupSigningKey("ed25519-v1")
	if !ok {
		t.Fatal("key id should be found")
	}
	if VerifyAnchorSignature(a, pub) {
		t.Error("wrong key should fail verification")
	}
}

// TestSigningKeyring_UnknownKeyIDFails — DoD: unknown key_id → fail-closed.
func TestSigningKeyring_UnknownKeyIDFails(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)

	a := testAnchorRecord()
	if err := SignAnchor(a, priv1, "ed25519-unknown"); err != nil {
		t.Fatalf("SignAnchor: %v", err)
	}

	// Keyring does NOT contain "ed25519-unknown".
	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{
		"ed25519-v1": pub1,
	}, nil)

	pub, ok := keyring.LookupSigningKey("ed25519-unknown")
	if ok {
		t.Error("unknown key_id should return ok=false (fail-closed)")
	}
	if pub != nil {
		t.Error("unknown key_id should return nil public key")
	}
}

// TestSigningKeyring_MixedEpochBundlePasses — DoD: bundle with anchors from
// different epochs verifies correctly using keyring.
func TestSigningKeyring_MixedEpochBundlePasses(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)
	pub2, priv2 := generateTestKeyPair(t)

	anchors := []*AnchorRecord{
		func() *AnchorRecord {
			a := testAnchorRecord()
			a.SeqLo, a.SeqHi = 1, 50
			_ = SignAnchor(a, priv1, "key-v1")
			return a
		}(),
		func() *AnchorRecord {
			a := testAnchorRecord()
			a.SeqLo, a.SeqHi = 51, 100
			_ = SignAnchor(a, priv2, "key-v2")
			return a
		}(),
		func() *AnchorRecord {
			a := testAnchorRecord()
			a.SeqLo, a.SeqHi = 101, 150
			// Legacy: no pubkey_id (pre-W4.1)
			return a
		}(),
	}

	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{
		"key-v1": pub1,
		"key-v2": pub2,
	}, pub1) // pub1 also used as legacy key

	failures := 0
	for _, a := range anchors {
		if len(a.Signature) == 0 {
			// Unsigned: skip (counted as UnsignedCount, not failure)
			continue
		}
		pub, ok := keyring.LookupSigningKey(a.PubKeyID)
		if !ok {
			failures++
			t.Errorf("unknown pubkey_id %q", a.PubKeyID)
			continue
		}
		if !VerifyAnchorSignature(a, pub) {
			failures++
			t.Errorf("anchor [%d,%d] failed verification", a.SeqLo, a.SeqHi)
		}
	}
	if failures > 0 {
		t.Errorf("mixed epoch bundle: %d failure(s)", failures)
	}
}

// TestSigningKeyring_LegacyKeyUsedForEmptyPubKeyID — backward compat:
// anchors with empty pubkey_id verified against legacy key.
func TestSigningKeyring_LegacyKeyUsedForEmptyPubKeyID(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	a := testAnchorRecord()
	_ = SignAnchor(a, priv, "legacy-key-id")
	a.PubKeyID = "" // simulate pre-W4.1 anchor (no pubkey_id stored)
	// Re-sign without pubkey_id so canonical matches empty pubkey_id
	if err := SignAnchor(a, priv, ""); err != nil {
		t.Fatalf("re-sign: %v", err)
	}

	keyring := SingleKeyKeyring(pub)
	legacyPub, ok := keyring.LookupSigningKey("")
	if !ok {
		t.Fatal("legacy key not found for empty pubkey_id")
	}
	if !VerifyAnchorSignature(a, legacyPub) {
		t.Error("legacy anchor should verify with legacy key")
	}
	pubWithID, ok := keyring.LookupSigningKey("ed25519-current")
	if !ok || !bytes.Equal(pubWithID, pub) {
		t.Error("single-key compatibility mode should verify anchors with non-empty pubkey_id")
	}
}

// TestSigningKeyring_ExtraKeysNotError — extra keys in keyring don't cause errors.
func TestSigningKeyring_ExtraKeysNotError(t *testing.T) {
	pub1, priv1 := generateTestKeyPair(t)
	pub_extra, _ := generateTestKeyPair(t)

	a := testAnchorRecord()
	_ = SignAnchor(a, priv1, "key-v1")

	keyring := NewSigningKeyring(map[string]ed25519.PublicKey{
		"key-v1":    pub1,
		"extra-key": pub_extra, // not used by any anchor — not an error
	}, nil)

	pub, ok := keyring.LookupSigningKey("key-v1")
	if !ok || !VerifyAnchorSignature(a, pub) {
		t.Error("extra keys in keyring should not affect valid anchor verification")
	}
}

// ---------------------------------------------------------------------------
// ChainSecretKeyring tests
// ---------------------------------------------------------------------------

// TestChainSecretKeyring_SingleSecret_BackwardCompat — SingleSecretKeyring
// covers all seq_nos, equivalent to old single-secret VerifyAuditLogs.
func TestChainSecretKeyring_SingleSecret_BackwardCompat(t *testing.T) {
	secret := []byte("test-chain-secret-32-chars-padded")
	keyring := SingleSecretKeyring(secret)

	for _, seqNo := range []int64{0, 1, 100, 999999} {
		s, ok := keyring.LookupSecret(seqNo)
		if !ok {
			t.Errorf("seq_no %d: expected ok=true for single-secret keyring", seqNo)
		}
		if string(s) != string(secret) {
			t.Errorf("seq_no %d: wrong secret returned", seqNo)
		}
	}
}

// TestChainSecretKeyring_LookupBySeqNo — correct epoch returned per seq_no.
func TestChainSecretKeyring_LookupBySeqNo(t *testing.T) {
	secret1 := []byte("epoch-1-secret-32-chars-xxxxxxxxx")
	secret2 := []byte("epoch-2-secret-32-chars-xxxxxxxxx")

	keyring, err := NewChainSecretKeyring([]ChainEpoch{
		{FromSeqNo: 0, ToSeqNo: 999, Secret: secret1},
		{FromSeqNo: 1000, ToSeqNo: -1, Secret: secret2},
	})
	if err != nil {
		t.Fatalf("NewChainSecretKeyring: %v", err)
	}

	cases := []struct {
		seqNo   int64
		wantSec []byte
		wantOK  bool
	}{
		{0, secret1, true},
		{500, secret1, true},
		{999, secret1, true},
		{1000, secret2, true},
		{999999, secret2, true},
	}
	for _, c := range cases {
		got, ok := keyring.LookupSecret(c.seqNo)
		if ok != c.wantOK {
			t.Errorf("seq_no=%d: ok=%v, want %v", c.seqNo, ok, c.wantOK)
		}
		if ok && string(got) != string(c.wantSec) {
			t.Errorf("seq_no=%d: wrong secret", c.seqNo)
		}
	}
}

// TestChainSecretKeyring_UnknownSeqNo_ReturnsFalse — seq_no not covered by
// any epoch returns (nil, false) for fail-closed behavior.
func TestChainSecretKeyring_UnknownSeqNo_ReturnsFalse(t *testing.T) {
	keyring, _ := NewChainSecretKeyring([]ChainEpoch{
		{FromSeqNo: 100, ToSeqNo: 200, Secret: []byte("secret-1-padded-to-32-chars-xxxx")},
	})

	// seq_no 50 is below the epoch range.
	s, ok := keyring.LookupSecret(50)
	if ok || s != nil {
		t.Error("seq_no below epoch range should return (nil, false)")
	}
	// seq_no 250 is above the epoch range (no unbounded epoch).
	s, ok = keyring.LookupSecret(250)
	if ok || s != nil {
		t.Error("seq_no above epoch range should return (nil, false)")
	}
}

// TestChainSecretKeyring_Validation_EmptySecret_Error.
func TestChainSecretKeyring_Validation_EmptySecret_Error(t *testing.T) {
	_, err := NewChainSecretKeyring([]ChainEpoch{
		{FromSeqNo: 0, ToSeqNo: -1, Secret: nil},
	})
	if err == nil {
		t.Error("empty secret should return error")
	}
}

// TestChainSecretKeyring_Validation_Overlap_Error.
func TestChainSecretKeyring_Validation_Overlap_Error(t *testing.T) {
	_, err := NewChainSecretKeyring([]ChainEpoch{
		{FromSeqNo: 0, ToSeqNo: 100, Secret: []byte("s1padded32charsxxxxxxxxxxxxxxxxx")},
		{FromSeqNo: 50, ToSeqNo: 200, Secret: []byte("s2padded32charsxxxxxxxxxxxxxxxxx")}, // overlaps
	})
	if err == nil {
		t.Error("overlapping epochs should return error")
	}
}

// ---------------------------------------------------------------------------
// Keyring file loading tests
// ---------------------------------------------------------------------------

func TestLoadSigningKeyringFromFile(t *testing.T) {
	pub1, _ := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)

	jk := signingKeyringJSON{
		Keys: map[string]string{
			"v1": base64.StdEncoding.EncodeToString(pub1),
			"v2": base64.StdEncoding.EncodeToString(pub2),
		},
	}
	data, _ := json.Marshal(jk)
	f, _ := os.CreateTemp(t.TempDir(), "keyring-*.json")
	f.Write(data)
	f.Close()

	kr, err := LoadSigningKeyringFromFile(f.Name())
	if err != nil {
		t.Fatalf("LoadSigningKeyringFromFile: %v", err)
	}
	k, ok := kr.LookupSigningKey("v1")
	if !ok || string(k) != string(pub1) {
		t.Error("v1 key not loaded correctly")
	}
}

func TestLoadChainSecretKeyringFromFile(t *testing.T) {
	s1 := []byte("epoch1-secret-32-chars-xxxxxxxxxx")
	s2 := []byte("epoch2-secret-32-chars-xxxxxxxxxx")

	jk := chainKeyringJSON{
		Epochs: []chainEpochJSON{
			{FromSeqNo: 0, ToSeqNo: 999, SecretBase64: base64.StdEncoding.EncodeToString(s1)},
			{FromSeqNo: 1000, ToSeqNo: -1, SecretBase64: base64.StdEncoding.EncodeToString(s2)},
		},
	}
	data, _ := json.Marshal(jk)
	f, _ := os.CreateTemp(t.TempDir(), "chain-keyring-*.json")
	f.Write(data)
	f.Close()

	kr, err := LoadChainSecretKeyringFromFile(f.Name())
	if err != nil {
		t.Fatalf("LoadChainSecretKeyringFromFile: %v", err)
	}
	secret, ok := kr.LookupSecret(500)
	if !ok || string(secret) != string(s1) {
		t.Error("epoch 1 secret not returned for seq_no 500")
	}
	secret, ok = kr.LookupSecret(1500)
	if !ok || string(secret) != string(s2) {
		t.Error("epoch 2 secret not returned for seq_no 1500")
	}
}

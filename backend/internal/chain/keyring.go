// Package chain — W7: key epoch model for HMAC chain secret rotation and
// Ed25519 signing key rotation.
//
// Two independent keyring types:
//
//	SigningKeyring — maps pubkey_id → ed25519.PublicKey for anchor signature
//	  verification across key rotation epochs. Anchors without pubkey_id
//	  ("legacy") are verified with the optional legacyKey.
//
//	ChainSecretKeyring — maps seq_no ranges to HMAC secrets.
//	  Rows in epoch 1 (seq_no 0..N) are verified with secret_1;
//	  rows in epoch 2 (seq_no N+1..) with secret_2, etc.
//	  No DB schema change required — epoch is determined by seq_no at verify time.
//
// Backward-compatible constructors:
//
//	SingleKeyKeyring(pubKey)    — wraps one key; treats ALL anchors as legacy
//	SingleSecretKeyring(secret) — wraps one secret; covers all seq_nos
package chain

import (
	"crypto/ed25519"
	"fmt"
	"sort"
)

// ---------------------------------------------------------------------------
// SigningKeyring
// ---------------------------------------------------------------------------

// SigningKeyring holds Ed25519 public keys indexed by pubkey_id.
// Supports multi-epoch anchor signature verification after key rotation.
type SigningKeyring struct {
	keys      map[string]ed25519.PublicKey
	legacyKey ed25519.PublicKey // used for anchors with empty pubkey_id (pre-W4.1)
}

// NewSigningKeyring creates a keyring from a pubkey_id→pubKey map.
// legacyKey may be nil if all anchors are expected to have a pubkey_id.
// Extra keys in the keyring (not referenced by any anchor) are not an error.
func NewSigningKeyring(keys map[string]ed25519.PublicKey, legacyKey ed25519.PublicKey) *SigningKeyring {
	k := &SigningKeyring{
		keys:      make(map[string]ed25519.PublicKey, len(keys)),
		legacyKey: legacyKey,
	}
	for id, pub := range keys {
		k.keys[id] = pub
	}
	return k
}

// SingleKeyKeyring wraps a single public key as the legacy key.
// Backward-compatible: equivalent to passing the key to VerifyAnchorSignatures.
// All anchors (with or without pubkey_id) are verified with this key.
func SingleKeyKeyring(pubKey ed25519.PublicKey) *SigningKeyring {
	return &SigningKeyring{legacyKey: pubKey}
}

// LookupSigningKey returns the Ed25519 public key for the given pubkey_id.
//
//   - empty pubKeyID (legacy anchor)  → (legacyKey, legacyKey != nil)
//   - non-empty, found in keyring     → (key, true)
//   - single-key compatibility mode   → (legacyKey, true) for any pubkey_id
//   - non-empty, NOT in real keyring  → (nil, false)  ← fail-closed: caller must reject
func (k *SigningKeyring) LookupSigningKey(pubKeyID string) (ed25519.PublicKey, bool) {
	if pubKeyID == "" {
		return k.legacyKey, k.legacyKey != nil
	}
	key, ok := k.keys[pubKeyID]
	if ok {
		return key, true
	}
	if len(k.keys) == 0 && k.legacyKey != nil {
		return k.legacyKey, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// ChainSecretKeyring
// ---------------------------------------------------------------------------

// ChainEpoch maps a contiguous seq_no range to an HMAC secret.
// Rows with seq_no ∈ [FromSeqNo, ToSeqNo] use Secret.
// ToSeqNo = -1 means "no upper bound" (covers the current/latest epoch).
type ChainEpoch struct {
	FromSeqNo int64  // inclusive lower bound; 0 = from beginning
	ToSeqNo   int64  // inclusive upper bound; -1 = unbounded (latest epoch)
	Secret    []byte // HMAC-SHA256 key for rows in this range
}

// ChainSecretKeyring maps seq_no ranges to HMAC secrets.
// Enables verification of chains that span multiple AUDIT_CHAIN_SECRET rotations.
type ChainSecretKeyring struct {
	epochs []ChainEpoch // sorted by FromSeqNo ascending
}

// NewChainSecretKeyring creates a keyring from a list of epochs.
// Validates that:
//   - at least one epoch is provided,
//   - epochs are non-overlapping (no two epochs cover the same seq_no),
//   - at most one epoch has ToSeqNo=-1 (unbounded) and it must be the last.
func NewChainSecretKeyring(epochs []ChainEpoch) (*ChainSecretKeyring, error) {
	if len(epochs) == 0 {
		return nil, fmt.Errorf("chain keyring: at least one epoch required")
	}
	// Sort by FromSeqNo ascending so LookupSecret can binary-search.
	sorted := make([]ChainEpoch, len(epochs))
	copy(sorted, epochs)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].FromSeqNo < sorted[j].FromSeqNo
	})
	// Validate: no overlap, at most one unbounded at the end.
	for i, e := range sorted {
		if len(e.Secret) == 0 {
			return nil, fmt.Errorf("chain keyring: epoch %d has empty secret", i)
		}
		if e.ToSeqNo != -1 && e.ToSeqNo < e.FromSeqNo {
			return nil, fmt.Errorf("chain keyring: epoch %d to_seq_no %d < from_seq_no %d",
				i, e.ToSeqNo, e.FromSeqNo)
		}
		if e.ToSeqNo == -1 && i != len(sorted)-1 {
			return nil, fmt.Errorf("chain keyring: epoch %d has to_seq_no=-1 (unbounded) but is not the last epoch", i)
		}
		if i > 0 {
			prev := sorted[i-1]
			if prev.ToSeqNo != -1 && e.FromSeqNo <= prev.ToSeqNo {
				return nil, fmt.Errorf("chain keyring: epoch %d overlaps with epoch %d", i, i-1)
			}
		}
	}
	return &ChainSecretKeyring{epochs: sorted}, nil
}

// SingleSecretKeyring wraps a single HMAC secret covering all seq_nos.
// Backward-compatible: equivalent to calling VerifyAuditLogs(ctx, db, secret).
func SingleSecretKeyring(secret []byte) *ChainSecretKeyring {
	return &ChainSecretKeyring{epochs: []ChainEpoch{{FromSeqNo: 0, ToSeqNo: -1, Secret: secret}}}
}

// LookupSecret returns the HMAC secret for the given seq_no.
// Returns (nil, false) if no epoch covers this seq_no — caller must treat as
// verification failure (fail-closed).
func (k *ChainSecretKeyring) LookupSecret(seqNo int64) ([]byte, bool) {
	for _, e := range k.epochs {
		if seqNo < e.FromSeqNo {
			continue
		}
		if e.ToSeqNo == -1 || seqNo <= e.ToSeqNo {
			return e.Secret, true
		}
	}
	return nil, false
}

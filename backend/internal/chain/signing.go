package chain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ManifestCanonical builds the deterministic signable payload for an anchor.
// Canonical format: v1|table|seq_lo|seq_hi|row_count|merkle_root_hex|
//                      created_at_epoch|sink_name|sink_ref|pubkey_id
//
// All fields are fixed-order, no escaping (field values come from controlled
// internal sources, not user input). created_at = Unix epoch (UTC integer)
// for platform-independent determinism. merkle_root_hex = lowercase hex.
// NULL/empty fields included as empty strings between separators.
//
// The canonical is signed AFTER sink write, so sink_name and sink_ref are
// included and covered by the signature.
func ManifestCanonical(a *AnchorRecord) string {
	var sb strings.Builder
	sb.WriteString("v1")
	sb.WriteByte('|')
	sb.WriteString(a.TableName)
	sb.WriteByte('|')
	sb.WriteString(strconv.FormatInt(a.SeqLo, 10))
	sb.WriteByte('|')
	sb.WriteString(strconv.FormatInt(a.SeqHi, 10))
	sb.WriteByte('|')
	sb.WriteString(strconv.Itoa(a.RowCount))
	sb.WriteByte('|')
	sb.WriteString(hex.EncodeToString(a.MerkleRoot))
	sb.WriteByte('|')
	sb.WriteString(strconv.FormatInt(a.CreatedAt.UTC().Unix(), 10))
	sb.WriteByte('|')
	sb.WriteString(a.SinkName)
	sb.WriteByte('|')
	sb.WriteString(a.SinkRef)
	sb.WriteByte('|')
	sb.WriteString(a.PubKeyID)
	return sb.String()
}

// SignAnchor signs the manifest canonical with an Ed25519 private key.
// Sets a.PubKeyID and a.Signature on the record.
// privKey must be a 64-byte Ed25519 private key.
func SignAnchor(a *AnchorRecord, privKey ed25519.PrivateKey, pubKeyID string) error {
	if len(privKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("signing: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(privKey))
	}
	a.PubKeyID = pubKeyID
	canonical := ManifestCanonical(a)
	a.Signature = ed25519.Sign(privKey, []byte(canonical))
	return nil
}

// VerifyAnchorSignature verifies the Ed25519 signature on an anchor.
// Returns false if signature is nil/empty (unsigned), key mismatch,
// or tampered canonical.
//
// pubKey must be a 32-byte Ed25519 public key.
// The public key is NOT stored in DB — caller provides it from a trusted
// out-of-band source (file, env var) so a DBA cannot re-sign by replacing
// the DB key.
func VerifyAnchorSignature(a *AnchorRecord, pubKey ed25519.PublicKey) bool {
	if len(a.Signature) == 0 {
		return false
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return false
	}
	canonical := ManifestCanonical(a)
	return ed25519.Verify(pubKey, []byte(canonical), a.Signature)
}

// ParsePrivateKey decodes a base64-standard Ed25519 private key.
// Accepts 64-byte (standard combined) or 32-byte (seed only) forms.
func ParsePrivateKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Try URL-safe encoding as fallback.
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("signing: decode private key: %w", err)
		}
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("signing: private key must be %d or %d bytes, got %d",
			ed25519.PrivateKeySize, ed25519.SeedSize, len(raw))
	}
}

// ParsePublicKey decodes a base64-standard Ed25519 public key (32 bytes).
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("signing: decode public key: %w", err)
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing: public key must be %d bytes, got %d",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

package chain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// signingKeyringJSON — JSON format for signing keyring files.
// Example:
//
//	{
//	  "keys": {
//	    "ed25519-2026-Q1": "base64pubkey...",
//	    "ed25519-2026-Q2": "base64pubkey..."
//	  },
//	  "legacy_key": "base64pubkey..."
//	}
//
// legacy_key is optional; used for anchors with empty pubkey_id.
type signingKeyringJSON struct {
	Keys      map[string]string `json:"keys"`
	LegacyKey string            `json:"legacy_key,omitempty"`
}

// LoadSigningKeyringFromFile reads a JSON signing keyring file.
// Returns an error if the file cannot be read or any key fails to parse.
func LoadSigningKeyringFromFile(path string) (*SigningKeyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signing keyring: read %s: %w", path, err)
	}
	var jk signingKeyringJSON
	if err := json.Unmarshal(data, &jk); err != nil {
		return nil, fmt.Errorf("signing keyring: parse %s: %w", path, err)
	}
	keys := make(map[string]ed25519.PublicKey, len(jk.Keys))
	for id, b64 := range jk.Keys {
		pub, err := parsePublicKeyB64(b64)
		if err != nil {
			return nil, fmt.Errorf("signing keyring: key %q: %w", id, err)
		}
		keys[id] = pub
	}
	var legacyKey ed25519.PublicKey
	if jk.LegacyKey != "" {
		legacyKey, err = parsePublicKeyB64(jk.LegacyKey)
		if err != nil {
			return nil, fmt.Errorf("signing keyring: legacy_key: %w", err)
		}
	}
	return NewSigningKeyring(keys, legacyKey), nil
}

// chainKeyringJSON — JSON format for chain secret keyring files.
// Example:
//
//	{
//	  "epochs": [
//	    {"from_seq_no": 0, "to_seq_no": 9999, "secret_base64": "base64..."},
//	    {"from_seq_no": 10000, "to_seq_no": -1, "secret_base64": "base64..."}
//	  ]
//	}
//
// to_seq_no=-1 means unbounded (current/latest epoch); must be the last entry.
type chainKeyringJSON struct {
	Epochs []chainEpochJSON `json:"epochs"`
}

type chainEpochJSON struct {
	FromSeqNo    int64  `json:"from_seq_no"`
	ToSeqNo      int64  `json:"to_seq_no"`
	SecretBase64 string `json:"secret_base64"`
}

// LoadChainSecretKeyringFromFile reads a JSON chain secret keyring file.
func LoadChainSecretKeyringFromFile(path string) (*ChainSecretKeyring, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("chain keyring: read %s: %w", path, err)
	}
	var jk chainKeyringJSON
	if err := json.Unmarshal(data, &jk); err != nil {
		return nil, fmt.Errorf("chain keyring: parse %s: %w", path, err)
	}
	if len(jk.Epochs) == 0 {
		return nil, fmt.Errorf("chain keyring: %s: no epochs defined", path)
	}
	epochs := make([]ChainEpoch, len(jk.Epochs))
	for i, e := range jk.Epochs {
		if e.SecretBase64 == "" {
			return nil, fmt.Errorf("chain keyring: epoch %d: secret_base64 is required", i)
		}
		secret, err := base64.StdEncoding.DecodeString(e.SecretBase64)
		if err != nil {
			secret, err = base64.URLEncoding.DecodeString(e.SecretBase64)
			if err != nil {
				return nil, fmt.Errorf("chain keyring: epoch %d: invalid secret_base64: %w", i, err)
			}
		}
		epochs[i] = ChainEpoch{
			FromSeqNo: e.FromSeqNo,
			ToSeqNo:   e.ToSeqNo,
			Secret:    secret,
		}
	}
	return NewChainSecretKeyring(epochs)
}

// parsePublicKeyB64 decodes a base64-encoded Ed25519 public key (standard or URL-safe).
func parsePublicKeyB64(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode public key: %w", err)
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

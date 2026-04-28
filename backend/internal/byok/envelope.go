package byok

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	EnvelopePrefix = "byok:v1:"

	AlgAES256GCM    = "AES-256-GCM"
	AlgVaultTransit = "VAULT-TRANSIT"
)

type Envelope struct {
	V     int    `json:"v"`
	Alg   string `json:"alg"`
	KID   string `json:"kid"`
	Field string `json:"field,omitempty"`
	IV    string `json:"iv,omitempty"`
	CT    string `json:"ct"`
	Tag   string `json:"tag,omitempty"`
}

func EncodeEnvelope(env Envelope) (string, error) {
	if env.V == 0 {
		env.V = 1
	}
	if env.Alg == "" {
		return "", errors.New("byok envelope: alg is required")
	}
	if env.KID == "" {
		return "", errors.New("byok envelope: kid is required")
	}
	if env.CT == "" {
		return "", errors.New("byok envelope: ct is required")
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("byok envelope marshal: %w", err)
	}
	return EnvelopePrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeEnvelope(value string) (Envelope, error) {
	if !IsEnvelopeString(value) {
		return Envelope{}, errors.New("value is not a BYOK envelope")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, EnvelopePrefix))
	if err != nil {
		return Envelope{}, fmt.Errorf("byok envelope base64: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Envelope{}, fmt.Errorf("byok envelope json: %w", err)
	}
	if env.V != 1 {
		return Envelope{}, fmt.Errorf("unsupported BYOK envelope version %d", env.V)
	}
	if env.Alg == "" || env.KID == "" || env.CT == "" {
		return Envelope{}, errors.New("invalid BYOK envelope: alg, kid and ct are required")
	}
	return env, nil
}

func IsEnvelopeString(value string) bool {
	return strings.HasPrefix(value, EnvelopePrefix)
}

package byok

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

type AESGCMEncryptor struct {
	kid  string
	aead cipher.AEAD
}

func NewAESGCMEncryptor(kid string, key []byte) (*AESGCMEncryptor, error) {
	if kid == "" {
		return nil, errors.New("AES-GCM BYOK kid is required")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-GCM BYOK key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM mode: %w", err)
	}
	return &AESGCMEncryptor{kid: kid, aead: aead}, nil
}

func (e *AESGCMEncryptor) EncryptField(ctx context.Context, orgID, field, plaintext string) (string, error) {
	_ = ctx
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("AES-GCM nonce: %w", err)
	}
	_ = orgID
	aad := []byte(field)
	sealed := e.aead.Seal(nil, nonce, []byte(plaintext), aad)
	tagSize := e.aead.Overhead()
	env := Envelope{
		V:     1,
		Alg:   AlgAES256GCM,
		KID:   e.kid,
		Field: field,
		IV:    base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(sealed[:len(sealed)-tagSize]),
		Tag:   base64.StdEncoding.EncodeToString(sealed[len(sealed)-tagSize:]),
	}
	return EncodeEnvelope(env)
}

func (e *AESGCMEncryptor) DecryptField(ctx context.Context, ciphertext string) (string, error) {
	_ = ctx
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		return "", err
	}
	if env.Alg != AlgAES256GCM {
		return "", fmt.Errorf("AES-GCM decrypt received %s envelope", env.Alg)
	}
	if env.KID != e.kid {
		return "", fmt.Errorf("AES-GCM kid mismatch: envelope=%q configured=%q", env.KID, e.kid)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.IV)
	if err != nil {
		return "", fmt.Errorf("AES-GCM nonce decode: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(env.CT)
	if err != nil {
		return "", fmt.Errorf("AES-GCM ciphertext decode: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(env.Tag)
	if err != nil {
		return "", fmt.Errorf("AES-GCM tag decode: %w", err)
	}
	sealed := append(ct, tag...)
	plaintext, err := e.aead.Open(nil, nonce, sealed, []byte(env.Field))
	if err != nil {
		return "", fmt.Errorf("AES-GCM open: %w", err)
	}
	return string(plaintext), nil
}

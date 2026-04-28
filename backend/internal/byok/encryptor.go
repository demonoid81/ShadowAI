package byok

import "context"

type Encryptor interface {
	EncryptField(ctx context.Context, orgID, field, plaintext string) (string, error)
	DecryptField(ctx context.Context, ciphertext string) (string, error)
}

func EncryptString(ctx context.Context, enc Encryptor, orgID, field, plaintext string) (string, error) {
	if enc == nil || plaintext == "" {
		return plaintext, nil
	}
	return enc.EncryptField(ctx, orgID, field, plaintext)
}

func DecryptString(ctx context.Context, enc Encryptor, value string) (string, error) {
	if enc == nil || value == "" || !IsEnvelopeString(value) {
		return value, nil
	}
	return enc.DecryptField(ctx, value)
}

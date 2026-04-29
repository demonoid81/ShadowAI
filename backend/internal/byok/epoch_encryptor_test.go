package byok

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeEpochInner struct {
	providerKID string
}

func (f fakeEpochInner) EncryptField(ctx context.Context, orgID, field, plaintext string) (string, error) {
	_ = ctx
	_ = orgID
	return EncodeEnvelope(Envelope{
		V:     1,
		Alg:   AlgVaultTransit,
		KID:   f.providerKID,
		Field: field,
		CT:    "cipher:" + plaintext,
	})
}

func (f fakeEpochInner) DecryptField(ctx context.Context, ciphertext string) (string, error) {
	_ = ctx
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		return "", err
	}
	if env.KID != f.providerKID {
		return "", errors.New("provider kid mismatch")
	}
	return "plain:" + env.CT, nil
}

type fakeEpochStore struct {
	active map[string]Epoch
	byKID  map[string]Epoch
}

func (s fakeEpochStore) ActiveEpoch(ctx context.Context, orgID string) (Epoch, error) {
	_ = ctx
	if e, ok := s.active[orgID]; ok {
		return e, nil
	}
	return Epoch{}, ErrNoActiveEpoch
}

func (s fakeEpochStore) EpochByKID(ctx context.Context, kid string) (Epoch, error) {
	_ = ctx
	if e, ok := s.byKID[kid]; ok {
		return e, nil
	}
	return Epoch{}, ErrUnknownEpoch
}

func testEpoch(orgID, kid, status string) Epoch {
	return Epoch{
		ID:          "epoch-id",
		OrgID:       orgID,
		KID:         kid,
		Provider:    "vault_transit",
		ProviderKID: "vault:transit/audit-key",
		Status:      status,
		CreatedAt:   time.Unix(100, 0).UTC(),
	}
}

func TestEpochEncryptor_NewWriteUsesActiveTenantEpoch(t *testing.T) {
	store := fakeEpochStore{
		active: map[string]Epoch{"org-a": testEpoch("org-a", "tenant:org-a:dek:2026-Q2", EpochStatusActive)},
		byKID:  map[string]Epoch{},
	}
	enc := NewEpochEncryptor(fakeEpochInner{providerKID: "vault:transit/audit-key"}, store, EpochOptions{RequireActive: true})

	ciphertext, err := enc.EncryptField(context.Background(), "org-a", "request_body", "prompt")
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		t.Fatalf("DecodeEnvelope: %v", err)
	}
	if env.KID != "tenant:org-a:dek:2026-Q2" {
		t.Fatalf("KID=%q", env.KID)
	}
	if env.ProviderKID != "vault:transit/audit-key" {
		t.Fatalf("ProviderKID=%q", env.ProviderKID)
	}
	if env.OrgID != "org-a" {
		t.Fatalf("OrgID=%q", env.OrgID)
	}
}

func TestEpochEncryptor_DecryptOldEpochAfterRotation(t *testing.T) {
	oldEpoch := testEpoch("org-a", "tenant:org-a:dek:2026-Q1", EpochStatusRetired)
	newEpoch := testEpoch("org-a", "tenant:org-a:dek:2026-Q2", EpochStatusActive)
	store := fakeEpochStore{
		active: map[string]Epoch{"org-a": newEpoch},
		byKID:  map[string]Epoch{oldEpoch.KID: oldEpoch, newEpoch.KID: newEpoch},
	}
	enc := NewEpochEncryptor(fakeEpochInner{providerKID: "vault:transit/audit-key"}, store, EpochOptions{RequireActive: true})

	oldEnv, err := EncodeEnvelope(Envelope{
		V:           1,
		Alg:         AlgVaultTransit,
		KID:         oldEpoch.KID,
		ProviderKID: oldEpoch.ProviderKID,
		OrgID:       oldEpoch.OrgID,
		Field:       "response_body",
		CT:          "cipher:old",
	})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	plaintext, err := enc.DecryptField(context.Background(), oldEnv)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if plaintext != "plain:cipher:old" {
		t.Fatalf("plaintext=%q", plaintext)
	}
}

func TestEpochEncryptor_NoActiveEpochFailsClosedWhenRequired(t *testing.T) {
	enc := NewEpochEncryptor(fakeEpochInner{providerKID: "vault:transit/audit-key"}, fakeEpochStore{}, EpochOptions{RequireActive: true})
	_, err := enc.EncryptField(context.Background(), "org-a", "request_body", "prompt")
	if !errors.Is(err, ErrNoActiveEpoch) {
		t.Fatalf("err=%v, want ErrNoActiveEpoch", err)
	}
}

func TestEpochEncryptor_RevokedEpochRejectedForNewWrites(t *testing.T) {
	revoked := testEpoch("org-a", "tenant:org-a:dek:2026-Q1", EpochStatusRevoked)
	store := fakeEpochStore{active: map[string]Epoch{"org-a": revoked}}
	enc := NewEpochEncryptor(fakeEpochInner{providerKID: "vault:transit/audit-key"}, store, EpochOptions{RequireActive: true})
	_, err := enc.EncryptField(context.Background(), "org-a", "request_body", "prompt")
	if !errors.Is(err, ErrEpochNotUsable) {
		t.Fatalf("err=%v, want ErrEpochNotUsable", err)
	}
}

func TestEpochEncryptor_CrossTenantEnvelopeRejected(t *testing.T) {
	epoch := testEpoch("org-a", "tenant:org-a:dek:2026-Q1", EpochStatusActive)
	store := fakeEpochStore{byKID: map[string]Epoch{epoch.KID: epoch}}
	enc := NewEpochEncryptor(fakeEpochInner{providerKID: "vault:transit/audit-key"}, store, EpochOptions{RequireActive: true})
	crossTenantEnv, err := EncodeEnvelope(Envelope{
		V:           1,
		Alg:         AlgVaultTransit,
		KID:         epoch.KID,
		ProviderKID: epoch.ProviderKID,
		OrgID:       "org-b",
		Field:       "request_body",
		CT:          "cipher:prompt",
	})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	_, err = enc.DecryptField(context.Background(), crossTenantEnv)
	if err == nil || !strings.Contains(err.Error(), "cross-tenant") {
		t.Fatalf("err=%v, want cross-tenant rejection", err)
	}
}

func TestEpochEncryptor_LegacyEnvelopeFallsBackToInnerDecrypt(t *testing.T) {
	legacy, err := EncodeEnvelope(Envelope{
		V:     1,
		Alg:   AlgVaultTransit,
		KID:   "vault:transit/audit-key",
		Field: "request_body",
		CT:    "cipher:legacy",
	})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	enc := NewEpochEncryptor(fakeEpochInner{providerKID: "vault:transit/audit-key"}, fakeEpochStore{}, EpochOptions{RequireActive: true})
	got, err := enc.DecryptField(context.Background(), legacy)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if got != "plain:cipher:legacy" {
		t.Fatalf("got=%q", got)
	}
}

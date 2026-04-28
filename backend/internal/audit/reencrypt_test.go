package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/shadowai/backend/internal/byok"
)

func TestNeedsPayloadEncryption(t *testing.T) {
	validEnv, err := byok.EncodeEnvelope(byok.Envelope{V: 1, Alg: byok.AlgVaultTransit, KID: "vault:transit/audit-key", Field: "request_body", CT: "vault:v1:x"})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "empty", value: "", want: false},
		{name: "plaintext", value: "legacy prompt", want: true},
		{name: "valid envelope", value: validEnv, want: false},
		{name: "invalid envelope prefix is plaintext", value: "byok:v1:not-base64", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsPayloadEncryption(tt.value); got != tt.want {
				t.Fatalf("needsPayloadEncryption(%q)=%v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestReencryptPayloadValues_EncryptsOnlyLegacyFields(t *testing.T) {
	validEnv, err := byok.EncodeEnvelope(byok.Envelope{V: 1, Alg: byok.AlgVaultTransit, KID: "vault:transit/audit-key", Field: "response_body", CT: "vault:v1:x"})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	enc := &stubPayloadEncryptor{}

	got, changedReq, changedResp, err := reencryptPayloadValues(context.Background(), enc, "org-a", auditPayloadSweepRow{
		RequestBody:  "legacy prompt",
		ResponseBody: validEnv,
	})
	if err != nil {
		t.Fatalf("reencryptPayloadValues: %v", err)
	}
	if !changedReq || changedResp {
		t.Fatalf("changedReq=%v changedResp=%v", changedReq, changedResp)
	}
	if got.RequestBody != "enc(request_body:legacy prompt)" || got.ResponseBody != validEnv {
		t.Fatalf("unexpected payloads: %+v", got)
	}
	if len(enc.calls) != 1 || enc.calls[0] != "encrypt:org-a:request_body:legacy prompt" {
		t.Fatalf("unexpected encrypt calls: %v", enc.calls)
	}
}

func TestReencryptPayloadValues_EmptyRowNoop(t *testing.T) {
	enc := &stubPayloadEncryptor{}
	got, changedReq, changedResp, err := reencryptPayloadValues(context.Background(), enc, "org-a", auditPayloadSweepRow{})
	if err != nil {
		t.Fatalf("reencryptPayloadValues: %v", err)
	}
	if changedReq || changedResp || got.RequestBody != "" || got.ResponseBody != "" {
		t.Fatalf("expected noop, got row=%+v changedReq=%v changedResp=%v", got, changedReq, changedResp)
	}
	if len(enc.calls) != 0 {
		t.Fatalf("unexpected encrypt calls: %v", enc.calls)
	}
}

func TestReencryptPayloadValues_KMSErrorFailsClosed(t *testing.T) {
	enc := &stubPayloadEncryptor{encryptErr: errors.New("kms down")}
	_, _, _, err := reencryptPayloadValues(context.Background(), enc, "org-a", auditPayloadSweepRow{RequestBody: "legacy"})
	if err == nil {
		t.Fatal("expected KMS error")
	}
}

func TestReencryptLegacyPayloads_RequiresEncryptorUnlessDryRun(t *testing.T) {
	repo := NewRepository(nil)
	if _, err := repo.ReencryptLegacyPayloads(context.Background(), ReencryptOptions{Limit: 1}); err == nil {
		t.Fatal("expected missing encryptor error")
	}
}

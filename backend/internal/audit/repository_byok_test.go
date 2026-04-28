package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/domain"
)

type stubPayloadEncryptor struct {
	encryptErr error
	decryptErr error
	calls      []string
}

func (s *stubPayloadEncryptor) EncryptField(ctx context.Context, orgID, field, plaintext string) (string, error) {
	s.calls = append(s.calls, "encrypt:"+orgID+":"+field+":"+plaintext)
	if s.encryptErr != nil {
		return "", s.encryptErr
	}
	return "enc(" + field + ":" + plaintext + ")", nil
}

func (s *stubPayloadEncryptor) DecryptField(ctx context.Context, ciphertext string) (string, error) {
	s.calls = append(s.calls, "decrypt:"+ciphertext)
	if s.decryptErr != nil {
		return "", s.decryptErr
	}
	return "dec(" + ciphertext + ")", nil
}

func TestPreparePayloadsForWrite_EncryptsRequestAndResponse(t *testing.T) {
	enc := &stubPayloadEncryptor{}
	repo := NewRepository(nil).WithPayloadEncryptor(enc)
	log := &domain.AuditLog{
		OrgID:        "org-a",
		RequestBody:  "prompt",
		ResponseBody: "answer",
	}

	req, resp, err := repo.preparePayloadsForWrite(context.Background(), log)
	if err != nil {
		t.Fatalf("preparePayloadsForWrite: %v", err)
	}
	if req != "enc(request_body:prompt)" || resp != "enc(response_body:answer)" {
		t.Fatalf("encrypted payloads req=%q resp=%q", req, resp)
	}
	wantCalls := []string{
		"encrypt:org-a:request_body:prompt",
		"encrypt:org-a:response_body:answer",
	}
	if len(enc.calls) != len(wantCalls) {
		t.Fatalf("calls=%v", enc.calls)
	}
	for i := range wantCalls {
		if enc.calls[i] != wantCalls[i] {
			t.Fatalf("call[%d]=%q, want %q", i, enc.calls[i], wantCalls[i])
		}
	}
	if log.RequestBody != "prompt" || log.ResponseBody != "answer" {
		t.Fatalf("preparePayloadsForWrite must not mutate canonical source log: %+v", log)
	}
}

func TestPreparePayloadsForWrite_SkipsEmptyButEncryptsEnvelopeLiteral(t *testing.T) {
	enc := &stubPayloadEncryptor{}
	env, err := byok.EncodeEnvelope(byok.Envelope{V: 1, Alg: byok.AlgVaultTransit, KID: "vault:transit/audit-key", Field: "response_body", CT: "vault:v1:x"})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	repo := NewRepository(nil).WithPayloadEncryptor(enc)
	log := &domain.AuditLog{RequestBody: "", ResponseBody: env}

	req, resp, err := repo.preparePayloadsForWrite(context.Background(), log)
	if err != nil {
		t.Fatalf("preparePayloadsForWrite: %v", err)
	}
	if req != "" || resp != "enc(response_body:"+env+")" {
		t.Fatalf("payloads req=%q resp=%q", req, resp)
	}
	if len(enc.calls) != 1 || enc.calls[0] != "encrypt:00000000-0000-0000-0000-000000000001:response_body:"+env {
		t.Fatalf("unexpected encrypt calls: %v", enc.calls)
	}
}

func TestDecryptPayloadsAfterRead_DualReadPlaintextAndEnvelope(t *testing.T) {
	enc := &stubPayloadEncryptor{}
	env, err := byok.EncodeEnvelope(byok.Envelope{V: 1, Alg: byok.AlgVaultTransit, KID: "vault:transit/audit-key", Field: "response_body", CT: "vault:v1:x"})
	if err != nil {
		t.Fatalf("EncodeEnvelope: %v", err)
	}
	repo := NewRepository(nil).WithPayloadEncryptor(enc)
	log := &domain.AuditLog{RequestBody: "legacy plaintext", ResponseBody: env}

	if err := repo.decryptPayloadsAfterRead(context.Background(), log); err != nil {
		t.Fatalf("decryptPayloadsAfterRead: %v", err)
	}
	if log.RequestBody != "legacy plaintext" {
		t.Fatalf("legacy plaintext must remain unchanged: %q", log.RequestBody)
	}
	if log.ResponseBody != "dec("+env+")" {
		t.Fatalf("response body=%q", log.ResponseBody)
	}
	if len(enc.calls) != 1 || enc.calls[0] != "decrypt:"+env {
		t.Fatalf("unexpected decrypt calls: %v", enc.calls)
	}
}

func TestPreparePayloadsForWrite_EncryptErrorFailsClosed(t *testing.T) {
	repo := NewRepository(nil).WithPayloadEncryptor(&stubPayloadEncryptor{encryptErr: errors.New("kms down")})
	log := &domain.AuditLog{RequestBody: "prompt"}
	if _, _, err := repo.preparePayloadsForWrite(context.Background(), log); err == nil {
		t.Fatal("preparePayloadsForWrite expected encrypt error")
	}
}

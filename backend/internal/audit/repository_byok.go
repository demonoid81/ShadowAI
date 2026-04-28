package audit

import (
	"context"
	"fmt"

	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/domain"
)

func (r *Repository) preparePayloadsForWrite(ctx context.Context, log *domain.AuditLog) (string, string, error) {
	orgID := log.OrgID
	if orgID == "" {
		orgID = domain.DefaultOrgID
	}
	requestBody, err := byok.EncryptString(ctx, r.payloadEncryptor, orgID, "request_body", log.RequestBody)
	if err != nil {
		return "", "", fmt.Errorf("BYOK encrypt request_body: %w", err)
	}
	responseBody, err := byok.EncryptString(ctx, r.payloadEncryptor, orgID, "response_body", log.ResponseBody)
	if err != nil {
		return "", "", fmt.Errorf("BYOK encrypt response_body: %w", err)
	}
	return requestBody, responseBody, nil
}

func (r *Repository) decryptPayloadsAfterRead(ctx context.Context, log *domain.AuditLog) error {
	requestBody, err := byok.DecryptString(ctx, r.payloadEncryptor, log.RequestBody)
	if err != nil {
		return fmt.Errorf("BYOK decrypt request_body: %w", err)
	}
	responseBody, err := byok.DecryptString(ctx, r.payloadEncryptor, log.ResponseBody)
	if err != nil {
		return fmt.Errorf("BYOK decrypt response_body: %w", err)
	}
	log.RequestBody = requestBody
	log.ResponseBody = responseBody
	return nil
}

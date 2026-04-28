package byok

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type VaultTransitConfig struct {
	Addr       string
	Token      string
	Mount      string
	KeyName    string
	HTTPClient *http.Client
	Timeout    time.Duration
}

type VaultTransitEncryptor struct {
	addr       string
	token      string
	mount      string
	keyName    string
	kid        string
	httpClient *http.Client
}

func NewVaultTransitEncryptor(cfg VaultTransitConfig) (*VaultTransitEncryptor, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.Addr), "/")
	token := strings.TrimSpace(cfg.Token)
	mount := strings.Trim(strings.TrimSpace(cfg.Mount), "/")
	keyName := strings.Trim(strings.TrimSpace(cfg.KeyName), "/")
	if mount == "" {
		mount = "transit"
	}
	if addr == "" {
		return nil, errors.New("BYOK Vault Transit addr is required")
	}
	if token == "" {
		return nil, errors.New("BYOK Vault Transit token is required")
	}
	if keyName == "" {
		return nil, errors.New("BYOK Vault Transit key name is required")
	}
	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	return &VaultTransitEncryptor{
		addr:       addr,
		token:      token,
		mount:      mount,
		keyName:    keyName,
		kid:        "vault:" + mount + "/" + keyName,
		httpClient: client,
	}, nil
}

func (e *VaultTransitEncryptor) EncryptField(ctx context.Context, orgID, field, plaintext string) (string, error) {
	_ = orgID
	var resp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	req := map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString([]byte(plaintext)),
	}
	if err := e.call(ctx, "encrypt", req, &resp); err != nil {
		return "", err
	}
	env := Envelope{
		V:     1,
		Alg:   AlgVaultTransit,
		KID:   e.kid,
		Field: field,
		CT:    resp.Data.Ciphertext,
	}
	return EncodeEnvelope(env)
}

func (e *VaultTransitEncryptor) DecryptField(ctx context.Context, ciphertext string) (string, error) {
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		return "", err
	}
	if env.Alg != AlgVaultTransit {
		return "", fmt.Errorf("Vault Transit decrypt received %s envelope", env.Alg)
	}
	if env.KID != e.kid {
		return "", fmt.Errorf("Vault Transit kid mismatch: envelope=%q configured=%q", env.KID, e.kid)
	}
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	req := map[string]string{"ciphertext": env.CT}
	if err := e.call(ctx, "decrypt", req, &resp); err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return "", fmt.Errorf("Vault Transit plaintext decode: %w", err)
	}
	return string(raw), nil
}

func (e *VaultTransitEncryptor) call(ctx context.Context, op string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("Vault Transit request marshal: %w", err)
	}
	endpoint := e.addr + "/v1/" + url.PathEscape(e.mount) + "/" + op + "/" + url.PathEscape(e.keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("Vault Transit request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", e.token)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("Vault Transit %s: %w", op, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Vault Transit %s status %d: %s", op, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("Vault Transit %s response decode: %w", op, err)
	}
	return nil
}

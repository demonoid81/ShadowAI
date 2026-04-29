package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/byok"
)

type fakeEpochCLIRepo struct {
	created []byok.Epoch
	active  []string
	updates []string
	list    []byok.Epoch
}

func (f *fakeEpochCLIRepo) ListEpochs(ctx context.Context, orgID string) ([]byok.Epoch, error) {
	_ = ctx
	_ = orgID
	return f.list, nil
}

func (f *fakeEpochCLIRepo) CreateEpoch(ctx context.Context, e byok.Epoch) (byok.Epoch, error) {
	_ = ctx
	f.created = append(f.created, e)
	return e, nil
}

func (f *fakeEpochCLIRepo) ActivateEpoch(ctx context.Context, orgID, kid, actor string) error {
	_ = ctx
	f.active = append(f.active, orgID+"|"+kid+"|"+actor)
	return nil
}

func (f *fakeEpochCLIRepo) UpdateEpochStatus(ctx context.Context, orgID, kid, status, actor string) error {
	_ = ctx
	f.updates = append(f.updates, orgID+"|"+kid+"|"+status+"|"+actor)
	return nil
}

func TestRun_CreateEpoch_RequiresOrgAndKid(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithRepo([]string{"--action", "create"}, &stdout, &stderr, &fakeEpochCLIRepo{})
	if code != exitCfg {
		t.Fatalf("exit=%d", code)
	}
	if !strings.Contains(stderr.String(), "--org-id and --kid") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRun_CreateEpoch_WritesMetadata(t *testing.T) {
	repo := &fakeEpochCLIRepo{}
	var stdout, stderr bytes.Buffer
	code := runWithRepo([]string{
		"--action", "create",
		"--org-id", "org-a",
		"--kid", "tenant:org-a:dek:2026-Q2",
		"--provider", "vault_transit",
		"--provider-kid", "vault:transit/audit-key",
		"--status", byok.EpochStatusActive,
		"--metadata-json", `{"ticket":"SEC-1"}`,
	}, &stdout, &stderr, repo)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if len(repo.created) != 1 {
		t.Fatalf("created=%d", len(repo.created))
	}
	got := repo.created[0]
	if got.OrgID != "org-a" || got.KID != "tenant:org-a:dek:2026-Q2" || got.ProviderKID != "vault:transit/audit-key" {
		t.Fatalf("created=%+v", got)
	}
}

func TestRun_InvalidMetadataJSON_ReturnsConfigError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithRepo([]string{"--action", "create", "--metadata-json", "{"}, &stdout, &stderr, &fakeEpochCLIRepo{})
	if code != exitCfg {
		t.Fatalf("exit=%d", code)
	}
}

func TestRun_ActivateEpoch(t *testing.T) {
	repo := &fakeEpochCLIRepo{}
	var stdout, stderr bytes.Buffer
	code := runWithRepo([]string{"--action", "activate", "--org-id", "org-a", "--kid", "kid-a", "--actor-user-id", "actor-a"}, &stdout, &stderr, repo)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if len(repo.active) != 1 || repo.active[0] != "org-a|kid-a|actor-a" {
		t.Fatalf("active=%v", repo.active)
	}
}

func TestRun_RevokeEpoch(t *testing.T) {
	repo := &fakeEpochCLIRepo{}
	var stdout, stderr bytes.Buffer
	code := runWithRepo([]string{"--action", "revoke", "--org-id", "org-a", "--kid", "kid-a"}, &stdout, &stderr, repo)
	if code != exitOK {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if len(repo.updates) != 1 || repo.updates[0] != "org-a|kid-a|revoked|" {
		t.Fatalf("updates=%v", repo.updates)
	}
}

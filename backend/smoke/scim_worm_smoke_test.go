//go:build enterprise && smoke

// PR-O3.1.1: SCIM + WORM/evidence smoke scenarios.
// Extends the enterprise smoke harness with two compliance-critical paths
// that don't require an external IdP or LLM provider.
package smoke

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/auth"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/evidencebundle"
	"github.com/shadowai/backend/internal/scim"
)

const smokeChainSecret = "smoke-chain-secret-at-least-32chars!!"

// ---------------------------------------------------------------------------
// O3.1.1.A — SCIM lifecycle: provision → update → deprovision → reactivate
// ---------------------------------------------------------------------------

// TestSmoke_SCIM_LifecycleProvisionToDeprovision covers the full SCIM user lifecycle:
// provision → update department/role → deprovision → token_version bump → reactivate.
func TestSmoke_SCIM_LifecycleProvisionToDeprovision(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	authRepo := auth.NewRepository(infra.DB)

	scimCfg, err := scim.ParseSyncConfig("user", `{"admins":"admin"}`, "", false)
	if err != nil {
		t.Fatalf("ParseSyncConfig: %v", err)
	}
	syncer := scim.NewUserSyncer(authRepo, scimCfg)

	// 1. Provision new user from IdP.
	result, err := syncer.Provision(ctx, scim.User{
		ExternalID:     "idp-ext-001",
		UserName:       "scim@smoke.test",
		Active:         boolPtrSmoke(true),
		Roles:          []scim.RoleValue{{Value: "user"}},
		EnterpriseUser: &scim.EnterpriseUser{Department: "engineering"},
	})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if result.Action != "provisioned" {
		t.Errorf("action = %q, want provisioned", result.Action)
	}
	if !result.User.IsActive {
		t.Error("provisioned user must be active")
	}
	if result.User.Department == nil || *result.User.Department != "engineering" {
		t.Errorf("department = %v, want engineering", result.User.Department)
	}
	userID := result.User.ID
	t.Logf("smoke/scim: provisioned %s (dept=engineering)", userID)

	// 2. Update department → finance, role → admin via groups mapping.
	updateResult, err := syncer.Provision(ctx, scim.User{
		ExternalID:     "idp-ext-001",
		UserName:       "scim@smoke.test",
		Active:         boolPtrSmoke(true),
		Roles:          []scim.RoleValue{{Value: "admins"}}, // mapped → admin
		EnterpriseUser: &scim.EnterpriseUser{Department: "finance"},
	})
	if err != nil {
		t.Fatalf("Provision (update): %v", err)
	}
	if updateResult.User.Role != "admin" {
		t.Errorf("updated role = %q, want admin", updateResult.User.Role)
	}
	if updateResult.User.Department == nil || *updateResult.User.Department != "finance" {
		t.Errorf("updated dept = %v, want finance", updateResult.User.Department)
	}
	t.Logf("smoke/scim: updated role=%s dept=finance", updateResult.User.Role)

	// 3. Capture token_version before deprovision.
	beforeUser, err := authRepo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByID before deprovision: %v", err)
	}
	tokenVersionBefore := beforeUser.TokenVersion

	// 4. Deprovision — sets IsActive=false and bumps token_version.
	depResult, err := syncer.Deprovision(ctx, userID)
	if err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if depResult.Action != "deprovisioned" {
		t.Errorf("deprovision action = %q, want deprovisioned", depResult.Action)
	}
	if depResult.User.IsActive {
		t.Error("deprovisioned user must be inactive")
	}

	// Verify token_version bumped → all existing JWTs are invalidated.
	afterUser, err := authRepo.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetByID after deprovision: %v", err)
	}
	if afterUser.TokenVersion <= tokenVersionBefore {
		t.Errorf("token_version must bump on deprovision: before=%d after=%d",
			tokenVersionBefore, afterUser.TokenVersion)
	}
	t.Logf("smoke/scim: deprovisioned (token_version %d → %d)",
		tokenVersionBefore, afterUser.TokenVersion)

	// 5. PATCH reactivate.
	reactResult, err := syncer.ApplyPatch(ctx, userID, scim.PatchRequest{
		Operations: []scim.PatchOp{{Op: "Replace", Path: "active", Value: true}},
	})
	if err != nil {
		t.Fatalf("ApplyPatch (reactivate): %v", err)
	}
	if reactResult.Action != "reactivated" {
		t.Errorf("reactivate action = %q, want reactivated", reactResult.Action)
	}
	if !reactResult.User.IsActive {
		t.Error("reactivated user must be active")
	}
	t.Logf("smoke/scim: reactivated OK")
}

func boolPtrSmoke(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// O3.1.1.B — WORM/evidence: chain write → verify → anchor → export → bundle verify
// ---------------------------------------------------------------------------

// TestSmoke_WORM_ChainAnchorBundle covers the full WORM evidence path:
//  1. Write audit records with HMAC chain (AUDIT_CHAIN_SECRET)
//  2. chain.VerifyAuditLogs → OK
//  3. AnchorScheduler creates a Merkle anchor with Ed25519 signature
//  4. Export evidence bundle to temp dir
//  5. evidencebundle.VerifyBundle (offline, no DB required)
func TestSmoke_WORM_ChainAnchorBundle(t *testing.T) {
	infra := startInfra(t)
	defer infra.teardown()

	ctx := context.Background()
	auditRepo := audit.NewRepository(infra.DB).WithChainSecret(smokeChainSecret)
	chainRepo := chain.NewAnchorRepository(infra.DB)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// 1. Write 5 chained audit_logs.
	for i := 0; i < 5; i++ {
		if err := auditRepo.Insert(ctx, &domain.AuditLog{
			ID: uuid.NewString(), UserID: uuid.NewString(),
			Model: "gpt-4", Provider: "openai",
			Endpoint: "/v1/chat/completions", StatusCode: 200,
			PromptTokens: 100 + i, PolicyAction: "allowed",
		}); err != nil {
			t.Fatalf("Insert audit_log %d: %v", i, err)
		}
	}
	t.Logf("smoke/worm: wrote 5 chained audit_logs")

	// 2. Chain verify.
	vr, err := chain.VerifyAuditLogs(ctx, infra.DB, []byte(smokeChainSecret))
	if err != nil {
		t.Fatalf("VerifyAuditLogs: %v", err)
	}
	if !vr.OK {
		t.Errorf("chain verify FAIL: gaps=%v breaks=%v", vr.Gaps, vr.Breaks)
	}
	if vr.RowCount != 5 {
		t.Errorf("expected 5 rows, got %d", vr.RowCount)
	}
	t.Logf("smoke/worm: chain verify OK (rows=%d)", vr.RowCount)

	// 3. Run anchor scheduler once (interval=0 → immediate + return).
	sinkPath := t.TempDir() + "/anchors.ndjson"
	chain.NewAnchorScheduler(chainRepo, chain.NewFileSink(sinkPath), 0,
		[]string{"audit_logs"}).
		WithSigning(priv, "smoke-key-1", pub).
		Run(ctx)

	anchors, err := chainRepo.ListAnchors(ctx, "audit_logs")
	if err != nil {
		t.Fatalf("ListAnchors: %v", err)
	}
	if len(anchors) == 0 {
		t.Fatal("anchor scheduler produced no anchors")
	}
	a := anchors[0]
	if len(a.Signature) == 0 {
		t.Error("anchor must carry Ed25519 signature")
	}
	t.Logf("smoke/worm: anchor seq=[%d,%d] rows=%d signed=true", a.SeqLo, a.SeqHi, a.RowCount)

	// 4. Export evidence bundle.
	bundleDir := t.TempDir() + "/bundle"
	if err := buildSmokeBundle(ctx, t, infra, bundleDir, pub); err != nil {
		t.Fatalf("buildSmokeBundle: %v", err)
	}
	t.Logf("smoke/worm: evidence bundle exported to %s", bundleDir)

	// 5. Offline bundle verify (no DB required — pure evidencebundle).
	result, err := evidencebundle.VerifyBundle(bundleDir, pub)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !result.OK {
		t.Errorf("bundle verify FAIL: fileIntegrity=%v sigs.OK=%v sigs.fails=%v",
			result.FileIntegrity.OK, result.AnchorSigs.OK, result.AnchorSigs.Fails)
	}
	t.Logf("smoke/worm: offline bundle verify OK (sigs total=%d unsigned=%d fail=%d)",
		result.AnchorSigs.Total, result.AnchorSigs.Unsigned, len(result.AnchorSigs.Fails))
}

// buildSmokeBundle assembles an evidence bundle from the smoke DB.
// Mirrors the logic of cmd/audit-export-evidence.
func buildSmokeBundle(ctx context.Context, t *testing.T, infra *infraStack, dir string, pub ed25519.PublicKey) error {
	t.Helper()
	if err := os.MkdirAll(dir+"/reports", 0o755); err != nil {
		return err
	}

	chainRepo := chain.NewAnchorRepository(infra.DB)
	tables := []string{"audit_logs", "admin_event_logs", "legal_hold_events", "audit_purge_runs"}

	var allAnchors []evidencebundle.AnchorLine
	var allInventory []evidencebundle.ChainInventoryLine

	for _, table := range tables {
		dbAnchors, err := chainRepo.ListAnchors(ctx, table)
		if err != nil {
			return err
		}
		for _, a := range dbAnchors {
			line := evidencebundle.AnchorLine{
				ID:            a.ID,
				Table:         a.TableName,
				SeqLo:         a.SeqLo,
				SeqHi:         a.SeqHi,
				RowCount:      a.RowCount,
				MerkleRootHex: a.MerkleRootHex(),
				SinkName:      a.SinkName,
				SinkRef:       a.SinkRef,
				SinkOK:        a.SinkOK,
				PubKeyID:      a.PubKeyID,
				CreatedAt:     a.CreatedAt,
			}
			if len(a.Signature) > 0 {
				line.SignatureHex = hex.EncodeToString(a.Signature)
			}
			allAnchors = append(allAnchors, line)
		}

		inv, _ := chainRepo.FetchChainInventory(ctx, table)
		for _, row := range inv {
			allInventory = append(allInventory, evidencebundle.ChainInventoryLine{
				Table:      table,
				SeqNo:      row.SeqNo,
				RowIDHash:  row.RowIDHash,
				RowHashHex: row.RowHashHex,
			})
		}
	}

	// Write anchors.jsonl.
	af, err := os.Create(dir + "/anchors.jsonl")
	if err != nil {
		return err
	}
	if err := writeNDJSONBundle(af, allAnchors); err != nil {
		af.Close()
		return err
	}
	af.Close()

	// Write chain_inventory.jsonl.
	cf, err := os.Create(dir + "/chain_inventory.jsonl")
	if err != nil {
		return err
	}
	if err := writeNDJSONBundle(cf, allInventory); err != nil {
		cf.Close()
		return err
	}
	cf.Close()

	// Write public_key.b64.
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(dir+"/public_key.b64", []byte(pubB64+"\n"), 0o644); err != nil {
		return err
	}

	// Write README.
	if err := evidencebundle.WriteReadme(dir, []string{"audit_logs"}, true); err != nil {
		return err
	}

	// Compute hashes + write manifest.
	hashes, err := evidencebundle.ComputeBundleHashes(dir)
	if err != nil {
		return err
	}
	return evidencebundle.WriteManifest(dir, &evidencebundle.BundleManifest{
		Version:       evidencebundle.BundleVersion,
		ExportTime:    time.Now().UTC(),
		Tables:        []string{"audit_logs"},
		DBFingerprint: evidencebundle.DBFingerprint("smoke-host", "shadowai_smoke"),
		FileSHA256:    hashes,
	})
}

type ndjsonWriter interface{ Write([]byte) (int, error) }

func writeNDJSONBundle[T any](w ndjsonWriter, records []T) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i := range records {
		if err := enc.Encode(records[i]); err != nil {
			return err
		}
	}
	return nil
}

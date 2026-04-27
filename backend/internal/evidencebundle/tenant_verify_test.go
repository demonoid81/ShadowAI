package evidencebundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/chain"
)

// buildTestTenantBundle writes a minimal tenant bundle to a temp dir:
//   - anchors.jsonl with one anchor (signed or unsigned)
//   - tenant_chain_hashes.jsonl with one tenant row
//   - merkle_proofs.jsonl with the inclusion proof
//   - bundle_manifest.json (hashes of all files)
//
// Returns the dir path and the full leaf set (needed to reconstruct expected root).
func buildTestTenantBundle(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, tamper string) string {
	t.Helper()
	dir := t.TempDir()

	// Create 4 leaves: index 1 is our "tenant" row, others are "other tenant" rows.
	leaves := [][]byte{
		bytes.Repeat([]byte{0x01}, 32), // other
		bytes.Repeat([]byte{0x02}, 32), // tenant (index=1)
		bytes.Repeat([]byte{0x03}, 32), // other
		bytes.Repeat([]byte{0x04}, 32), // other
	}
	tenantLeafIdx := 1
	tenantLeaf := leaves[tenantLeafIdx]

	root := chain.ComputeMerkleRoot(leaves)
	rootHex := hex.EncodeToString(root)

	proof, _ := chain.GenerateMerkleProof(leaves, tenantLeafIdx)

	// Build anchor line.
	anchor := AnchorLine{
		ID:            "anchor-001",
		Table:         "audit_logs",
		SeqLo:         0,
		SeqHi:         3,
		RowCount:      4,
		MerkleRootHex: rootHex,
		SinkName:      "test",
		CreatedAt:     time.Now().UTC(),
	}
	if priv != nil {
		// Sign the anchor.
		msg := []byte(fmt.Sprintf("v1|audit_logs|0|3|4|%s|%d|||",
			rootHex, anchor.CreatedAt.Unix()))
		sig := ed25519.Sign(priv, msg)
		anchor.SignatureHex = hex.EncodeToString(sig)
		anchor.PubKeyID = "test-key"
	}

	// Write anchors.jsonl.
	writeJSONL(t, dir+"/anchors.jsonl", []any{anchor})

	// Tenant chain hash.
	leafHex := hex.EncodeToString(tenantLeaf)
	if tamper == "leaf" {
		leafHex = hex.EncodeToString(bytes.Repeat([]byte{0xFF}, 32))
	}

	th := TenantChainHashLine{
		Table:      "audit_logs",
		SeqNo:      1,
		RowIDHash:  hex.EncodeToString(bytes.Repeat([]byte{0xAB}, 32)),
		RowHashHex: leafHex,
	}
	writeJSONL(t, dir+"/tenant_chain_hashes.jsonl", []any{th})

	// Merkle proof.
	var sibLines []chain.MerkleProofSibling
	if tamper != "siblings" {
		sibLines = proof
	} else {
		sibLines = proof[:len(proof)-1] // truncate
	}
	proofRootHex := rootHex
	if tamper == "root" {
		proofRootHex = hex.EncodeToString(bytes.Repeat([]byte{0xDE}, 32))
	}
	mp := MerkleProofLine{
		Table:       "audit_logs",
		SeqNo:       1,
		AnchorSeqLo: 0,
		AnchorSeqHi: 3,
		LeafHashHex: hex.EncodeToString(tenantLeaf),
		Siblings:    sibLines,
		RootHex:     proofRootHex,
	}
	writeJSONL(t, dir+"/merkle_proofs.jsonl", []any{mp})

	// Write public_key.b64 if provided.
	if pub != nil {
		os.WriteFile(dir+"/public_key.b64", []byte(hex.EncodeToString(pub)+"\n"), 0o644)
	}

	// Compute manifest.
	hashes, _ := ComputeBundleHashes(dir)
	WriteManifest(dir, &BundleManifest{
		Version:    BundleVersion,
		ExportTime: time.Now().UTC(),
		Tables:     []string{"audit_logs"},
		OrgID:      "test-org",
		FileSHA256: hashes,
	})
	return dir
}

func writeJSONL(t *testing.T, path string, items []any) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		enc.Encode(item)
	}
}

// ---------------------------------------------------------------------------

func TestVerifyTenantBundle_ValidNoSig(t *testing.T) {
	dir := buildTestTenantBundle(t, nil, nil, "")
	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	if !res.OK {
		t.Errorf("want OK=true, got fails=%v sigs=%v", res.ProofsFailed, res.SignaturesFailed)
	}
	if res.ProofsChecked != 1 {
		t.Errorf("ProofsChecked=%d, want 1", res.ProofsChecked)
	}
}

func TestVerifyTenantBundle_TamperedLeafFails(t *testing.T) {
	dir := buildTestTenantBundle(t, nil, nil, "leaf")
	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	// Tampered leaf: inclusion proof reconstructs wrong root, OR root_hex mismatch.
	// Either way the cross-check finds a row without a valid proof.
	if res.OK {
		t.Error("tampered leaf should fail verification")
	}
}

func TestVerifyTenantBundle_TruncatedSiblingsFails(t *testing.T) {
	dir := buildTestTenantBundle(t, nil, nil, "siblings")
	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	if res.OK {
		t.Error("truncated siblings should fail verification")
	}
}

func TestVerifyTenantBundle_WrongRootFails(t *testing.T) {
	dir := buildTestTenantBundle(t, nil, nil, "root")
	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	if res.OK {
		t.Error("wrong root_hex should fail verification")
	}
}

// TestVerifyTenantBundle_ExtraProofRejected — a proof for a row NOT in
// tenant_chain_hashes.jsonl must fail (cross-tenant injection guard).
func TestVerifyTenantBundle_ExtraProofRejected(t *testing.T) {
	// Build a valid bundle, then inject an extra proof for a non-tenant row.
	dir := buildTestTenantBundle(t, nil, nil, "")

	// Read existing merkle_proofs.jsonl and append an extra entry.
	f, err := os.OpenFile(dir+"/merkle_proofs.jsonl", os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open proofs for append: %v", err)
	}
	extraProof := MerkleProofLine{
		Table:       "audit_logs",
		SeqNo:       99, // not in tenant_chain_hashes.jsonl
		AnchorSeqLo: 0,
		AnchorSeqHi: 3,
		LeafHashHex: hex.EncodeToString(bytes.Repeat([]byte{0x05}, 32)),
		RootHex:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	enc.Encode(extraProof)
	f.Close()

	// Recompute manifest so file integrity passes.
	hashes, _ := ComputeBundleHashes(dir)
	WriteManifest(dir, &BundleManifest{
		Version:    BundleVersion,
		ExportTime: time.Now().UTC(),
		Tables:     []string{"audit_logs"},
		OrgID:      "test-org",
		FileSHA256: hashes,
	})

	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	// The extra proof's root_hex is wrong so it fails Merkle verify first,
	// or the reverse check fails. Either way result must not be OK.
	if res.OK {
		t.Error("bundle with extra (cross-tenant) proof should fail verification")
	}
}

func TestVerifyTenantBundle_WrongSignatureFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := buildTestTenantBundle(t, pub, priv, "")

	// Use a different public key for verification → signature mismatch.
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	res, err := VerifyTenantBundle(dir, pub2)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	// Proof itself is valid (root matches), but Ed25519 fails.
	if len(res.SignaturesFailed) == 0 {
		t.Error("wrong signature key should produce SignaturesFailed")
	}
}

func TestVerifyTenantBundle_SelectorManifest_Valid(t *testing.T) {
	dir := buildTestTenantBundle(t, nil, nil, "")
	line := selectorLine(t, "hold-tenant", "test-org", `{"v":1,"field":"provider","op":"eq","value":"openai"}`)
	writeJSONL(t, dir+"/selector_manifest.jsonl", []any{line})
	hashes, _ := ComputeBundleHashes(dir)
	WriteManifest(dir, &BundleManifest{
		Version:    BundleVersion,
		ExportTime: time.Now().UTC(),
		Tables:     []string{"audit_logs"},
		OrgID:      "test-org",
		FileSHA256: hashes,
	})

	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	if !res.OK {
		t.Fatalf("tenant bundle should verify: %+v", res)
	}
	if !res.SelectorManifest.OK || res.SelectorManifest.Checked != 1 {
		t.Fatalf("selector manifest result = %+v, want OK checked=1", res.SelectorManifest)
	}
}

func TestVerifyTenantBundle_SelectorManifest_TamperedSelectorFails(t *testing.T) {
	dir := buildTestTenantBundle(t, nil, nil, "")
	line := selectorLine(t, "hold-tenant", "test-org", `{"v":1,"field":"provider","op":"eq","value":"openai"}`)
	line.SelectorJSON = json.RawMessage(`{"v":1,"field":"provider","op":"eq","value":"anthropic"}`)
	writeJSONL(t, dir+"/selector_manifest.jsonl", []any{line})
	hashes, _ := ComputeBundleHashes(dir)
	WriteManifest(dir, &BundleManifest{
		Version:    BundleVersion,
		ExportTime: time.Now().UTC(),
		Tables:     []string{"audit_logs"},
		OrgID:      "test-org",
		FileSHA256: hashes,
	})

	res, err := VerifyTenantBundle(dir, nil)
	if err != nil {
		t.Fatalf("VerifyTenantBundle: %v", err)
	}
	if res.OK {
		t.Fatal("tenant bundle with tampered selector should fail")
	}
	if res.SelectorManifest.OK || len(res.SelectorManifest.Fails) != 1 {
		t.Fatalf("selector manifest result = %+v, want one failure", res.SelectorManifest)
	}
}

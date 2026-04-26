package evidencebundle

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/shadowai/backend/internal/chain"
)

// VerifyTenantBundle verifies a tenant-scoped evidence bundle offline.
//
// Verification steps:
//  1. File integrity: SHA256 of every file matches bundle_manifest.json.
//  2. For every proof in merkle_proofs.jsonl:
//     a. Reconstruct Merkle root from leaf hash + siblings.
//     b. Compare with RootHex (which must match the signed anchor root).
//  3. For every anchor in anchors.jsonl with a signature: verify Ed25519.
//  4. Cross-check: every row in tenant_chain_hashes.jsonl has a proof.
//
// pubKey may be nil (skips Ed25519 check).
func VerifyTenantBundle(dir string, pubKey ed25519.PublicKey) (TenantVerifyResult, error) {
	var res TenantVerifyResult

	// 1. File integrity.
	manifest, err := readManifest(dir)
	if err != nil {
		return res, fmt.Errorf("read manifest: %w", err)
	}
	for rel, wantHex := range manifest.FileSHA256 {
		full := filepath.Join(dir, rel)
		gotHex, err := FileSHA256(full)
		if err != nil {
			return res, fmt.Errorf("hash %s: %w", rel, err)
		}
		if gotHex != wantHex {
			return res, fmt.Errorf("file integrity fail: %s got=%s want=%s", rel, gotHex, wantHex)
		}
	}

	// 2. Load anchors (for root lookup and sig verify).
	anchors, err := readAnchorLines(filepath.Join(dir, "anchors.jsonl"))
	if err != nil {
		return res, fmt.Errorf("read anchors.jsonl: %w", err)
	}
	anchorMap := make(map[string]AnchorLine) // key: table|seqLo|seqHi
	for _, a := range anchors {
		anchorMap[anchorKey(a.Table, a.SeqLo, a.SeqHi)] = a
	}

	// 3. Verify Ed25519 signatures on anchors using chain.VerifyAnchorSignature
	// (same canonical as ManifestCanonical — avoids any format divergence).
	if pubKey != nil {
		for _, a := range anchors {
			if a.SignatureHex == "" {
				continue
			}
			ar := anchorLineToRecord(a) // defined in bundle_verify.go (same package)
			if !chain.VerifyAnchorSignature(&ar, pubKey) {
				res.SignaturesFailed = append(res.SignaturesFailed, a.ID)
			}
		}
	}

	// 4. Read Merkle proofs and verify each one.
	proofsPath := filepath.Join(dir, "merkle_proofs.jsonl")
	proofsFile, err := os.Open(proofsPath)
	if err != nil {
		return res, fmt.Errorf("open merkle_proofs.jsonl: %w", err)
	}
	defer proofsFile.Close()

	coveredSeqs := make(map[string]bool) // table|seqNo → true

	scanner := bufio.NewScanner(proofsFile)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var p MerkleProofLine
		if err := json.Unmarshal(line, &p); err != nil {
			return res, fmt.Errorf("parse merkle_proofs.jsonl: %w", err)
		}
		res.ProofsChecked++

		// Verify inclusion proof.
		if !chain.VerifyMerkleProof(p.LeafHashHex, p.Siblings, p.RootHex) {
			res.ProofsFailed = append(res.ProofsFailed, TenantProofFailure{
				Table:  p.Table,
				SeqNo:  p.SeqNo,
				Reason: "merkle reconstruction does not match root_hex",
			})
			continue
		}

		// Verify proof root matches anchor root.
		ak := anchorKey(p.Table, p.AnchorSeqLo, p.AnchorSeqHi)
		anchor, ok := anchorMap[ak]
		if !ok {
			res.ProofsFailed = append(res.ProofsFailed, TenantProofFailure{
				Table:  p.Table,
				SeqNo:  p.SeqNo,
				Reason: fmt.Sprintf("no anchor found for table=%s seqLo=%d seqHi=%d", p.Table, p.AnchorSeqLo, p.AnchorSeqHi),
			})
			continue
		}
		if p.RootHex != anchor.MerkleRootHex {
			res.ProofsFailed = append(res.ProofsFailed, TenantProofFailure{
				Table:  p.Table,
				SeqNo:  p.SeqNo,
				Reason: "proof root_hex does not match anchor merkle_root_hex",
			})
			continue
		}
		coveredSeqs[fmt.Sprintf("%s|%d", p.Table, p.SeqNo)] = true
	}
	if err := scanner.Err(); err != nil {
		return res, fmt.Errorf("scan merkle_proofs.jsonl: %w", err)
	}

	// 5. Cross-check: every tenant hash has a proof AND matches the proof's leaf hash.
	// Build proof leaf map: table|seqNo → leaf_hash_hex.
	proofLeafMap := make(map[string]string)
	proofsFile2, err := os.Open(proofsPath)
	if err != nil {
		return res, fmt.Errorf("reopen merkle_proofs.jsonl: %w", err)
	}
	defer proofsFile2.Close()
	sc3 := bufio.NewScanner(proofsFile2)
	for sc3.Scan() {
		b := sc3.Bytes()
		if len(b) == 0 {
			continue
		}
		var p MerkleProofLine
		if err := json.Unmarshal(b, &p); err != nil {
			continue
		}
		proofLeafMap[fmt.Sprintf("%s|%d", p.Table, p.SeqNo)] = p.LeafHashHex
	}

	tenantHashesPath := filepath.Join(dir, "tenant_chain_hashes.jsonl")
	thFile, err := os.Open(tenantHashesPath)
	if err != nil {
		return res, fmt.Errorf("open tenant_chain_hashes.jsonl: %w", err)
	}
	defer thFile.Close()

	sc2 := bufio.NewScanner(thFile)
	for sc2.Scan() {
		line := sc2.Bytes()
		if len(line) == 0 {
			continue
		}
		var th TenantChainHashLine
		if err := json.Unmarshal(line, &th); err != nil {
			return res, fmt.Errorf("parse tenant_chain_hashes.jsonl: %w", err)
		}
		key := fmt.Sprintf("%s|%d", th.Table, th.SeqNo)
		proofLeaf, hasproof := proofLeafMap[key]
		if !hasproof {
			res.ProofsFailed = append(res.ProofsFailed, TenantProofFailure{
				Table:  th.Table,
				SeqNo:  th.SeqNo,
				Reason: "tenant row has no corresponding Merkle proof",
			})
		} else if proofLeaf != th.RowHashHex {
			// row_hash_hex must match the leaf used in the proof.
			res.ProofsFailed = append(res.ProofsFailed, TenantProofFailure{
				Table:  th.Table,
				SeqNo:  th.SeqNo,
				Reason: fmt.Sprintf("row_hash_hex does not match proof leaf_hash_hex (tampered hash)"),
			})
		}
	}
	if err := sc2.Err(); err != nil {
		return res, fmt.Errorf("scan tenant_chain_hashes.jsonl: %w", err)
	}

	res.OK = len(res.ProofsFailed) == 0 && len(res.SignaturesFailed) == 0
	return res, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func anchorKey(table string, seqLo, seqHi int64) string {
	return fmt.Sprintf("%s|%d|%d", table, seqLo, seqHi)
}

func readAnchorLines(path string) ([]AnchorLine, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []AnchorLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var a AnchorLine
		if err := json.Unmarshal(b, &a); err != nil {
			return nil, fmt.Errorf("parse anchor line: %w", err)
		}
		lines = append(lines, a)
	}
	return lines, sc.Err()
}

// anchorLineToRecord is defined in bundle_verify.go (same package).
// Signature verification uses chain.VerifyAnchorSignature(&ar, pubKey).

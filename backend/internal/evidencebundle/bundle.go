// Package evidencebundle assembles portable compliance artifacts for auditors.
//
// A bundle is a directory containing:
//
//	bundle_manifest.json  — metadata + SHA256 of every file
//	anchors.jsonl         — anchor records (Merkle root, signature, sink refs)
//	chain_inventory.jsonl — chain digest inventory: seq_no + row_hash (no payload)
//	public_key.b64        — Ed25519 public key (if provided by exporter)
//	reports/              — operator-side verification results (JSON)
//	README.txt            — what can and cannot be verified offline
//
// What offline auditors CAN verify from this bundle:
//
//	  - Ed25519 signature on each signed anchor (using public_key.b64)
//	  - SHA256 hashes of all bundle files (bundle_manifest.json file_sha256)
//	  - Merkle root consistency: if auditor independently holds row_hashes,
//	    they can recompute Merkle roots and compare against anchors.jsonl
//	  - chain_inventory.jsonl seq_no continuity (gap detection)
//	  - Anchor range continuity (no gaps between anchor seq_hi/seq_lo)
//
// What requires live infrastructure:
//
//	  - W2 HMAC chain verification (requires AUDIT_CHAIN_SECRET + canonical row data)
//	  - W4 immudb sink re-fetch (requires immudb connection + sink_refs)
//	  - Merkle root recomputation from row content (requires DB + row payload)
package evidencebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BundleVersion is the bundle format version. Increment on breaking changes.
const BundleVersion = "1"

// BundleManifest is the root metadata file written to bundle_manifest.json.
type BundleManifest struct {
	Version        string            `json:"version"`
	ExportTime     time.Time         `json:"export_time"`
	Tables         []string          `json:"tables"`
	ExporterCommit string            `json:"exporter_commit,omitempty"`
	// DBFingerprint is SHA256(host+"/"+dbname) from DATABASE_URL. Identifies
	// which database the bundle came from without exposing connection credentials.
	DBFingerprint string            `json:"db_fingerprint"`
	// FileSHA256 maps relative path → SHA256 hex for every file in the bundle
	// except bundle_manifest.json itself (which is written last).
	FileSHA256    map[string]string `json:"file_sha256"`
}

// AnchorLine is one entry in anchors.jsonl. Contains all verifiable
// anchor fields; no row payload data.
type AnchorLine struct {
	ID            string    `json:"id"`
	Table         string    `json:"table"`
	SeqLo         int64     `json:"seq_lo"`
	SeqHi         int64     `json:"seq_hi"`
	RowCount      int       `json:"row_count"`
	MerkleRootHex string    `json:"merkle_root_hex"`
	SinkName      string    `json:"sink_name,omitempty"`
	SinkRef       string    `json:"sink_ref,omitempty"`
	SinkOK        bool      `json:"sink_ok"`
	PubKeyID      string    `json:"pubkey_id,omitempty"`
	SignatureHex  string    `json:"signature_hex,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// ChainInventoryLine is one entry in chain_inventory.jsonl.
//
// This is a DIGEST INVENTORY, not a W2 chain verification artifact.
// W2 chain verification requires AUDIT_CHAIN_SECRET and the canonical
// form of each row (PII-containing fields). This file contains only
// seq_no and row_hash (the HMAC output stored in the DB) — sufficient
// for gap/continuity analysis and cross-referencing with anchor Merkle
// roots, but NOT sufficient to prove row_hash matches row content.
type ChainInventoryLine struct {
	Table      string `json:"table"`
	SeqNo      int64  `json:"seq_no"`
	RowIDHash  string `json:"row_id_hash"`  // SHA256(row_id) — stable identifier, no PII
	RowHashHex string `json:"row_hash_hex"` // hex of stored HMAC chain hash
}

// WriteNDJSON encodes each item in records as one JSON line to w.
func WriteNDJSON[T any](w io.Writer, records []T) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i := range records {
		if err := enc.Encode(records[i]); err != nil {
			return fmt.Errorf("ndjson encode item %d: %w", i, err)
		}
	}
	return nil
}

// FileSHA256 computes the SHA256 hex digest of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// DBFingerprint returns SHA256(host+"/"+dbname) as a hex string.
// Suitable for bundle_manifest.json to identify source DB without credentials.
func DBFingerprint(host, dbname string) string {
	h := sha256.Sum256([]byte(host + "/" + dbname))
	return hex.EncodeToString(h[:])
}

// WriteManifest encodes m as JSON to bundle_manifest.json in dir.
func WriteManifest(dir string, m *BundleManifest) error {
	path := filepath.Join(dir, "bundle_manifest.json")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("bundle manifest: create: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return fmt.Errorf("bundle manifest: encode: %w", err)
	}
	return nil
}

// ComputeBundleHashes walks dir and computes SHA256 for every file,
// returning a map of relative path → hex digest. Skips bundle_manifest.json.
func ComputeBundleHashes(dir string) (map[string]string, error) {
	result := make(map[string]string)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "bundle_manifest.json" {
			return nil // manifest is written last, after hashes
		}
		digest, err := FileSHA256(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", rel, err)
		}
		result[rel] = digest
		return nil
	})
	return result, err
}

// WriteReadme writes README.txt explaining what the bundle contains,
// what can be verified offline, and what requires live infrastructure.
func WriteReadme(dir string, tables []string, hasPubKey bool) error {
	path := filepath.Join(dir, "README.txt")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("README: %w", err)
	}
	defer f.Close()

	tablesStr := fmt.Sprintf("%v", tables)

	offline := "none (public_key.b64 not provided)"
	if hasPubKey {
		offline = "Ed25519 anchor signatures (public_key.b64 + anchors.jsonl)"
	}

	content := fmt.Sprintf(`ShadowAI Evidence Bundle
========================

Generated by audit-export-evidence. Tables: %s

FILES
-----
bundle_manifest.json
  Bundle metadata. file_sha256 lists SHA256 of every other file.
  Verify file integrity: sha256sum -c <(jq -r '.file_sha256 | to_entries[] | "\(.value)  \(.key)"' bundle_manifest.json)

anchors.jsonl
  Anchor records: Merkle root, seq ranges, Ed25519 signature, immudb sink_ref.
  One JSON object per line. These are the cryptographic commitments over
  ranges of audit log rows.

chain_inventory.jsonl
  DIGEST INVENTORY — seq_no and row_hash for every chained row.
  NOT a full W2 chain verification. W2 chain HMAC requires AUDIT_CHAIN_SECRET
  and canonical row content (not exported). This file allows:
    - Gap/continuity analysis (check seq_no is contiguous)
    - Cross-referencing row_hash values against anchor Merkle roots
  It does NOT prove that row_hash corresponds to specific row content.

reports/
  Operator-side verification results at export time (JSON).
  anchor_verify_<table>.json  — W3 Merkle anchor verification result
  signature_verify_<table>.json  — W4.1 Ed25519 signature verification result

public_key.b64 (if present)
  Base64-encoded Ed25519 public key used for anchor signature verification.

README.txt
  This file.

WHAT CAN BE VERIFIED OFFLINE
-----------------------------
%s
  File integrity: recompute SHA256 hashes and compare to bundle_manifest.json

WHAT REQUIRES LIVE INFRASTRUCTURE
----------------------------------
W2 chain verification: requires AUDIT_CHAIN_SECRET (secret, not exported)
  and canonical row content from the source database.
W4 immudb sink re-fetch: requires connection to the immudb instance.
  Use: audit-verify --verify-sink --immudb-addr <addr> ...
  The sink_ref values in anchors.jsonl identify what to fetch.
Merkle root recomputation from row content: requires source database access.

VERIFYING ANCHOR SIGNATURES (if public_key.b64 is present)
-----------------------------------------------------------
Install audit-verify from the ShadowAI release, then run:
  audit-verify --verify-signatures --pubkey-file public_key.b64 \
               --table all --verbose

Or verify manually using the Ed25519 canonical form:
  Canonical: v1|table|seq_lo|seq_hi|row_count|merkle_root_hex|created_at_epoch|sink_name|sink_ref|pubkey_id
  Signature: signature_hex field in anchors.jsonl (hex-encoded, 64 bytes)
`, tablesStr, offline)

	_, err = f.WriteString(content)
	return err
}

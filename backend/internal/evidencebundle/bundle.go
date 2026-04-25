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
	"archive/zip"
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
	// OrgID is non-empty for tenant-scoped exports (--org-id flag, PR-T2.4).
	// Empty for global bundles (--global flag).
	OrgID         string            `json:"org_id,omitempty"`
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

// RequireEmptyOrAbsentDir returns an error if dir exists and is non-empty.
// Callers should use this before writing a bundle to prevent contaminating a
// new export with stale files from a previous run.
func RequireEmptyOrAbsentDir(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("path exists and is not a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("directory is not empty (%d entries); exporting into an existing directory can contaminate the bundle with stale files", len(entries))
	}
	return nil
}

// ZipBundleDir creates a zip archive of dir at zipPath.
//
// zipPath is derived by the caller; this function additionally skips
// zipPath if it happens to land inside dir (defensive guard against
// self-inclusion when the caller computes the path from a dir with a
// trailing slash).
//
// Recommended usage: zipPath = filepath.Clean(dir) + ".zip"
func ZipBundleDir(dir, zipPath string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("zip: abs dir: %w", err)
	}
	absZip, err := filepath.Abs(zipPath)
	if err != nil {
		return fmt.Errorf("zip: abs zip: %w", err)
	}

	zf, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	defer zw.Close()

	base := filepath.Base(absDir)
	return filepath.Walk(absDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if absPath == absZip {
			return nil // skip the zip file itself
		}
		rel, err := filepath.Rel(absDir, absPath)
		if err != nil {
			return err
		}
		w, err := zw.Create(filepath.Join(base, rel))
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
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
  Operator-side verification results run at export time (JSON).
  anchor_verify_<table>.json       — W3 Merkle anchor verification result
  signature_verify_<table>.json    — W4.1 Ed25519 signature verification result
  These reports were produced by the operator; they are informational.
  For independent re-verification see the manual steps below.

public_key.b64 (if present)
  Base64-encoded Ed25519 public key used for anchor signature verification.

README.txt
  This file.

WHAT CAN BE VERIFIED OFFLINE (no DATABASE_URL required)
--------------------------------------------------------
%s
  File integrity: recompute SHA256 hashes and compare to bundle_manifest.json

WHAT REQUIRES LIVE INFRASTRUCTURE
----------------------------------
W2 chain verification: requires AUDIT_CHAIN_SECRET (not exported) and
  canonical row content from the source database. The chain_inventory.jsonl
  file enables gap/continuity analysis only — it does not substitute for W2.
W4 immudb sink re-fetch: requires connection to the immudb instance.
  The sink_ref values in anchors.jsonl identify which keys to fetch.
  (W5.2 will add audit-verify --bundle support for this.)
Merkle root recomputation from row content: requires source database access.

NOTE: the current audit-verify binary reads anchor data from DATABASE_URL,
not from this bundle. Using the --verify-signatures flag of audit-verify
against the live database yields results equivalent to this bundle, but
that is a live database check, NOT an offline check from the bundle.
A future "audit-verify --bundle" mode (W5.2) will read directly from
anchors.jsonl and not require DATABASE_URL.

MANUALLY VERIFYING ANCHOR SIGNATURES (if public_key.b64 is present)
--------------------------------------------------------------------
Each signed anchor in anchors.jsonl has a "signature_hex" field (64 bytes,
hex-encoded). The Ed25519 signature covers the canonical string:

  v1|<table>|<seq_lo>|<seq_hi>|<row_count>|<merkle_root_hex>|<created_at_epoch>|<sink_name>|<sink_ref>|<pubkey_id>

where created_at_epoch is the Unix timestamp (seconds) of the created_at field.

To verify using any Ed25519 library (Python example):
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
  import base64, binascii, json
  pubkey = Ed25519PublicKey.from_public_bytes(base64.b64decode(open("public_key.b64").read()))
  for line in open("anchors.jsonl"):
      a = json.loads(line)
      if not a.get("signature_hex"): continue
      msg = "|".join([
          "v1", a["table"], str(a["seq_lo"]), str(a["seq_hi"]), str(a["row_count"]),
          a["merkle_root_hex"],
          str(int(a["created_at"].rstrip("Z").split(".")[0].replace("T"," ").strip())),
          a.get("sink_name",""), a.get("sink_ref",""), a.get("pubkey_id",""),
      ]).encode()
      sig = binascii.unhexlify(a["signature_hex"])
      pubkey.verify(sig, msg)  # raises if invalid
      print("OK", a["id"], a["table"], a["seq_lo"], "-", a["seq_hi"])
`, tablesStr, offline)

	_, err = f.WriteString(content)
	return err
}

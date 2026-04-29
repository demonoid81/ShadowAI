// cmd/audit-export-evidence — W5.1: exports a portable evidence bundle
// for auditors containing anchor records, chain inventory, verification
// reports, and optional Ed25519 public key.
//
// The bundle is a directory (optionally zipped) that auditors can inspect
// without access to the live database or AUDIT_CHAIN_SECRET.
//
// What auditors can verify offline from the bundle:
//   - Ed25519 anchor signatures (if --pubkey-file provided)
//   - File integrity via SHA256 hashes in bundle_manifest.json
//   - Anchor seq_lo/seq_hi continuity (no coverage gaps)
//   - chain_inventory.jsonl seq_no continuity (gap detection)
//   - query_scope selector hash integrity in selector_manifest.jsonl
//
// What requires live infrastructure (documented in bundle README.txt):
//   - W2 HMAC chain verification (requires AUDIT_CHAIN_SECRET + row content)
//   - W4 immudb sink re-fetch (requires immudb connection)
//
// Usage:
//
//	audit-export-evidence \
//	  --output <dir>              # required: output directory path
//	  [--table <table|all>]       # default: all
//	  [--pubkey-file <path>]      # optional: Ed25519 public key for sig reports
//	  [--zip]                     # create <output>.zip after writing directory
//
// Environment:
//
//	DATABASE_URL  — required Postgres connection string
//
// Exit codes:
//
//	0 — export complete (reports may contain verification failures)
//	1 — export failed (DB error, I/O error)
//	2 — configuration error (missing flags, bad flag values)
package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/evidencebundle"
)

// exporterCommit is injected at build time via -ldflags "-X main.exporterCommit=<git-sha>".
var exporterCommit string

func main() {
	outputFlag := flag.String("output", "", "Output directory path (required)")
	tableFlag := flag.String("table", "all", "Table: audit_logs|admin_event_logs|legal_hold_events|audit_purge_runs|all")
	pubKeyFile := flag.String("pubkey-file", "", "Path to base64 Ed25519 public key for signature verification reports")
	doZip := flag.Bool("zip", false, "Create <output>.zip after writing directory")
	orgIDFlag := flag.String("org-id", "", "Export evidence for a single org (tenant export)")
	globalFlag := flag.Bool("global", false, "Export full evidence bundle across all orgs (privileged)")
	flag.Parse()

	exitCfg := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "config error: "+format+"\n", args...)
		os.Exit(2)
	}
	exitErr := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
		os.Exit(1)
	}

	if strings.TrimSpace(*outputFlag) == "" {
		exitCfg("--output is required")
	}

	// PR-T2.4: explicit scope required — fail-fast with exit 2 if neither provided.
	if strings.TrimSpace(*orgIDFlag) == "" && !*globalFlag {
		exitCfg("--org-id <uuid> or --global is required (PR-T2.4: export scope must be explicit)\n" +
			"  --org-id <uuid>   export evidence for a single org (tenant)\n" +
			"  --global          export full evidence bundle (privileged, all orgs)")
	}
	if strings.TrimSpace(*orgIDFlag) != "" && *globalFlag {
		exitCfg("--org-id and --global are mutually exclusive")
	}

	tenantOrgID := strings.TrimSpace(*orgIDFlag)

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		exitCfg("DATABASE_URL is required")
	}

	tables := []string{*tableFlag}
	if *tableFlag == "all" {
		tables = []string{"audit_logs", "admin_event_logs", "legal_hold_events", "audit_purge_runs"}
	} else {
		switch *tableFlag {
		case "audit_logs", "admin_event_logs", "legal_hold_events", "audit_purge_runs":
		default:
			exitCfg("unknown table %q: must be audit_logs|admin_event_logs|legal_hold_events|audit_purge_runs|all", *tableFlag)
		}
	}

	// Load optional public key for signature verification reports.
	var pubKeyB64 string
	if *pubKeyFile != "" {
		data, err := os.ReadFile(*pubKeyFile)
		if err != nil {
			exitCfg("pubkey-file: %v", err)
		}
		pubKeyB64 = strings.TrimSpace(string(data))
		if _, err := chain.ParsePublicKey(pubKeyB64); err != nil {
			exitCfg("pubkey-file: invalid Ed25519 public key: %v", err)
		}
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		exitErr("db open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		exitErr("db ping: %v", err)
	}

	outDir := *outputFlag
	if err := evidencebundle.RequireEmptyOrAbsentDir(outDir); err != nil {
		exitCfg("--output %s: %v\n  Hint: use a new path or remove the directory first.", outDir, err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		exitErr("create output dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "reports"), 0o755); err != nil {
		exitErr("create reports dir: %v", err)
	}

	repo := chain.NewAnchorRepository(db)
	selectorRepo := evidencebundle.NewSelectorManifestRepository(db)
	dbFingerprint := dbFingerprint(dsn)

	if tenantOrgID != "" {
		fmt.Printf("Exporting tenant evidence bundle → %s (org=%s)\n", outDir, tenantOrgID)
	} else {
		fmt.Printf("Exporting global evidence bundle → %s\n", outDir)
	}
	fmt.Printf("Tables: %v\n", tables)

	// Collect anchors and — depending on mode — inventory or Merkle proofs.
	//
	// T3/W6 TENANT MODE (--org-id):
	//   Writes tenant_chain_hashes.jsonl (org rows only) and merkle_proofs.jsonl.
	//   No cross-tenant hashes. Auditor reconstructs each anchor's Merkle root
	//   offline using only their rows + sibling proofs.
	//
	// GLOBAL MODE (--global):
	//   Legacy behavior: writes chain_inventory.jsonl with full ranges.
	var allAnchors []evidencebundle.AnchorLine
	var allInventory []evidencebundle.ChainInventoryLine
	var tenantHashes []evidencebundle.TenantChainHashLine
	var merkleProofs []evidencebundle.MerkleProofLine

	for _, table := range tables {
		if tenantOrgID != "" {
			// T3/W6: generate Merkle inclusion proofs for org rows only.
			tRows, tProofs, err := repo.GenerateTenantMerkleProofs(ctx, table, tenantOrgID)
			if err != nil {
				exitErr("tenant merkle proofs %s (org=%s): %v", table, tenantOrgID, err)
			}
			// Collect intersecting anchors for anchors.jsonl.
			_, orgAnchors, err := repo.FetchChainInventoryForOrgAnchors(ctx, table, tenantOrgID)
			if err != nil {
				exitErr("chain anchors %s (org=%s): %v", table, tenantOrgID, err)
			}
			for _, row := range tRows {
				tenantHashes = append(tenantHashes, evidencebundle.TenantChainHashLine{
					Table:      table,
					SeqNo:      row.SeqNo,
					RowIDHash:  row.RowIDHash,
					RowHashHex: row.RowHashHex,
				})
			}
			for _, p := range tProofs {
				// Siblings is []chain.MerkleProofSibling — assign directly.
				merkleProofs = append(merkleProofs, evidencebundle.MerkleProofLine{
					Table:       p.Table,
					SeqNo:       p.SeqNo,
					AnchorSeqLo: p.AnchorSeqLo,
					AnchorSeqHi: p.AnchorSeqHi,
					LeafHashHex: p.LeafHashHex,
					Siblings:    p.Siblings,
					RootHex:     p.RootHex,
				})
			}
			for _, a := range orgAnchors {
				allAnchors = append(allAnchors, anchorToLine(a))
			}
			fmt.Printf("  %s: %d intersecting anchors, %d tenant rows, %d proofs (T3/W6)\n",
				table, len(orgAnchors), len(tRows), len(tProofs))
		} else {
			// Global: legacy full inventory.
			anchorsForTable, err := repo.ListAnchors(ctx, table)
			if err != nil {
				exitErr("list anchors %s: %v", table, err)
			}
			inv, err := repo.FetchChainInventory(ctx, table)
			if err != nil {
				exitErr("chain inventory %s: %v", table, err)
			}
			for _, row := range inv {
				allInventory = append(allInventory, evidencebundle.ChainInventoryLine{
					Table:      table,
					SeqNo:      row.SeqNo,
					RowIDHash:  row.RowIDHash,
					RowHashHex: row.RowHashHex,
				})
			}
			for _, a := range anchorsForTable {
				allAnchors = append(allAnchors, anchorToLine(a))
			}
			fmt.Printf("  %s: %d anchors, %d chained rows\n", table, len(anchorsForTable), len(inv))
		}
	}

	// Write anchors.jsonl (always present).
	if err := writeNDJSON(filepath.Join(outDir, "anchors.jsonl"), allAnchors); err != nil {
		exitErr("write anchors.jsonl: %v", err)
	}

	if tenantOrgID != "" {
		// T3/W6: tenant-specific files; no chain_inventory.jsonl.
		if err := writeNDJSON(filepath.Join(outDir, "tenant_chain_hashes.jsonl"), tenantHashes); err != nil {
			exitErr("write tenant_chain_hashes.jsonl: %v", err)
		}
		if err := writeNDJSON(filepath.Join(outDir, "merkle_proofs.jsonl"), merkleProofs); err != nil {
			exitErr("write merkle_proofs.jsonl: %v", err)
		}
	} else {
		// Global: legacy inventory.
		if err := writeNDJSON(filepath.Join(outDir, "chain_inventory.jsonl"), allInventory); err != nil {
			exitErr("write chain_inventory.jsonl: %v", err)
		}
	}

	selectorLines, err := selectorRepo.Fetch(ctx, tenantOrgID)
	if err != nil {
		exitErr("selector manifest: %v", err)
	}
	if err := writeNDJSON(filepath.Join(outDir, evidencebundle.SelectorManifestFilename), selectorLines); err != nil {
		exitErr("write %s: %v", evidencebundle.SelectorManifestFilename, err)
	}
	if tenantOrgID != "" {
		fmt.Printf("  legal_holds: %d query_scope selector manifests (org=%s)\n", len(selectorLines), tenantOrgID)
	} else {
		fmt.Printf("  legal_holds: %d query_scope selector manifests\n", len(selectorLines))
	}

	// Write public key if provided.
	hasPubKey := pubKeyB64 != ""
	if hasPubKey {
		if err := os.WriteFile(filepath.Join(outDir, "public_key.b64"), []byte(pubKeyB64+"\n"), 0o644); err != nil {
			exitErr("write public_key.b64: %v", err)
		}
	}

	// Run anchor verification reports (W3 + W4.1).
	// Tenant bundles (--org-id) skip global verification reports: VerifyAnchors and
	// VerifyAnchorSignatures operate on the full table and would expose global anchor
	// counts and metadata to the tenant auditor. For tenant export the chain_inventory
	// and anchors.jsonl already contain all information for offline Merkle verification.
	if tenantOrgID == "" {
		for _, table := range tables {
			// W3: anchor verify.
			anchorResult, err := chain.VerifyAnchors(ctx, db, table, "")
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: anchor verify %s failed: %v\n", table, err)
			} else {
				if err := writeJSON(filepath.Join(outDir, "reports", fmt.Sprintf("anchor_verify_%s.json", table)), anchorResult); err != nil {
					exitErr("write anchor report %s: %v", table, err)
				}
			}

			// W4.1: signature verify (only if pubkey provided).
			if hasPubKey {
				pubKey, _ := chain.ParsePublicKey(pubKeyB64)
				sigResult, err := chain.VerifyAnchorSignatures(ctx, db, table, pubKey)
				if err != nil {
					fmt.Fprintf(os.Stderr, "WARNING: signature verify %s failed: %v\n", table, err)
				} else {
					if err := writeJSON(filepath.Join(outDir, "reports", fmt.Sprintf("signature_verify_%s.json", table)), sigResult); err != nil {
						exitErr("write sig report %s: %v", table, err)
					}
				}
			}
		}
	} else {
		fmt.Printf("Note: global verification reports skipped for tenant bundle (org=%s).\n", tenantOrgID)
		fmt.Printf("  Use audit-verify --bundle <dir> for offline Merkle inclusion proof verification.\n")
		fmt.Printf("  Files: anchors.jsonl + tenant_chain_hashes.jsonl + merkle_proofs.jsonl\n")
	}

	// Write README.txt.
	if err := evidencebundle.WriteReadme(outDir, tables, hasPubKey, tenantOrgID); err != nil {
		exitErr("write README: %v", err)
	}

	// Compute file hashes and write bundle_manifest.json.
	hashes, err := evidencebundle.ComputeBundleHashes(outDir)
	if err != nil {
		exitErr("compute bundle hashes: %v", err)
	}
	encryptedFields, keyEpochs, err := fetchBYOKBundleMetadata(ctx, db, tenantOrgID)
	if err != nil {
		exitErr("fetch BYOK bundle metadata: %v", err)
	}
	manifest := &evidencebundle.BundleManifest{
		Version:         evidencebundle.BundleVersion,
		ExportTime:      time.Now().UTC(),
		Tables:          tables,
		ExporterCommit:  exporterCommit,
		DBFingerprint:   dbFingerprint,
		EncryptedFields: encryptedFields,
		KeyEpochs:       keyEpochs,
		FileSHA256:      hashes,
	}
	if tenantOrgID != "" {
		manifest.OrgID = tenantOrgID
	}
	if err := evidencebundle.WriteManifest(outDir, manifest); err != nil {
		exitErr("write manifest: %v", err)
	}

	fmt.Printf("Bundle written: %s\n", outDir)
	fmt.Printf("  anchors: %d  inventory rows: %d\n", len(allAnchors), len(allInventory))

	if *doZip {
		// filepath.Clean removes trailing slashes before appending .zip so that
		// --output /tmp/bundle/ produces /tmp/bundle.zip, not /tmp/bundle/.zip
		// (which would land inside the bundle directory and be included in its
		// own archive during the walk).
		zipPath := filepath.Clean(outDir) + ".zip"
		if err := evidencebundle.ZipBundleDir(outDir, zipPath); err != nil {
			exitErr("zip: %v", err)
		}
		fmt.Printf("Zip written: %s\n", zipPath)
	}
}

// dbFingerprint returns SHA256(host+"/"+dbname) from the DSN.
// Falls back to hash of raw DSN if URL parse fails (no credentials exposed).
func dbFingerprint(dsn string) string {
	if u, err := url.Parse(dsn); err == nil && u.Host != "" {
		dbname := strings.TrimPrefix(u.Path, "/")
		return evidencebundle.DBFingerprint(u.Host, dbname)
	}
	// DSN key=value format: extract host and dbname best-effort.
	host, dbname := parseDSNFields(dsn)
	return evidencebundle.DBFingerprint(host, dbname)
}

// anchorToLine converts an AnchorRecord to the bundle's AnchorLine format.
func anchorToLine(a chain.AnchorRecord) evidencebundle.AnchorLine {
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
	return line
}

func parseDSNFields(dsn string) (host, dbname string) {
	for _, field := range strings.Fields(dsn) {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "host":
			host = kv[1]
		case "dbname":
			dbname = kv[1]
		}
	}
	return host, dbname
}

func writeNDJSON[T any](path string, records []T) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return evidencebundle.WriteNDJSON(f, records)
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func fetchBYOKBundleMetadata(ctx context.Context, db *sql.DB, orgID string) ([]string, []evidencebundle.KeyEpochSummary, error) {
	where := "WHERE (COALESCE(request_body,'') LIKE 'byok:v1:%' OR COALESCE(response_body,'') LIKE 'byok:v1:%')"
	args := []any{}
	if strings.TrimSpace(orgID) != "" {
		where += " AND org_id = $1"
		args = append(args, strings.TrimSpace(orgID))
	}
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(request_body,''), COALESCE(response_body,'')
		FROM audit_logs `+where, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	fieldSeen := map[string]bool{}
	kidCounts := map[string]int{}
	for rows.Next() {
		var req, resp string
		if err := rows.Scan(&req, &resp); err != nil {
			return nil, nil, err
		}
		for _, item := range []struct {
			field string
			value string
		}{
			{field: "audit_logs.request_body", value: req},
			{field: "audit_logs.response_body", value: resp},
		} {
			if !byok.IsEnvelopeString(item.value) {
				continue
			}
			env, err := byok.DecodeEnvelope(item.value)
			if err != nil {
				continue
			}
			fieldSeen[item.field] = true
			kidCounts[env.KID]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	encryptedFields := make([]string, 0, len(fieldSeen))
	for _, field := range []string{"audit_logs.request_body", "audit_logs.response_body"} {
		if fieldSeen[field] {
			encryptedFields = append(encryptedFields, field)
		}
	}
	if len(kidCounts) == 0 {
		return encryptedFields, nil, nil
	}
	summaries := make([]evidencebundle.KeyEpochSummary, 0, len(kidCounts))
	for kid, count := range kidCounts {
		var s evidencebundle.KeyEpochSummary
		err := db.QueryRowContext(ctx, `SELECT org_id::text, kid, provider, provider_kid, status
			FROM byok_key_epochs WHERE kid = $1`, kid).Scan(&s.OrgID, &s.KID, &s.Provider, &s.ProviderKID, &s.Status)
		if errors.Is(err, sql.ErrNoRows) {
			s = evidencebundle.KeyEpochSummary{KID: kid, Status: "unknown", FieldCount: count}
			summaries = append(summaries, s)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		s.FieldCount = count
		summaries = append(summaries, s)
	}
	return encryptedFields, summaries, nil
}

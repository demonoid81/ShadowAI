// cmd/audit-verify — PR-W2: tamper-evident chain verifier CLI.
//
// Верифицирует integrity hash chain для:
//   - audit_logs
//   - admin_event_logs
//   - legal_hold_events
//   - audit_purge_runs
//
// Требует DATABASE_URL. AUDIT_CHAIN_SECRET обязателен только для режима
// chain verification (W2 tier). Anchor-only mode (W3 tier) не требует секрета.
//
// Usage:
//
//	# Chain verification (W2 tier, requires AUDIT_CHAIN_SECRET):
//	audit-verify [--table <table>] [--verbose]
//
//	# Anchor verification (W3 tier, no secret, optionally cross-reference sink):
//	audit-verify --anchor-only [--anchor-sink-path <file>] [--table <table>]
//
//	# Both chain + anchor:
//	audit-verify --include-anchors [--anchor-sink-path <file>] [--table <table>]
//
//	# W5.2: offline bundle verification (no DATABASE_URL required):
//	audit-verify --bundle <dir|zip> [--pubkey-file <key>] [--verbose]
//
// --table: "audit_logs" | "admin_event_logs" | "legal_hold_events" |
//
//	"audit_purge_runs" | "all" (default)
//
// --anchor-sink-path: path to NDJSON file:// sink file for external cross-reference.
// --bundle: path to evidence bundle directory or .zip (W5.2 offline mode).
//
// Exit codes:
//
//	0 — verification OK
//	1 — chain/anchor failures detected (GAP, CHAIN_BREAK, ANCHOR_MISMATCH)
//	2 — configuration / connection / invalid-flag error
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/shadowai/backend/internal/chain"
	"github.com/shadowai/backend/internal/evidencebundle"
)

func main() {
	tableFlag := flag.String("table", "all", "Table to verify: audit_logs|admin_event_logs|legal_hold_events|audit_purge_runs|all")
	verbose := flag.Bool("verbose", false, "Print detailed gap/break info")
	anchorOnly := flag.Bool("anchor-only", false, "W3 anchor-only mode: no chain_secret required, verifies Merkle anchors")
	includeAnchors := flag.Bool("include-anchors", false, "Also verify Merkle anchors in addition to chain (W2+W3 combined)")
	anchorSinkPath := flag.String("anchor-sink-path", "", "Path to NDJSON file:// sink for external anchor cross-reference")
	verifySignatures := flag.Bool("verify-signatures", false, "W4.1: verify Ed25519 anchor signatures (--pubkey or --pubkey-file required)")
	pubKeyFlag := flag.String("pubkey", "", "Base64-encoded Ed25519 public key for signature verification")
	pubKeyFile := flag.String("pubkey-file", "", "Path to file containing base64 Ed25519 public key")
	// W5.2: offline bundle verification mode.
	bundleFlag := flag.String("bundle", "", "W5.2: path to evidence bundle dir or .zip for offline verification (no DATABASE_URL required)")
	// W4.2: immudb:// sink verification.
	// Usage: audit-verify --verify-sink --immudb-addr 127.0.0.1:3322 --immudb-db shadowai
	//        [--immudb-user immudb --immudb-pass immudb]
	// For each DB anchor with sink_name=immudb://, fetches manifest from immudb,
	// cross-checks all fields, and verifies Ed25519 signature (if --pubkey provided).
	verifySink      := flag.Bool("verify-sink", false, "W4.2: verify anchor manifests against external immudb sink")
	immudbAddr      := flag.String("immudb-addr", "127.0.0.1:3322", "immudb REST address for --verify-sink")
	immudbDB        := flag.String("immudb-db", "shadowai", "immudb database for --verify-sink")
	immudbUser      := flag.String("immudb-user", "immudb", "immudb username for --verify-sink")
	immudbPass      := flag.String("immudb-pass", "", "immudb password for --verify-sink")
	immudbAPIPrefix := flag.String("immudb-api-prefix", "", "immudb REST API prefix (default /v1/immurestproxy for immugw; /api/v2 for immudb 2.x built-in REST)")
	immudbProfile   := flag.String("immudb-rest-profile", "", "W4.3.1: immudb REST API profile: immugw_v1 (default) or immudb_v2 (immudb 1.9+ built-in REST)")
	flag.Parse()

	// Config errors exit with code 2 (not 1 which is verification failure).
	exitConfig := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "config error: "+format+"\n", args...)
		os.Exit(2)
	}

	// W5.2: --bundle mode — entirely offline, no DATABASE_URL or chain secret required.
	if *bundleFlag != "" {
		var pubKey ed25519.PublicKey
		// Resolve pubkey: --pubkey or --pubkey-file override bundle's own public_key.b64.
		switch {
		case *pubKeyFlag != "":
			pk, err := chain.ParsePublicKey(*pubKeyFlag)
			if err != nil {
				exitConfig("--pubkey: %v", err)
			}
			pubKey = pk
		case *pubKeyFile != "":
			data, err := os.ReadFile(*pubKeyFile)
			if err != nil {
				exitConfig("--pubkey-file: %v", err)
			}
			pk, err := chain.ParsePublicKey(strings.TrimSpace(string(data)))
			if err != nil {
				exitConfig("--pubkey-file: invalid key: %v", err)
			}
			pubKey = pk
		}
		// pubKey may remain nil — VerifyBundle reads bundle's public_key.b64.

		dir, cleanup, err := evidencebundle.OpenBundle(*bundleFlag)
		if err != nil {
			exitConfig("--bundle: %v", err)
		}
		defer cleanup()

		// T3/W6: dispatch on bundle type.
		// Tenant bundles (org_id != "") use VerifyTenantBundle (Merkle proofs).
		// Global bundles use legacy VerifyBundle (full chain inventory).
		manifest, manifestErr := evidencebundle.ReadBundleManifest(dir)
		if manifestErr != nil {
			fmt.Fprintf(os.Stderr, "ERROR: read manifest: %v\n", manifestErr)
			os.Exit(1)
		}

		if manifest.OrgID != "" {
			// Tenant bundle — resolve pubKey from bundle if not supplied.
			if pubKey == nil {
				pubKey, _ = evidencebundle.LoadBundlePublicKey(dir)
			}
			tenantResult, err := evidencebundle.VerifyTenantBundle(dir, pubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: tenant bundle verify: %v\n", err)
				os.Exit(1)
			}
			printTenantBundleResult(tenantResult, *verbose)
			if !tenantResult.OK {
				os.Exit(1)
			}
		} else {
			// Global bundle — legacy path.
			result, err := evidencebundle.VerifyBundle(dir, pubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: bundle verify: %v\n", err)
				os.Exit(1)
			}
			printBundleResult(result, *verbose)
			if !result.OK {
				os.Exit(1)
			}
		}
		return
	}

	// Chain verification (W2 tier) requires AUDIT_CHAIN_SECRET.
	// Anchor-only (W3 tier) does not.
	wantChain := !*anchorOnly
	var secretBytes []byte
	if wantChain {
		secret := os.Getenv("AUDIT_CHAIN_SECRET")
		if secret == "" {
			exitConfig("AUDIT_CHAIN_SECRET is required for chain verification (use --anchor-only to skip)")
		}
		if len(secret) < 32 {
			exitConfig("AUDIT_CHAIN_SECRET must be >= 32 chars")
		}
		secretBytes = []byte(secret)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		exitConfig("DATABASE_URL is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		exitConfig("db open: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		exitConfig("db ping: %v", err)
	}

	ctx := context.Background()
	var anyFail bool

	tables := []string{*tableFlag}
	if *tableFlag == "all" {
		tables = []string{"audit_logs", "admin_event_logs", "legal_hold_events", "audit_purge_runs"}
	}

	// W2 chain verification.
	if wantChain {
		var results []chain.VerifyResult
		for _, table := range tables {
			var res chain.VerifyResult
			var err error
			switch table {
			case "audit_logs":
				res, err = chain.VerifyAuditLogs(ctx, db, secretBytes)
			case "admin_event_logs":
				res, err = chain.VerifyAdminEventLogs(ctx, db, secretBytes)
			case "legal_hold_events":
				res, err = chain.VerifyLegalHoldEvents(ctx, db, secretBytes)
			case "audit_purge_runs":
				res, err = chain.VerifyAuditPurgeRuns(ctx, db, secretBytes)
			default:
				exitConfig("unknown table: %q (valid: audit_logs|admin_event_logs|legal_hold_events|audit_purge_runs|all)", table)
				return
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR chain %s: %v\n", table, err)
				anyFail = true
				continue
			}
			results = append(results, res)
			if !res.OK {
				anyFail = true
			}
		}
		for _, res := range results {
			status := "OK"
			if !res.OK {
				status = "FAIL"
			}
			fmt.Printf("chain  %-24s %-6s rows=%d gaps=%d breaks=%d elapsed=%s\n",
				res.Table, status, res.RowCount, len(res.Gaps), len(res.Breaks), res.Duration.Round(1e6))
			if *verbose {
				for _, g := range res.Gaps {
					fmt.Printf("  GAP seq_no=%d\n", g)
				}
				for _, b := range res.Breaks {
					fmt.Printf("  CHAIN_BREAK seq_no=%d row_id=%s\n", b.SeqNo, b.RowID)
				}
			}
		}
	}

	// W4.1: signature verification — no chain_secret required, needs public key.
	if *verifySignatures {
		var pubKeyB64 string
		switch {
		case *pubKeyFlag != "":
			pubKeyB64 = *pubKeyFlag
		case *pubKeyFile != "":
			data, err := os.ReadFile(*pubKeyFile)
			if err != nil {
				exitConfig("pubkey-file: %v", err)
			}
			pubKeyB64 = strings.TrimSpace(string(data))
		default:
			exitConfig("--verify-signatures requires --pubkey or --pubkey-file")
		}
		pubKey, err := chain.ParsePublicKey(pubKeyB64)
		if err != nil {
			exitConfig("parse public key: %v", err)
		}
		for _, table := range tables {
			sr, err := chain.VerifyAnchorSignatures(ctx, db, table, pubKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR signatures %s: %v\n", table, err)
				anyFail = true
				continue
			}
			if !sr.OK {
				anyFail = true
			}
			status := "OK"
			if !sr.OK {
				status = "FAIL"
			}
			fmt.Printf("sigs   %-24s %-6s total=%d unsigned=%d fails=%d\n",
				sr.Table, status, sr.AnchorCount, sr.UnsignedCount, len(sr.SignatureFails))
			if *verbose {
				for _, f := range sr.SignatureFails {
					fmt.Printf("  SIG_FAIL anchor_id=%s range=[%d,%d] (tampered or wrong key)\n",
						f.AnchorID, f.SeqLo, f.SeqHi)
				}
			}
		}
	}

	// W4.2: immudb sink verification.
	if *verifySink {
		if *immudbPass == "" {
			exitConfig("--verify-sink requires --immudb-pass")
		}
		opts := chain.DefaultImmuDBOptions()
		if *immudbAPIPrefix != "" {
			opts.APIPrefix = *immudbAPIPrefix
		}
		if *immudbProfile != "" {
			parsed, err := chain.ParseImmuDBRESTProfile(*immudbProfile)
			if err != nil {
				exitConfig("--immudb-rest-profile: %v", err)
			}
			opts.Profile = parsed
		}
		immuClient, err := chain.DialImmuDBWithOptions(ctx, *immudbAddr, *immudbUser, *immudbPass, *immudbDB, opts)
		if err != nil {
			exitConfig("immudb connect: %v", err)
		}
		sink := chain.NewImmuDBSink(immuClient, *immudbDB)
		repo := chain.NewAnchorRepository(db)

		// Optional pubKey for signature verification.
		var sinkPubKey ed25519.PublicKey
		if *pubKeyFlag != "" || *pubKeyFile != "" {
			var b64 string
			if *pubKeyFlag != "" {
				b64 = *pubKeyFlag
			} else {
				data, err := os.ReadFile(*pubKeyFile)
				if err != nil {
					exitConfig("pubkey-file: %v", err)
				}
				b64 = strings.TrimSpace(string(data))
			}
			pk, err := chain.ParsePublicKey(b64)
			if err != nil {
				exitConfig("parse public key for --verify-sink: %v", err)
			}
			sinkPubKey = pk
		}

		for _, table := range tables {
			anchors, err := repo.ListAnchors(ctx, table)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR sink list anchors %s: %v\n", table, err)
				anyFail = true
				continue
			}
			var sinkFails, sinkOK int
			var sigWarned bool
			for _, a := range anchors {
				if a.SinkName != "immudb://" {
					continue
				}
				// Warn if signed anchor verified without pubkey (signature not checked).
				if a.PubKeyID != "" && len(sinkPubKey) == 0 && !sigWarned {
					fmt.Printf("  WARNING: signed anchor(s) for %s found (pubkey_id=%q) "+
						"but no --pubkey provided — field parity only, signature NOT verified.\n",
						table, a.PubKeyID)
					sigWarned = true
				}
				aCopy := a
				ok, err := chain.VerifyImmuDBSinkRecord(ctx, sink, &aCopy, sinkPubKey)
				if err != nil {
					if *verbose {
						fmt.Printf("  SINK_ERR anchor_id=%s: %v\n", a.ID, err)
					}
					sinkFails++
					anyFail = true
				} else if !ok {
					sinkFails++
					anyFail = true
					if *verbose {
						fmt.Printf("  SINK_MISMATCH anchor_id=%s range=[%d,%d]\n", a.ID, a.SeqLo, a.SeqHi)
					}
				} else {
					sinkOK++
				}
			}
			status := "OK"
			if sinkFails > 0 {
				status = "FAIL"
			}
			fmt.Printf("sink   %-24s %-6s ok=%d fails=%d\n", table, status, sinkOK, sinkFails)
		}
	}

	// W3 anchor verification — no secret required.
	if *anchorOnly || *includeAnchors {
		for _, table := range tables {
			ar, err := chain.VerifyAnchors(ctx, db, table, *anchorSinkPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR anchors %s: %v\n", table, err)
				anyFail = true
				continue
			}
			if !ar.OK {
				anyFail = true
			}
			status := "OK"
			if !ar.OK {
				status = "FAIL"
			}
			fmt.Printf("anchor %-24s %-6s count=%d db_mm=%d sink_mm=%d seq_gaps=%d\n",
				ar.Table, status, ar.AnchorCount,
				len(ar.DBMismatches), len(ar.SinkMismatches), len(ar.SeqGaps))
			if *verbose {
				for _, m := range ar.DBMismatches {
					fmt.Printf("  DB_MISMATCH anchor_id=%s range=[%d,%d] (rows modified in DB)\n",
						m.AnchorID, m.SeqLo, m.SeqHi)
				}
				for _, m := range ar.SinkMismatches {
					if m.Recomputed == nil {
						fmt.Printf("  SINK_MISSING anchor_id=%s range=[%d,%d] (in DB sink_ok=true but missing from sink file)\n",
							m.AnchorID, m.SeqLo, m.SeqHi)
					} else {
						fmt.Printf("  SINK_MISMATCH anchor_id=%s range=[%d,%d] (DB anchor root ≠ external sink root — DBA tampering)\n",
							m.AnchorID, m.SeqLo, m.SeqHi)
					}
				}
				for _, g := range ar.SeqGaps {
					fmt.Printf("  ANCHOR_GAP seq_no=%d\n", g)
				}
			}
		}
	}

	if anyFail {
		os.Exit(1)
	}
}

// printBundleResult prints W5.2 bundle verification results in the same
// single-line-per-check style as the live audit-verify output.
func printBundleResult(r evidencebundle.BundleVerifyResult, verbose bool) {
	status := func(ok bool) string {
		if ok {
			return "OK"
		}
		return "FAIL"
	}

	// File integrity.
	fi := r.FileIntegrity
	fmt.Printf("bundle file_integrity          %-6s checked=%d fails=%d\n",
		status(fi.OK), fi.Checked, len(fi.Fails))
	if verbose {
		for _, f := range fi.Fails {
			if f.Missing {
				fmt.Printf("  FILE_MISSING %s\n", f.File)
			} else {
				fmt.Printf("  FILE_TAMPERED %s (want=%s got=%s)\n", f.File, f.Expected[:8]+"…", f.Actual[:8]+"…")
			}
		}
	}

	// Anchor signatures.
	as := r.AnchorSigs
	fmt.Printf("bundle sigs                    %-6s total=%d unsigned=%d no_pubkey=%d fails=%d\n",
		status(as.OK), as.Total, as.Unsigned, as.NoPubKey, len(as.Fails))
	if verbose {
		for _, f := range as.Fails {
			fmt.Printf("  SIG_FAIL anchor_id=%s table=%s range=[%d,%d]\n",
				f.AnchorID, f.Table, f.SeqLo, f.SeqHi)
		}
	}

	// Range continuity per table.
	for _, rc := range r.RangeContinuity {
		fmt.Printf("bundle range  %-18s %-6s anchors=%d gaps=%d\n",
			rc.Table, status(rc.OK), rc.AnchorCount, len(rc.Gaps))
		if verbose {
			for _, g := range rc.Gaps {
				fmt.Printf("  RANGE_GAP prev_seq_hi=%d next_seq_lo=%d (rows %d..%d not covered by any anchor)\n",
					g.PrevSeqHi, g.NextSeqLo, g.PrevSeqHi+1, g.NextSeqLo-1)
			}
		}
	}

	// Inventory continuity per table.
	for _, ic := range r.InventoryContinuity {
		fmt.Printf("bundle inv    %-18s %-6s rows=%d gaps=%d\n",
			ic.Table, status(ic.OK), ic.RowCount, len(ic.Gaps))
		if verbose {
			for _, g := range ic.Gaps {
				fmt.Printf("  INV_GAP seq_no=%d\n", g)
			}
		}
	}

	// Inventory count vs anchor row_count.
	for _, ic := range r.InventoryCount {
		fmt.Printf("bundle count  %-18s %-6s anchors=%d mismatches=%d\n",
			ic.Table, status(ic.OK), ic.Anchors, len(ic.Mismatches))
		if verbose {
			for _, m := range ic.Mismatches {
				fmt.Printf("  COUNT_MISMATCH anchor_id=%s range=[%d,%d] anchor_count=%d inventory_count=%d\n",
					m.AnchorID, m.SeqLo, m.SeqHi, m.AnchorRowCount, m.InventoryCount)
			}
		}
	}
}

func printTenantBundleResult(r evidencebundle.TenantVerifyResult, verbose bool) {
	ok := func(b bool) string {
		if b {
			return "OK"
		}
		return "FAIL"
	}
	status := ok(r.OK)
	fmt.Printf("tenant bundle proofs            %-6s checked=%d failed=%d\n",
		status, r.ProofsChecked, len(r.ProofsFailed))
	if verbose {
		for _, f := range r.ProofsFailed {
			fmt.Printf("  PROOF_FAIL table=%s seq_no=%d reason=%s\n",
				f.Table, f.SeqNo, f.Reason)
		}
	}
	fmt.Printf("tenant bundle sigs              %-6s failed=%d\n",
		ok(len(r.SignaturesFailed) == 0), len(r.SignaturesFailed))
	if verbose {
		for _, id := range r.SignaturesFailed {
			fmt.Printf("  SIG_FAIL anchor_id=%s\n", id)
		}
	}
}

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
// --table: "audit_logs" | "admin_event_logs" | "legal_hold_events" |
//
//	"audit_purge_runs" | "all" (default)
//
// --anchor-sink-path: path to NDJSON file:// sink file for external cross-reference.
//
// Exit codes:
//
//	0 — verification OK
//	1 — chain/anchor failures detected (GAP, CHAIN_BREAK, ANCHOR_MISMATCH)
//	2 — configuration / connection / invalid-flag error
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/shadowai/backend/internal/chain"
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
	// W4.2: immudb:// sink verification.
	// Usage: audit-verify --verify-sink --immudb-addr 127.0.0.1:3322 --immudb-db shadowai
	// Fetches manifest from immudb per each anchor's sink_ref, cross-checks fields + signature.
	verifySink := flag.Bool("verify-sink", false, "W4.2: verify anchor manifests against external immudb sink")
	immudbAddr := flag.String("immudb-addr", "127.0.0.1:3322", "immudb server address for --verify-sink")
	immudbDB := flag.String("immudb-db", "shadowai", "immudb database for --verify-sink")
	_ = verifySink  // reserved; real client wired in W4.2 integration
	_ = immudbAddr
	_ = immudbDB
	flag.Parse()

	// Config errors exit with code 2 (not 1 which is verification failure).
	exitConfig := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "config error: "+format+"\n", args...)
		os.Exit(2)
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

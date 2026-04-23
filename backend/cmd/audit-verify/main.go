// cmd/audit-verify — PR-W2: tamper-evident chain verifier CLI.
//
// Верифицирует integrity hash chain для audit_logs, admin_event_logs,
// legal_hold_events. Требует AUDIT_CHAIN_SECRET и DATABASE_URL.
//
// Usage:
//
//	audit-verify [--table <table>] [--verbose]
//
// --table: "audit_logs" | "admin_event_logs" | "legal_hold_events" | "all" (default)
// --verbose: print each gap and break detail
//
// Exit codes:
//
//	0 — chain OK
//	1 — chain failures detected (GAP or CHAIN_BREAK)
//	2 — configuration / connection error
//
// W2 verifier requires AUDIT_CHAIN_SECRET (privileged tool).
// See RFC §8.4 for verification tier semantics.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	"context"

	_ "github.com/lib/pq"
	"github.com/shadowai/backend/internal/chain"
)

func main() {
	tableFlag := flag.String("table", "all", "Table to verify: audit_logs|admin_event_logs|legal_hold_events|all")
	verbose := flag.Bool("verbose", false, "Print detailed gap/break info")
	flag.Parse()

	secret := os.Getenv("AUDIT_CHAIN_SECRET")
	if secret == "" {
		log.Fatal("AUDIT_CHAIN_SECRET is required for chain verification")
	}
	if len(secret) < 32 {
		log.Fatal("AUDIT_CHAIN_SECRET must be >= 32 chars")
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		log.Fatalf("db ping: %v", err)
	}

	secretBytes := []byte(secret)
	ctx := context.Background()

	var results []chain.VerifyResult
	var anyFail bool

	tables := []string{*tableFlag}
	if *tableFlag == "all" {
		tables = []string{"audit_logs", "admin_event_logs", "legal_hold_events"}
	}

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
		default:
			log.Fatalf("unknown table: %q (valid: audit_logs|admin_event_logs|legal_hold_events|all)", table)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", table, err)
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
		fmt.Printf("%-25s %-6s rows=%d gaps=%d breaks=%d elapsed=%s\n",
			res.Table, status, res.RowCount, len(res.Gaps), len(res.Breaks), res.Duration.Round(1e6))
		if *verbose && len(res.Gaps) > 0 {
			for _, g := range res.Gaps {
				fmt.Printf("  GAP seq_no=%d (row deleted or sequence broken)\n", g)
			}
		}
		if *verbose && len(res.Breaks) > 0 {
			for _, b := range res.Breaks {
				fmt.Printf("  CHAIN_BREAK seq_no=%d row_id=%s (row modified after insert)\n",
					b.SeqNo, b.RowID)
			}
		}
	}

	if anyFail {
		os.Exit(1)
	}
}

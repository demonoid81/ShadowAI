//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

// Command audit-purge удаляет audit_logs старше TTL.
//
// Usage (PR-T2.4: explicit org scope required):
//
//	audit-purge --retention-days 30 --org-id <uuid>     # tenant purge
//	audit-purge --retention-days 30 --all-orgs          # global purge (privileged)
//	audit-purge --retention-days 30 --org-id <uuid> --dry-run
//
// Exit codes:
//
//	0 — purge завершён (возможно 0 строк, это ок)
//	1 — runtime error (DB unreachable, SQL fail)
//	2 — config error (bad flags, missing scope)
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
)

const (
	exitOK      = 0
	exitRuntime = 1
	exitCfg     = 2 // missing/invalid flags — distinct from runtime failures
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run — чистая CLI-логика для тестирования через exec-less harness.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-purge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		retentionDays = fs.Int("retention-days", 0, "rows older than N days are deleted (required, must be > 0)")
		dryRun        = fs.Bool("dry-run", false, "count what would be deleted but do not modify rows")
		chunkSize     = fs.Int("chunk-size", 1000, "batch size for chunked DELETE (protects against long locks)")
		dbURL         = fs.String("database-url", "", "override DATABASE_URL env")
		target        = fs.String("target", "audit_logs", "purge target: audit_logs | admin_event_logs")
		orgID         = fs.String("org-id", "", "purge only this org's rows (required unless --all-orgs)")
		allOrgs       = fs.Bool("all-orgs", false, "purge all orgs (global; requires elevated privilege)")
	)
	if err := fs.Parse(args); err != nil {
		return exitRuntime
	}

	// PR-T2.4: explicit scope required — fail-fast with exit 2 if neither provided.
	if strings.TrimSpace(*orgID) == "" && !*allOrgs {
		fmt.Fprintln(stderr, "error: --org-id <uuid> or --all-orgs is required (PR-T2.4: purge scope must be explicit)")
		fmt.Fprintln(stderr, "  --org-id <uuid>   purge rows for a single org")
		fmt.Fprintln(stderr, "  --all-orgs        purge all orgs (global, privileged operation)")
		fs.Usage()
		return exitCfg
	}
	if strings.TrimSpace(*orgID) != "" && *allOrgs {
		fmt.Fprintln(stderr, "error: --org-id and --all-orgs are mutually exclusive")
		return exitCfg
	}

	if *retentionDays <= 0 {
		fmt.Fprintln(stderr, "error: --retention-days is required and must be > 0")
		fs.Usage()
		return exitCfg
	}
	if *chunkSize <= 0 {
		fmt.Fprintln(stderr, "error: --chunk-size must be > 0")
		return exitCfg
	}
	switch *target {
	case audit.PurgeTargetAuditLogs, adminaudit.PurgeTarget:
	default:
		fmt.Fprintf(stderr, "error: invalid --target %q (want audit_logs|admin_event_logs)\n", *target)
		return exitCfg
	}

	url := *dbURL
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		fmt.Fprintln(stderr, "error: DATABASE_URL env or --database-url flag required")
		return exitCfg
	}

	// Determine scope for evidence record.
	scope := "global"
	effectiveOrgID := ""
	if strings.TrimSpace(*orgID) != "" {
		scope = "org"
		effectiveOrgID = strings.TrimSpace(*orgID)
	}

	db, err := sql.Open("postgres", url)
	if err != nil {
		fmt.Fprintf(stderr, "error: open DB: %v\n", err)
		return exitRuntime
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	cutoff := time.Now().UTC().Add(-time.Duration(*retentionDays) * 24 * time.Hour)
	fmt.Fprintf(stdout, "audit-purge: target=%s scope=%s org=%s cutoff=%s (retention=%d days), chunk_size=%d, dry_run=%v\n",
		*target, scope, effectiveOrgID, cutoff.Format(time.RFC3339), *retentionDays, *chunkSize, *dryRun)

	auditRepo := audit.NewRepository(db)

	if *dryRun {
		table := "audit_logs"
		if *target == adminaudit.PurgeTarget {
			table = "admin_event_logs"
		}
		var n int
		var scanErr error
		if effectiveOrgID != "" {
			//nolint:gosec // table name is from whitelist
			scanErr = db.QueryRowContext(ctx,
				fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE created_at < $1 AND org_id = $2`, table),
				cutoff, effectiveOrgID).Scan(&n)
		} else {
			//nolint:gosec // table name is from whitelist
			scanErr = db.QueryRowContext(ctx,
				fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE created_at < $1`, table),
				cutoff).Scan(&n)
		}
		if scanErr != nil {
			fmt.Fprintf(stderr, "error: count: %v\n", scanErr)
			return exitRuntime
		}
		fmt.Fprintf(stdout, "dry-run: would delete %d rows\n", n)
		return exitOK
	}

	// W2.3 + PR-T2.4: atomic PurgeAndRecord with org scope.
	var deleted int
	var purgeErr error
	if *target == adminaudit.PurgeTarget {
		adminRepo := adminaudit.NewRepository(db)
		deleted, purgeErr = adminRepo.PurgeAndRecord(ctx, cutoff, *chunkSize, func(c context.Context, tx *sql.Tx, total int) error {
			return auditRepo.RecordPurgeRunTx(c, tx, cutoff, total, *target, effectiveOrgID, scope)
		})
	} else {
		deleted, purgeErr = auditRepo.PurgeAndRecord(ctx, cutoff, *chunkSize, *target, effectiveOrgID, scope)
	}
	if purgeErr != nil {
		fmt.Fprintf(stderr, "error: purge: %v\n", purgeErr)
		recordPurgeAdminEvent(ctx, db, cutoff, 0, "cli", *target, effectiveOrgID, scope, purgeErr.Error())
		return exitRuntime
	}
	recordPurgeAdminEvent(ctx, db, cutoff, deleted, "cli", *target, effectiveOrgID, scope, "")
	fmt.Fprintf(stdout, "deleted %d rows\n", deleted)
	return exitOK
}

func recordPurgeAdminEvent(ctx context.Context, db *sql.DB, cutoff time.Time, rowsDeleted int, mode, target, orgID, scope, errMsg string) {
	repo := adminaudit.NewRepository(db)
	svc := adminaudit.NewService(repo)
	success := errMsg == ""
	metadata := map[string]any{
		"mode":         mode,
		"cutoff":       cutoff.Format(time.RFC3339),
		"rows_deleted": rowsDeleted,
		"target":       target,
		"scope":        scope,
	}
	if orgID != "" {
		metadata["org_id"] = orgID
	}
	if !success {
		metadata["error"] = errMsg
	}
	svc.Record(ctx, adminaudit.Event{
		ActorUserID: nil,
		Action:      "purge",
		Resource:    target,
		OrgID:       orgID,
		Path:        "cmd/audit-purge",
		Method:      "CLI",
		StatusCode:  0,
		Success:     success,
		Metadata:    metadata,
	})
}

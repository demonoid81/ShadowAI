//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

// Command audit-purge удаляет audit_logs старше TTL. Запускается
// оператором вручную или scheduler'ом внутри backend (AUDIT_PURGE_INTERVAL).
//
// Usage:
//
//	audit-purge --retention-days 30
//	audit-purge --retention-days 30 --dry-run
//	audit-purge --retention-days 30 --chunk-size 500
//
// Exit codes:
//
//	0 — purge завершён (возможно 0 строк, это ок)
//	1 — runtime error (bad flags, DB unreachable, SQL fail)
//
// Reads DATABASE_URL из env (same shape, что cmd/shadowai).
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
)

const (
	exitOK      = 0
	exitRuntime = 1
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
		target        = fs.String("target", "audit_logs", "purge target: audit_logs | admin_event_logs (PR-D.1)")
	)
	if err := fs.Parse(args); err != nil {
		return exitRuntime
	}

	if *retentionDays <= 0 {
		fmt.Fprintln(stderr, "error: --retention-days is required and must be > 0")
		fs.Usage()
		return exitRuntime
	}
	if *chunkSize <= 0 {
		fmt.Fprintln(stderr, "error: --chunk-size must be > 0")
		return exitRuntime
	}
	switch *target {
	case audit.PurgeTargetAuditLogs, adminaudit.PurgeTarget:
		// OK
	default:
		fmt.Fprintf(stderr, "error: invalid --target %q (want audit_logs|admin_event_logs)\n", *target)
		return exitRuntime
	}

	url := *dbURL
	if url == "" {
		url = os.Getenv("DATABASE_URL")
	}
	if url == "" {
		fmt.Fprintln(stderr, "error: DATABASE_URL env or --database-url flag required")
		return exitRuntime
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
	fmt.Fprintf(stdout, "audit-purge: target=%s cutoff=%s (retention=%d days), chunk_size=%d, dry_run=%v\n",
		*target, cutoff.Format(time.RFC3339), *retentionDays, *chunkSize, *dryRun)

	auditRepo := audit.NewRepository(db)

	if *dryRun {
		// Dry-run: COUNT через прямой SELECT. PurgeOlderThan не вызываем,
		// чтобы не модифицировать строки.
		table := "audit_logs"
		if *target == adminaudit.PurgeTarget {
			table = "admin_event_logs"
		}
		var n int
		//nolint:gosec // table name из whitelist, не user input.
		if err := db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE created_at < $1`, table),
			cutoff).Scan(&n); err != nil {
			fmt.Fprintf(stderr, "error: count: %v\n", err)
			return exitRuntime
		}
		fmt.Fprintf(stdout, "dry-run: would delete %d rows\n", n)
		return exitOK
	}

	var deleted int
	var purgeErr error
	if *target == adminaudit.PurgeTarget {
		deleted, purgeErr = adminaudit.NewRepository(db).PurgeOlderThan(ctx, cutoff, *chunkSize)
	} else {
		deleted, purgeErr = auditRepo.PurgeOlderThan(ctx, cutoff, *chunkSize)
	}
	if purgeErr != nil {
		fmt.Fprintf(stderr, "error: purge: %v\n", purgeErr)
		recordPurgeAdminEvent(ctx, db, cutoff, 0, "cli", *target, purgeErr.Error())
		return exitRuntime
	}
	if err := auditRepo.RecordPurgeRun(ctx, cutoff, deleted, *target); err != nil {
		fmt.Fprintf(stderr, "warning: purge succeeded (%d rows deleted) but failed to record run: %v\n", deleted, err)
	}
	recordPurgeAdminEvent(ctx, db, cutoff, deleted, "cli", *target, "")
	fmt.Fprintf(stdout, "deleted %d rows\n", deleted)
	return exitOK
}

// recordPurgeAdminEvent — PR-D: логирует успешный/неудачный purge в
// admin_event_logs. actor_user_id = NULL (системная CLI-операция).
// Метаданные включают mode=cli|scheduler, cutoff RFC3339, target.
func recordPurgeAdminEvent(ctx context.Context, db *sql.DB, cutoff time.Time, rowsDeleted int, mode, target, errMsg string) {
	repo := adminaudit.NewRepository(db)
	svc := adminaudit.NewService(repo)
	success := errMsg == ""
	metadata := map[string]any{
		"mode":         mode,
		"cutoff":       cutoff.Format(time.RFC3339),
		"rows_deleted": rowsDeleted,
		"target":       target,
	}
	if !success {
		metadata["error"] = errMsg
	}
	svc.Record(ctx, adminaudit.Event{
		ActorUserID: nil,
		Action:      "purge",
		Resource:    target,
		Path:        "cmd/audit-purge",
		Method:      "CLI",
		StatusCode:  0,
		Success:     success,
		Metadata:    metadata,
	})
}

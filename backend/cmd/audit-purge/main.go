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
	fmt.Fprintf(stdout, "audit-purge: cutoff=%s (retention=%d days), chunk_size=%d, dry_run=%v\n",
		cutoff.Format(time.RFC3339), *retentionDays, *chunkSize, *dryRun)

	repo := audit.NewRepository(db)

	if *dryRun {
		// Dry-run: COUNT через прямой SELECT. PurgeOlderThan не вызываем,
		// чтобы не модифицировать строки.
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_logs WHERE created_at < $1`, cutoff).Scan(&n); err != nil {
			fmt.Fprintf(stderr, "error: count: %v\n", err)
			return exitRuntime
		}
		fmt.Fprintf(stdout, "dry-run: would delete %d rows\n", n)
		return exitOK
	}

	deleted, err := repo.PurgeOlderThan(ctx, cutoff, *chunkSize)
	if err != nil {
		fmt.Fprintf(stderr, "error: purge: %v\n", err)
		return exitRuntime
	}
	if err := repo.RecordPurgeRun(ctx, cutoff, deleted); err != nil {
		// Purge уже выполнен — не отменяем, но сообщаем оператору.
		fmt.Fprintf(stderr, "warning: purge succeeded (%d rows deleted) but failed to record run: %v\n", deleted, err)
	}
	fmt.Fprintf(stdout, "deleted %d rows\n", deleted)
	return exitOK
}

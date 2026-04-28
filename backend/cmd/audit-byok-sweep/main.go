// Command audit-byok-sweep re-encrypts legacy audit payload fields after BYOK rollout.
//
// It is intentionally operator-triggered rather than a background scheduler:
// historical audit rows are being rewritten, even though WORM canonical hashes
// remain valid because request/response bodies are outside canonical fields.
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

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/config"
)

const (
	exitOK      = 0
	exitRuntime = 1
	exitCfg     = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-byok-sweep", flag.ContinueOnError)
	fs.SetOutput(stderr)
	databaseURL := fs.String("database-url", "", "override DATABASE_URL env")
	limit := fs.Int("limit", 1000, "maximum rows to scan in this run")
	orgID := fs.String("org-id", "", "optional org_id filter")
	dryRun := fs.Bool("dry-run", false, "count rows that would be updated without writing")
	if err := fs.Parse(args); err != nil {
		return exitRuntime
	}
	if *limit <= 0 {
		fmt.Fprintln(stderr, "config error: --limit must be > 0")
		return exitCfg
	}

	cfg := config.Load()
	if !cfg.BYOKEnabled {
		fmt.Fprintln(stderr, "config error: BYOK_ENABLED=true is required")
		return exitCfg
	}
	dsn := strings.TrimSpace(*databaseURL)
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv("DATABASE_URL"))
	}
	if dsn == "" {
		fmt.Fprintln(stderr, "config error: DATABASE_URL env or --database-url flag required")
		return exitCfg
	}

	var enc byok.Encryptor
	var err error
	if !*dryRun {
		enc, err = byok.NewEncryptorFromConfig(byok.RuntimeConfig{
			Provider:     cfg.BYOKProvider,
			VaultAddr:    cfg.BYOKVaultAddr,
			VaultToken:   cfg.BYOKVaultToken,
			VaultMount:   cfg.BYOKVaultMount,
			VaultKeyName: cfg.BYOKVaultKeyName,
			Timeout:      cfg.BYOKTimeout,
			StaticKeyB64: cfg.BYOKStaticKeyB64,
		})
		if err != nil {
			fmt.Fprintf(stderr, "config error: BYOK encryptor: %v\n", err)
			return exitCfg
		}
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(stderr, "error: open DB: %v\n", err)
		return exitRuntime
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		fmt.Fprintf(stderr, "error: db ping: %v\n", err)
		return exitRuntime
	}

	repo := audit.NewRepository(db).WithPayloadEncryptor(enc)
	result, err := repo.ReencryptLegacyPayloads(ctx, audit.ReencryptOptions{
		Limit:  *limit,
		OrgID:  strings.TrimSpace(*orgID),
		DryRun: *dryRun,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: BYOK sweep: %v\n", err)
		return exitRuntime
	}
	fmt.Fprintf(stdout, "audit-byok-sweep: scanned=%d would_update=%d updated=%d skipped_concurrent=%d request_fields=%d response_fields=%d dry_run=%v\n",
		result.Scanned, result.WouldUpdate, result.Updated, result.SkippedConcurrentUpdate,
		result.RequestFieldsEncrypted, result.ResponseFieldsEncrypted, *dryRun)
	return exitOK
}

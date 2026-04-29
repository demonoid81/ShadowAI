// Command audit-byok-epochs manages non-secret BYOK DEK epoch metadata.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/shadowai/backend/internal/byok"
	"github.com/shadowai/backend/internal/config"
)

const (
	exitOK      = 0
	exitRuntime = 1
	exitCfg     = 2
)

type epochRepo interface {
	ListEpochs(ctx context.Context, orgID string) ([]byok.Epoch, error)
	CreateEpoch(ctx context.Context, e byok.Epoch) (byok.Epoch, error)
	ActivateEpoch(ctx context.Context, orgID, kid, actor string) error
	UpdateEpochStatus(ctx context.Context, orgID, kid, status, actor string) error
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithRepo(args, stdout, stderr, nil)
}

func runWithRepo(args []string, stdout, stderr io.Writer, repo epochRepo) int {
	fs := flag.NewFlagSet("audit-byok-epochs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	databaseURL := fs.String("database-url", "", "override DATABASE_URL env")
	action := fs.String("action", "list", "action: list|create|activate|retire|revoke|disable")
	orgID := fs.String("org-id", "", "tenant org_id (required for create/status changes)")
	kid := fs.String("kid", "", "DEK epoch kid")
	provider := fs.String("provider", "", "BYOK provider; defaults to BYOK_PROVIDER")
	providerKID := fs.String("provider-kid", "", "provider key id; defaults from BYOK config")
	status := fs.String("status", byok.EpochStatusPending, "initial status for create")
	actor := fs.String("actor-user-id", "", "optional actor user UUID for event trail")
	metadata := fs.String("metadata-json", "{}", "non-secret metadata JSON")
	format := fs.String("format", "table", "output format: table|json")
	if err := fs.Parse(args); err != nil {
		return exitRuntime
	}
	cfg := config.Load()
	if strings.TrimSpace(*provider) == "" {
		*provider = cfg.BYOKProvider
	}
	if strings.TrimSpace(*providerKID) == "" {
		*providerKID = providerKIDFromConfig(cfg)
	}
	if !json.Valid([]byte(*metadata)) {
		fmt.Fprintln(stderr, "config error: --metadata-json must be valid JSON")
		return exitCfg
	}
	if repo == nil {
		dsn := strings.TrimSpace(*databaseURL)
		if dsn == "" {
			dsn = strings.TrimSpace(os.Getenv("DATABASE_URL"))
		}
		if dsn == "" {
			fmt.Fprintln(stderr, "config error: DATABASE_URL env or --database-url flag required")
			return exitCfg
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			fmt.Fprintf(stderr, "error: open DB: %v\n", err)
			return exitRuntime
		}
		defer db.Close()
		repo = byok.NewEpochRepository(db)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch strings.TrimSpace(*action) {
	case "list":
		epochs, err := repo.ListEpochs(ctx, strings.TrimSpace(*orgID))
		if err != nil {
			fmt.Fprintf(stderr, "error: list epochs: %v\n", err)
			return exitRuntime
		}
		return writeEpochs(stdout, stderr, strings.TrimSpace(*format), epochs)
	case "create":
		if strings.TrimSpace(*orgID) == "" || strings.TrimSpace(*kid) == "" {
			fmt.Fprintln(stderr, "config error: --org-id and --kid are required for create")
			return exitCfg
		}
		if strings.TrimSpace(*provider) == "" || strings.TrimSpace(*providerKID) == "" {
			fmt.Fprintln(stderr, "config error: --provider and --provider-kid are required for create")
			return exitCfg
		}
		epoch, err := repo.CreateEpoch(ctx, byok.Epoch{
			OrgID:        strings.TrimSpace(*orgID),
			KID:          strings.TrimSpace(*kid),
			Provider:     strings.TrimSpace(*provider),
			ProviderKID:  strings.TrimSpace(*providerKID),
			Status:       strings.TrimSpace(*status),
			CreatedBy:    strings.TrimSpace(*actor),
			MetadataJSON: strings.TrimSpace(*metadata),
		})
		if err != nil {
			fmt.Fprintf(stderr, "error: create epoch: %v\n", err)
			return exitRuntime
		}
		return writeEpochs(stdout, stderr, strings.TrimSpace(*format), []byok.Epoch{epoch})
	case "activate":
		if err := requireOrgKid(stderr, *orgID, *kid, *action); err != nil {
			return exitCfg
		}
		if err := repo.ActivateEpoch(ctx, strings.TrimSpace(*orgID), strings.TrimSpace(*kid), strings.TrimSpace(*actor)); err != nil {
			fmt.Fprintf(stderr, "error: activate epoch: %v\n", err)
			return exitRuntime
		}
	case "retire", "revoke", "disable":
		if err := requireOrgKid(stderr, *orgID, *kid, *action); err != nil {
			return exitCfg
		}
		nextStatus := map[string]string{
			"retire":  byok.EpochStatusRetired,
			"revoke":  byok.EpochStatusRevoked,
			"disable": byok.EpochStatusDisabled,
		}[*action]
		if err := repo.UpdateEpochStatus(ctx, strings.TrimSpace(*orgID), strings.TrimSpace(*kid), nextStatus, strings.TrimSpace(*actor)); err != nil {
			fmt.Fprintf(stderr, "error: update epoch: %v\n", err)
			return exitRuntime
		}
	default:
		fmt.Fprintf(stderr, "config error: unsupported --action %q\n", *action)
		return exitCfg
	}
	fmt.Fprintf(stdout, "audit-byok-epochs: action=%s org_id=%s kid=%s ok\n", *action, *orgID, *kid)
	return exitOK
}

func requireOrgKid(stderr io.Writer, orgID, kid, action string) error {
	if strings.TrimSpace(orgID) == "" || strings.TrimSpace(kid) == "" {
		fmt.Fprintf(stderr, "config error: --org-id and --kid are required for %s\n", action)
		return fmt.Errorf("missing org/kid")
	}
	return nil
}

func writeEpochs(stdout, stderr io.Writer, format string, epochs []byok.Epoch) int {
	switch format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(epochs); err != nil {
			fmt.Fprintf(stderr, "error: encode epochs: %v\n", err)
			return exitRuntime
		}
	case "table":
		fmt.Fprintln(stdout, "ORG_ID\tKID\tPROVIDER\tPROVIDER_KID\tSTATUS")
		for _, e := range epochs {
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", e.OrgID, e.KID, e.Provider, e.ProviderKID, e.Status)
		}
	default:
		fmt.Fprintf(stderr, "config error: unsupported --format %q\n", format)
		return exitCfg
	}
	return exitOK
}

func providerKIDFromConfig(cfg *config.Config) string {
	switch strings.TrimSpace(cfg.BYOKProvider) {
	case "vault_transit":
		mount := strings.Trim(strings.TrimSpace(cfg.BYOKVaultMount), "/")
		if mount == "" {
			mount = "transit"
		}
		key := strings.Trim(strings.TrimSpace(cfg.BYOKVaultKeyName), "/")
		if key == "" {
			return ""
		}
		return "vault:" + mount + "/" + key
	case "static_aes_gcm":
		return "static_aes_gcm"
	default:
		return ""
	}
}

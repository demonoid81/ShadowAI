// cmd/audit-access-review — SOC2.3: Period-scoped access review evidence report.
//
// Usage:
//
//	audit-access-review --org-id <uuid> --from 2026-01-01 --to 2026-03-31
//	audit-access-review --global --from 2026-01-01 --to 2026-03-31
//	audit-access-review --org-id <uuid> --from ... --to ... \
//	  --require-admin-mfa --require-idp-link --format json --output report.json
//
// Exit codes:
//
//	0 — report generated, no findings
//	1 — findings present (review action required)
//	2 — configuration or runtime error
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
)

const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("audit-access-review", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		orgID      = fs.String("org-id", "", "Org UUID for tenant-scoped review")
		global     = fs.Bool("global", false, "Global review (cross-org, global_admin focus)")
		from       = fs.String("from", "", "Period start date YYYY-MM-DD (required)")
		to         = fs.String("to", "", "Period end date YYYY-MM-DD (required)")
		format     = fs.String("format", "table", `Output format: "table" or "json"`)
		output     = fs.String("output", "", "Write output to file (default: stdout)")
		requireMFA = fs.Bool("require-admin-mfa", false, "Finding: admins without MFA (severity critical)")
		requireIDP = fs.Bool("require-idp-link", false, "Finding: admins without OIDC/SCIM linkage")
	)
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	cfgErr := func(f string, a ...any) int {
		fmt.Fprintf(stderr, "config error: "+f+"\n", a...)
		return exitError
	}

	if *orgID == "" && !*global {
		return cfgErr("--org-id <uuid> or --global is required")
	}
	if *orgID != "" && *global {
		return cfgErr("--org-id and --global are mutually exclusive")
	}
	if *from == "" || *to == "" {
		return cfgErr("--from and --to are required (YYYY-MM-DD)")
	}
	fromTime, err := time.Parse("2006-01-02", *from)
	if err != nil {
		return cfgErr("--from: invalid date %q", *from)
	}
	toTime, err := time.Parse("2006-01-02", *to)
	if err != nil {
		return cfgErr("--to: invalid date %q", *to)
	}
	toTime = toTime.Add(24*time.Hour - time.Second) // include full to-day

	switch *format {
	case "json", "table":
	default:
		return cfgErr("--format must be json or table, got %q", *format)
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return cfgErr("DATABASE_URL is required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(stderr, "error: db open: %v\n", err)
		return exitError
	}
	defer db.Close()
	if err := db.PingContext(context.Background()); err != nil {
		fmt.Fprintf(stderr, "error: db ping: %v\n", err)
		return exitError
	}

	cfg := CollectConfig{
		OrgID:           *orgID,
		IsGlobal:        *global,
		From:            fromTime,
		To:              toTime,
		RequireAdminMFA: *requireMFA,
		RequireIDPLink:  *requireIDP,
	}

	report, err := Collect(context.Background(), db, cfg)
	if err != nil {
		fmt.Fprintf(stderr, "error: collect: %v\n", err)
		return exitError
	}

	outWriter := stdout
	if *output != "" {
		f, ferr := os.Create(*output)
		if ferr != nil {
			fmt.Fprintf(stderr, "error: create output file: %v\n", ferr)
			return exitError
		}
		defer f.Close()
		outWriter = f
	}

	switch *format {
	case "json":
		data, merr := marshalReport(report)
		if merr != nil {
			fmt.Fprintf(stderr, "error: marshal: %v\n", merr)
			return exitError
		}
		outWriter.Write(data)
		outWriter.WriteString("\n")
	case "table":
		PrintTable(outWriter, report)
	}

	if *output != "" {
		fmt.Fprintf(stderr, "[audit-access-review] report written to %s\n", *output)
	}
	if len(report.Findings) > 0 {
		fmt.Fprintf(stderr, "[audit-access-review] %d finding(s) require review action\n", len(report.Findings))
		return exitFindings
	}
	fmt.Fprintf(stderr, "[audit-access-review] review complete: %d users, no findings\n", report.UsersSummary.Total)
	return exitOK
}

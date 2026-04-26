// cmd/audit-evidence-report — PR-O4.4: S3 Evidence Retention Audit Report.
//
// Lists all evidence bundle zips under a given S3 prefix and reports their
// Object Lock retention posture. No database access required — reads only
// S3 List, HeadObject, and optionally GetObject.
//
// Usage:
//
//	audit-evidence-report \
//	  --bucket shadowai-compliance \
//	  [--prefix shadowai/evidence] \
//	  [--region us-east-1] \
//	  [--endpoint http://minio:9000] \
//	  [--force-path-style] \
//	  [--after 2026-01-01] [--before 2026-04-30] \
//	  [--require-lock] [--min-retention-days 90] \
//	  [--read-manifest] \
//	  [--format json|table] [--output report.json]
//
// Exit codes:
//
//	0 — all bundles compliant (or no policy flags set)
//	1 — one or more compliance violations found
//	2 — configuration or S3 access error
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	exitOK        = 0
	exitViolation = 1
	exitConfig    = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit-evidence-report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		bucket           = fs.String("bucket", "", "S3 bucket name (required)")
		prefix           = fs.String("prefix", "shadowai/evidence", "S3 object key prefix")
		region           = fs.String("region", "us-east-1", "AWS region")
		endpoint         = fs.String("endpoint", "", "Custom S3 endpoint URL")
		forcePathStyle   = fs.Bool("force-path-style", false, "Use path-style addressing (MinIO)")
		afterStr         = fs.String("after", "", "Include bundles last_modified on or after date (YYYY-MM-DD)")
		beforeStr        = fs.String("before", "", "Include bundles last_modified on or before date (YYYY-MM-DD)")
		requireLock      = fs.Bool("require-lock", false, "Violation if any bundle has no Object Lock mode")
		minRetentionDays = fs.Int("min-retention-days", 0, "Violation if retain_until < now + N days (0 = disabled)")
		readManifest     = fs.Bool("read-manifest", false, "Download each zip and parse bundle_manifest.json for org_id/tables")
		format           = fs.String("format", "table", `Output format: "table" or "json"`)
		outputFile       = fs.String("output", "", "Write report to file instead of stdout")
		timeout          = fs.Int("timeout", 120, "S3 operation timeout in seconds")
	)
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}

	cfgErr := func(f string, a ...any) int {
		fmt.Fprintf(stderr, "config error: "+f+"\n", a...)
		return exitConfig
	}

	if *bucket == "" {
		return cfgErr("--bucket is required")
	}
	switch *format {
	case "json", "table":
	default:
		return cfgErr("--format must be json or table, got %q", *format)
	}

	var afterFilter, beforeFilter *time.Time
	if *afterStr != "" {
		t, err := time.Parse("2006-01-02", *afterStr)
		if err != nil {
			return cfgErr("--after: %v", err)
		}
		afterFilter = &t
	}
	if *beforeStr != "" {
		t, err := time.Parse("2006-01-02", *beforeStr)
		if err != nil {
			return cfgErr("--before: %v", err)
		}
		t = t.Add(24*time.Hour - time.Second) // inclusive: include the entire day
		beforeFilter = &t
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	opts := []func(*config.LoadOptions) error{
		config.WithRegion(*region),
	}
	if accessKey := os.Getenv("AWS_ACCESS_KEY_ID"); accessKey != "" {
		secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
		sessionToken := os.Getenv("AWS_SESSION_TOKEN")
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, sessionToken),
		))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return cfgErr("load AWS config: %v", err)
	}

	s3Opts := []func(*s3.Options){}
	if *endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(*endpoint)
		})
	}
	if *forcePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}
	client := s3.NewFromConfig(cfg, s3Opts...)

	fmt.Fprintf(stderr, "[audit-evidence-report] listing s3://%s/%s\n", *bucket, *prefix)

	bundles, err := collectBundles(ctx, client, *bucket, *prefix,
		afterFilter, beforeFilter,
		*requireLock, *minRetentionDays, *readManifest)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitConfig
	}

	report := buildReport(*bucket, *prefix, *afterStr, *beforeStr,
		*requireLock, *minRetentionDays, bundles)

	out := stdout
	if *outputFile != "" {
		f, ferr := os.Create(*outputFile)
		if ferr != nil {
			return cfgErr("create output file: %v", ferr)
		}
		defer f.Close()
		out = f
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if encErr := enc.Encode(report); encErr != nil {
			fmt.Fprintf(stderr, "encode JSON: %v\n", encErr)
			return exitConfig
		}
	case "table":
		printTable(out, report)
	}

	if report.ViolationCount > 0 {
		fmt.Fprintf(stderr, "[audit-evidence-report] %d violation(s) found\n", report.ViolationCount)
		return exitViolation
	}
	fmt.Fprintf(stderr, "[audit-evidence-report] %d bundle(s) checked, all compliant\n", report.TotalBundles)
	return exitOK
}

// buildReport assembles a Report from individual bundle records.
func buildReport(bucket, prefix, afterStr, beforeStr string, requireLock bool, minRetentionDays int, bundles []BundleRecord) Report {
	r := Report{
		GeneratedAt:      time.Now().UTC(),
		Bucket:           bucket,
		Prefix:           prefix,
		AfterFilter:      afterStr,
		BeforeFilter:     beforeStr,
		RequireLock:      requireLock,
		MinRetentionDays: minRetentionDays,
		TotalBundles:     len(bundles),
		Bundles:          bundles,
	}
	for _, b := range bundles {
		if b.Compliant {
			r.CompliantCount++
		} else {
			r.ViolationCount++
		}
	}
	return r
}

// printTable writes a human-readable retention summary to w.
func printTable(w io.Writer, report Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintf(tw, "GENERATED\t%s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "BUCKET\t%s\n", report.Bucket)
	fmt.Fprintf(tw, "PREFIX\t%s\n", report.Prefix)
	fmt.Fprintf(tw, "POLICY\trequire_lock=%v  min_retention_days=%d\n",
		report.RequireLock, report.MinRetentionDays)
	fmt.Fprintf(tw, "TOTALS\t%d bundles  compliant=%d  violations=%d\n\n",
		report.TotalBundles, report.CompliantCount, report.ViolationCount)

	if len(report.Bundles) == 0 {
		fmt.Fprintln(w, "(no bundles found)")
		return
	}

	fmt.Fprintln(tw, "KEY\tTYPE\tORG_ID\tSIZE\tLOCK_MODE\tRETAIN_UNTIL\tSTATUS\tVIOLATIONS")
	fmt.Fprintln(tw, "---\t----\t------\t----\t---------\t------------\t------\t----------")
	for _, b := range report.Bundles {
		retainStr := "-"
		if b.RetainUntil != nil {
			retainStr = b.RetainUntil.Format("2006-01-02")
		}
		orgShort := b.OrgID
		if len(orgShort) > 8 {
			orgShort = orgShort[:8] + "…"
		}
		status := "OK"
		if !b.Compliant {
			status = "VIOLATION"
		}
		viols := "-"
		if len(b.Violations) > 0 {
			viols = b.Violations[0]
			for _, v := range b.Violations[1:] {
				viols += " | " + v
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			shortKey(b.Key), b.BundleType, orgShort,
			b.SizeBytes, b.LockMode, retainStr,
			status, viols)
	}
}

func shortKey(key string) string {
	const maxLen = 52
	if len(key) > maxLen {
		return "…" + key[len(key)-(maxLen-1):]
	}
	return key
}

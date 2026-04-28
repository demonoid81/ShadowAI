package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

func runValidation(ctx context.Context, opts options, runner commandRunner, client *http.Client) Report {
	report := Report{
		SchemaVersion: "1",
		GeneratedAt:   time.Now().UTC(),
		Overall:       statusPass,
	}
	if opts.Chart != "" {
		report.Checks = append(report.Checks, runCommandCheck(ctx, runner, CheckResult{
			ID:       "helm_template",
			Category: "preflight",
			Required: true,
		}, "helm", helmArgs(opts)...))
	}
	if opts.Live {
		report.Checks = append(report.Checks, runCommandCheck(ctx, runner, CheckResult{
			ID:       "kubectl_rollout",
			Category: "live",
			Required: true,
		}, "kubectl", "-n", opts.Namespace, "rollout", "status", "deployment/"+opts.Release, "--timeout="+fmt.Sprintf("%ds", int(opts.Timeout.Seconds()))))
	}
	if opts.BaseURL != "" {
		report.Checks = append(report.Checks,
			runHTTPCheck(ctx, client, "http_health", opts.BaseURL, "/api/health"),
			runHTTPCheck(ctx, client, "http_ready", opts.BaseURL, "/api/ready"),
		)
	}
	if opts.EvidenceBundle != "" {
		report.Checks = append(report.Checks, runCommandCheck(ctx, runner, CheckResult{
			ID:       "evidence_bundle",
			Category: "evidence",
			Required: true,
		}, "audit-verify", "--bundle", opts.EvidenceBundle, "--verbose"))
	}
	if opts.Bucket != "" {
		report.Checks = append(report.Checks, runCommandCheck(ctx, runner, CheckResult{
			ID:       "evidence_retention",
			Category: "evidence",
			Required: true,
		}, "audit-evidence-report", evidenceReportArgs(opts)...))
	}
	report.Summary = summarize(report.Checks)
	if report.Summary.RequiredFailures > 0 {
		report.Overall = statusFail
	}
	return report
}

func helmArgs(opts options) []string {
	args := []string{"template", opts.Release, opts.Chart, "--namespace", opts.Namespace}
	for _, v := range opts.Values {
		args = append(args, "-f", v)
	}
	if opts.ExistingSecret != "" {
		args = append(args, "--set", "existingSecret="+opts.ExistingSecret)
	}
	if opts.ImageTag != "" {
		args = append(args, "--set", "image.tag="+opts.ImageTag)
	}
	return args
}

func evidenceReportArgs(opts options) []string {
	args := []string{
		"--bucket", opts.Bucket,
		"--prefix", opts.Prefix,
		"--region", opts.Region,
		"--format", "json",
	}
	if opts.Endpoint != "" {
		args = append(args, "--endpoint", opts.Endpoint)
	}
	if opts.ForcePathStyle {
		args = append(args, "--force-path-style")
	}
	if opts.RequireObjectLock {
		args = append(args, "--require-lock")
	}
	if opts.MinRetentionDays > 0 {
		args = append(args, "--min-retention-days", fmt.Sprintf("%d", opts.MinRetentionDays))
	}
	return args
}

func runCommandCheck(ctx context.Context, runner commandRunner, base CheckResult, name string, args ...string) CheckResult {
	start := time.Now()
	output, err := runner.Run(ctx, name, args...)
	base.DurationMS = time.Since(start).Milliseconds()
	base.Detail = cleanDetail(output)
	if err != nil {
		base.Status = statusFail
		if base.Detail == "" {
			base.Detail = err.Error()
		} else {
			base.Detail = base.Detail + ": " + err.Error()
		}
		return base
	}
	base.Status = statusPass
	return base
}

func runHTTPCheck(ctx context.Context, client *http.Client, id, baseURL, path string) CheckResult {
	result := CheckResult{
		ID:       id,
		Category: "live",
		Required: true,
	}
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+path, nil)
	if err != nil {
		result.Status = statusFail
		result.Detail = err.Error()
		result.DurationMS = time.Since(start).Milliseconds()
		return result
	}
	resp, err := client.Do(req)
	result.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		result.Status = statusFail
		result.Detail = err.Error()
		return result
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		result.Status = statusFail
		result.Detail = fmt.Sprintf("status=%d", resp.StatusCode)
		return result
	}
	result.Status = statusPass
	result.Detail = "status=200"
	return result
}

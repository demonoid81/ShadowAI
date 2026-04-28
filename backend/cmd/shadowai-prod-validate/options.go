package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"
)

type repeatedFlag []string

func (v *repeatedFlag) String() string {
	return strings.Join(*v, ",")
}

func (v *repeatedFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("empty value")
	}
	*v = append(*v, s)
	return nil
}

type options struct {
	Release           string
	Namespace         string
	Chart             string
	Values            []string
	ExistingSecret    string
	ImageTag          string
	Live              bool
	BaseURL           string
	EvidenceBundle    string
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	ForcePathStyle    bool
	RequireObjectLock bool
	MinRetentionDays  int
	Format            string
	Output            string
	Timeout           time.Duration
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("shadowai-prod-validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var values repeatedFlag
	opts := options{}
	timeoutSeconds := 120

	fs.StringVar(&opts.Release, "release", "shadowai", "Helm release / Kubernetes deployment name")
	fs.StringVar(&opts.Namespace, "namespace", "shadowai", "Kubernetes namespace")
	fs.StringVar(&opts.Chart, "chart", "", "Helm chart path; enables helm template validation")
	fs.Var(&values, "values", "Helm values file; repeatable")
	fs.StringVar(&opts.ExistingSecret, "existing-secret", "shadowai-secrets", "Helm existingSecret value used for render validation")
	fs.StringVar(&opts.ImageTag, "image-tag", "prod-validate", "Helm image.tag value used for render validation")
	fs.BoolVar(&opts.Live, "live", false, "Run live kubectl rollout validation")
	fs.StringVar(&opts.BaseURL, "base-url", "", "Application base URL; enables /api/health and /api/ready checks")
	fs.StringVar(&opts.EvidenceBundle, "evidence-bundle", "", "Evidence bundle dir/zip; enables audit-verify --bundle")
	fs.StringVar(&opts.Bucket, "bucket", "", "Evidence S3 bucket; enables audit-evidence-report")
	fs.StringVar(&opts.Prefix, "prefix", "shadowai/evidence", "Evidence S3 prefix")
	fs.StringVar(&opts.Region, "region", "us-east-1", "Evidence S3 region")
	fs.StringVar(&opts.Endpoint, "endpoint", "", "Custom S3 endpoint")
	fs.BoolVar(&opts.ForcePathStyle, "force-path-style", false, "Use path-style S3 addressing")
	fs.BoolVar(&opts.RequireObjectLock, "require-object-lock", false, "Require Object Lock in audit-evidence-report")
	fs.IntVar(&opts.MinRetentionDays, "min-retention-days", 90, "Minimum retention days for audit-evidence-report")
	fs.StringVar(&opts.Format, "format", "table", `Output format: "table" or "json"`)
	fs.StringVar(&opts.Output, "output", "", "Write report to file instead of stdout")
	fs.IntVar(&timeoutSeconds, "timeout", 120, "Overall timeout in seconds")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	opts.Values = values
	if opts.Format != "table" && opts.Format != "json" {
		return options{}, fmt.Errorf("--format must be table or json, got %q", opts.Format)
	}
	if timeoutSeconds <= 0 {
		return options{}, fmt.Errorf("--timeout must be > 0")
	}
	if opts.MinRetentionDays < 0 {
		return options{}, fmt.Errorf("--min-retention-days must be >= 0")
	}
	opts.Timeout = time.Duration(timeoutSeconds) * time.Second
	if opts.Chart == "" && !opts.Live && opts.BaseURL == "" && opts.EvidenceBundle == "" && opts.Bucket == "" {
		return options{}, fmt.Errorf("at least one validation check must be configured")
	}
	if opts.BaseURL != "" {
		if _, err := url.ParseRequestURI(opts.BaseURL); err != nil {
			return options{}, fmt.Errorf("--base-url is invalid: %w", err)
		}
	}
	return opts, nil
}

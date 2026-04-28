package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type CheckResult struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Required   bool   `json:"required"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type Summary struct {
	Passed           int `json:"passed"`
	Failed           int `json:"failed"`
	Skipped          int `json:"skipped"`
	RequiredFailures int `json:"required_failures"`
}

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Overall       string        `json:"overall"`
	Summary       Summary       `json:"summary"`
	Checks        []CheckResult `json:"checks"`
}

func summarize(checks []CheckResult) Summary {
	var s Summary
	for _, c := range checks {
		switch c.Status {
		case statusPass:
			s.Passed++
		case statusFail:
			s.Failed++
			if c.Required {
				s.RequiredFailures++
			}
		case statusSkip:
			s.Skipped++
		}
	}
	return s
}

func writeReport(opts options, stdout io.Writer, report Report) error {
	out := stdout
	var f *os.File
	if opts.Output != "" {
		var err error
		f, err = os.Create(opts.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	switch opts.Format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		return enc.Encode(report)
	case "table":
		printTable(out, report)
		return nil
	default:
		return fmt.Errorf("unsupported format %q", opts.Format)
	}
}

func printTable(w io.Writer, report Report) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	fmt.Fprintf(tw, "GENERATED\t%s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "OVERALL\t%s\n", report.Overall)
	fmt.Fprintf(tw, "SUMMARY\tpass=%d fail=%d skip=%d required_failures=%d\n\n",
		report.Summary.Passed, report.Summary.Failed, report.Summary.Skipped, report.Summary.RequiredFailures)
	fmt.Fprintln(tw, "ID\tCATEGORY\tREQUIRED\tSTATUS\tDETAIL")
	for _, check := range report.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\n",
			check.ID, check.Category, check.Required, check.Status, check.Detail)
	}
}

func cleanDetail(output []byte) string {
	detail := strings.TrimSpace(string(bytes.ReplaceAll(output, []byte{'\n'}, []byte{' '})))
	if len(detail) > 500 {
		return detail[:500] + "...(truncated)"
	}
	return detail
}

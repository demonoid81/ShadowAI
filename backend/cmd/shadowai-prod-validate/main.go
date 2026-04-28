package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	exitOK      = 0
	exitFailure = 1
	exitConfig  = 2

	statusPass = "pass"
	statusFail = "fail"
	statusSkip = "skip"
)

func main() {
	os.Exit(runWithDeps(os.Args[1:], os.Stdout, os.Stderr, execCommandRunner{}, http.DefaultClient))
}

func runWithDeps(args []string, stdout, stderr io.Writer, runner commandRunner, client *http.Client) int {
	opts, err := parseOptions(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return exitConfig
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	report := runValidation(ctx, opts, runner, client)
	if err := writeReport(opts, stdout, report); err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return exitConfig
	}
	if report.Summary.RequiredFailures > 0 {
		fmt.Fprintf(stderr, "production validation failed: %d required check(s) failed\n", report.Summary.RequiredFailures)
		return exitFailure
	}
	fmt.Fprintf(stderr, "production validation passed: %d passed, %d skipped\n", report.Summary.Passed, report.Summary.Skipped)
	return exitOK
}

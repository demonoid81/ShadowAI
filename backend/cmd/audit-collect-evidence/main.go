// cmd/audit-collect-evidence — SOC2.1: Quarterly compliance evidence package collector.
//
// Collects and packages control evidence artifacts for an audit period into a
// structured directory, zip archive, or JSON report suitable for external auditors.
//
// Usage:
//
//	audit-collect-evidence \
//	  --from 2026-01-01 \
//	  --to   2026-03-31 \
//	  --output ./evidence-Q1-2026 \
//	  [--format dir|zip|json] \
//	  [--controls-doc /path/to/soc2-iso-control-mapping.md] \
//	  [--bucket shadowai-compliance] \
//	  [--region us-east-1] [--endpoint ...] [--force-path-style] \
//	  [--allow-incomplete]
//
// Exit codes:
//
//	0 — all requested controls collected; package written
//	1 — one or more controls not_collected AND --allow-incomplete not set
//	2 — configuration or runtime error (bad flags, can't write output)
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

const (
	exitOK         = 0
	exitIncomplete = 1
	exitError      = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs2 := flag.NewFlagSet("audit-collect-evidence", flag.ContinueOnError)
	fs2.SetOutput(stderr)

	var (
		from        = fs2.String("from", "", "Period start date YYYY-MM-DD (required)")
		to          = fs2.String("to", "", "Period end date YYYY-MM-DD (required)")
		output      = fs2.String("output", "", "Output path: directory, zip file, or JSON file (required)")
		format      = fs2.String("format", "dir", `Output format: "dir" (default), "zip", or "json"`)
		controlsDoc = fs2.String("controls-doc", "",
			"Path to soc2-iso-control-mapping.md (default: auto-search relative to binary)")
		allowIncomplete = fs2.Bool("allow-incomplete", false, "Exit 0 even if some controls could not be collected")
		// S3 flags for retention report (optional).
		bucket         = fs2.String("bucket", "", "S3 bucket for retention report (optional)")
		region         = fs2.String("region", "us-east-1", "AWS region")
		endpoint       = fs2.String("endpoint", "", "Custom S3 endpoint (MinIO)")
		forcePathStyle = fs2.Bool("force-path-style", false, "S3 path-style addressing")
	)
	if err := fs2.Parse(args); err != nil {
		return exitError
	}

	cfgErr := func(f string, a ...any) int {
		fmt.Fprintf(stderr, "config error: "+f+"\n", a...)
		return exitError
	}

	if *from == "" || *to == "" {
		return cfgErr("--from and --to are required (YYYY-MM-DD)")
	}
	if _, err := time.Parse("2006-01-02", *from); err != nil {
		return cfgErr("--from: invalid date %q, use YYYY-MM-DD", *from)
	}
	if _, err := time.Parse("2006-01-02", *to); err != nil {
		return cfgErr("--to: invalid date %q, use YYYY-MM-DD", *to)
	}
	if *output == "" {
		return cfgErr("--output is required")
	}
	switch *format {
	case "dir", "zip", "json":
	default:
		return cfgErr("--format must be dir, zip, or json; got %q", *format)
	}

	// Create a temporary working directory.
	workDir, err := os.MkdirTemp("", "audit-evidence-*")
	if err != nil {
		fmt.Fprintf(stderr, "error creating work dir: %v\n", err)
		return exitError
	}
	defer os.RemoveAll(workDir)

	manifest := &PackageManifest{
		SchemaVersion: pkgSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Generator:     "audit-collect-evidence",
		BuildCommit:   buildCommit(),
		Period:        Period{From: *from, To: *to},
	}

	if err := os.MkdirAll(filepath.Join(workDir, "controls"), 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir controls: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(filepath.Join(workDir, "evidence"), 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir evidence: %v\n", err)
		return exitError
	}
	if err := os.MkdirAll(filepath.Join(workDir, "checklists"), 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir checklists: %v\n", err)
		return exitError
	}

	// ── 1. SOC2 control mapping snapshot ──────────────────────────────────
	docPath := resolveControlsDoc(*controlsDoc)
	if docPath != "" {
		data, err := os.ReadFile(docPath)
		if err == nil {
			_ = os.WriteFile(filepath.Join(workDir, "controls", "soc2-iso-control-mapping.md"), data, 0o644)
			manifest.addControl(ControlEntry{
				ID:          "soc2_control_mapping",
				Description: "SOC 2 / ISO 27001 control mapping snapshot",
				Status:      ControlCollected,
				File:        "controls/soc2-iso-control-mapping.md",
			})
		} else {
			manifest.addControl(ControlEntry{
				ID:          "soc2_control_mapping",
				Description: "SOC 2 / ISO 27001 control mapping snapshot",
				Status:      ControlNotCollected,
				Reason:      fmt.Sprintf("could not read %s: %v", docPath, err),
			})
		}
	} else {
		manifest.addControl(ControlEntry{
			ID:          "soc2_control_mapping",
			Description: "SOC 2 / ISO 27001 control mapping snapshot",
			Status:      ControlNotCollected,
			Reason:      "not found; pass --controls-doc /path/to/docs/compliance/soc2-iso-control-mapping.md",
		})
	}

	// ── 2. Evidence retention report (requires S3 + audit-evidence-report) ─
	if *bucket != "" {
		retFile := filepath.Join(workDir, "evidence", "retention-report.json")
		if err := collectRetentionReport(retFile, *from, *to, *bucket, *region, *endpoint, *forcePathStyle, stderr); err == nil {
			manifest.addControl(ControlEntry{
				ID:          "retention_posture",
				Description: "S3 Object Lock retention posture for evidence bundles in period",
				Status:      ControlCollected,
				File:        "evidence/retention-report.json",
			})
		} else {
			fmt.Fprintf(stderr, "warning: retention report: %v\n", err)
			manifest.addControl(ControlEntry{
				ID:                "retention_posture",
				Description:       "S3 Object Lock retention posture for evidence bundles in period",
				Status:            ControlNotCollected,
				LiveCheckRequired: true,
				Reason:            err.Error(),
			})
		}
	} else {
		manifest.addControl(ControlEntry{
			ID:                "retention_posture",
			Description:       "S3 Object Lock retention posture for evidence bundles in period",
			Status:            ControlNotCollected,
			LiveCheckRequired: true,
			Reason:            "--bucket not provided; run: audit-evidence-report --bucket <bucket> --after <from> --before <to> --require-lock --format json",
		})
	}

	// ── 3. Chain + anchor verification (requires DATABASE_URL + AUDIT_CHAIN_SECRET) ──
	if os.Getenv("DATABASE_URL") != "" && os.Getenv("AUDIT_CHAIN_SECRET") != "" {
		verFile := filepath.Join(workDir, "evidence", "chain-verify-summary.json")
		if err := collectChainVerify(verFile, stderr); err == nil {
			manifest.addControl(ControlEntry{
				ID:          "chain_verification",
				Description: "WORM HMAC chain and Merkle anchor integrity verification (restore-drill mode)",
				Status:      ControlCollected,
				File:        "evidence/chain-verify-summary.json",
			})
		} else {
			fmt.Fprintf(stderr, "warning: chain verify: %v\n", err)
			manifest.addControl(ControlEntry{
				ID:                "chain_verification",
				Description:       "WORM HMAC chain and Merkle anchor integrity verification",
				Status:            ControlNotCollected,
				LiveCheckRequired: true,
				Reason:            err.Error(),
			})
		}
	} else {
		manifest.addControl(ControlEntry{
			ID:                "chain_verification",
			Description:       "WORM HMAC chain and Merkle anchor integrity verification",
			Status:            ControlNotCollected,
			LiveCheckRequired: true,
			Reason:            "DATABASE_URL and/or AUDIT_CHAIN_SECRET not set; run: audit-verify --restore-drill --table all --verbose",
		})
	}

	// ── 3.5 Access review report (SOC2.3 — requires DATABASE_URL) ─────────
	if os.Getenv("DATABASE_URL") != "" {
		arFile := filepath.Join(workDir, "evidence", "access-review.json")
		if err := collectAccessReview(arFile, *from, *to, stderr); err == nil {
			manifest.addControl(ControlEntry{
				ID:          "access_review",
				Description: "Period-scoped access review: users, privileged roles, MFA, IdP linkage, break-glass (SOC2.3)",
				Status:      ControlCollected,
				File:        "evidence/access-review.json",
			})
		} else {
			fmt.Fprintf(stderr, "warning: access review: %v\n", err)
			manifest.addControl(ControlEntry{
				ID:                "access_review",
				Description:       "Period-scoped access review: users, privileged roles, MFA, IdP linkage, break-glass",
				Status:            ControlNotCollected,
				LiveCheckRequired: true,
				Reason:            fmt.Sprintf("audit-access-review failed: %v", err),
			})
		}
	} else {
		manifest.addControl(ControlEntry{
			ID:                "access_review",
			Description:       "Period-scoped access review: users, privileged roles, MFA, IdP linkage, break-glass",
			Status:            ControlNotCollected,
			LiveCheckRequired: true,
			Reason:            "DATABASE_URL not set; run: audit-access-review --global --from <from> --to <to> --format json",
		})
	}

	// ── 4. Checklist templates (always generated) ──────────────────────────
	checklists := map[string]string{
		"access-review-checklist.md":          accessReviewChecklist(*from, *to),
		"incident-alert-review-checklist.md":  incidentAlertReviewChecklist(*from, *to),
		"ci-release-checklist.md":             ciReleaseChecklist(*from, *to),
	}
	for name, content := range checklists {
		_ = os.WriteFile(filepath.Join(workDir, "checklists", name), []byte(content), 0o644)
		manifest.addControl(ControlEntry{
			ID:          strings.TrimSuffix(strings.ReplaceAll(name, "-", "_"), ".md"),
			Description: "Operator checklist template — must be completed and signed off by operator",
			Status:      ControlTemplate,
			File:        "checklists/" + name,
		})
	}

	// ── 5. not_collected summary ────────────────────────────────────────────
	var notCollectedEntries []ControlEntry
	for _, c := range manifest.Controls {
		if c.Status == ControlNotCollected {
			notCollectedEntries = append(notCollectedEntries, c)
		}
	}
	if len(notCollectedEntries) > 0 {
		data, _ := json.MarshalIndent(notCollectedEntries, "", "  ")
		_ = os.WriteFile(filepath.Join(workDir, "evidence", "not_collected.json"), data, 0o644)
	}

	// ── 6. Manifest: hash all files, write final manifest ──────────────────
	hashes, err := computeFileSHA256(workDir)
	if err != nil {
		fmt.Fprintf(stderr, "error computing hashes: %v\n", err)
		return exitError
	}
	manifest.FileSHA256 = hashes
	if err := writeManifest(workDir, manifest); err != nil {
		fmt.Fprintf(stderr, "error writing manifest: %v\n", err)
		return exitError
	}

	// ── 7. Package output ──────────────────────────────────────────────────
	switch *format {
	case "dir":
		if err := copyDir(workDir, *output); err != nil {
			fmt.Fprintf(stderr, "error writing output dir: %v\n", err)
			return exitError
		}
	case "zip":
		if err := zipDir(workDir, *output); err != nil {
			fmt.Fprintf(stderr, "error writing zip: %v\n", err)
			return exitError
		}
	case "json":
		if err := writeJSONPackage(workDir, manifest, *output); err != nil {
			fmt.Fprintf(stderr, "error writing json package: %v\n", err)
			return exitError
		}
	}

	notCollectedCount := len(notCollectedEntries)
	collected := len(manifest.Controls) - notCollectedCount
	fmt.Fprintf(stdout, "[audit-collect-evidence] %d/%d controls collected; period %s → %s; output %s\n",
		collected, len(manifest.Controls), *from, *to, *output)

	if notCollectedCount > 0 {
		fmt.Fprintf(stderr, "[audit-collect-evidence] %d control(s) not_collected — see evidence/not_collected.json\n", notCollectedCount)
		if !*allowIncomplete {
			return exitIncomplete
		}
	}
	return exitOK
}

// resolveControlsDoc returns the path to the SOC2 control mapping doc.
// Searches: explicit flag → well-known relative paths from executable location.
func resolveControlsDoc(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	// Try common locations relative to the executable.
	exe, _ := os.Executable()
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "..", "..", "docs", "compliance", "soc2-iso-control-mapping.md"),
		"docs/compliance/soc2-iso-control-mapping.md",
		"../../docs/compliance/soc2-iso-control-mapping.md",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// collectRetentionReport invokes audit-evidence-report and saves its JSON output.
func collectRetentionReport(outFile, from, to, bucket, region, endpoint string, forcePathStyle bool, stderr io.Writer) error {
	bin, err := exec.LookPath("audit-evidence-report")
	if err != nil {
		return fmt.Errorf("audit-evidence-report not found in PATH; install via make build-cli")
	}
	cmdArgs := []string{
		"--bucket", bucket, "--region", region,
		"--after", from, "--before", to,
		"--require-lock", "--format", "json", "--timeout", "120",
	}
	if endpoint != "" {
		cmdArgs = append(cmdArgs, "--endpoint", endpoint)
	}
	if forcePathStyle {
		cmdArgs = append(cmdArgs, "--force-path-style")
	}
	cmd := exec.Command(bin, cmdArgs...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.Env = &outBuf, &errBuf, os.Environ()

	runErr := cmd.Run()
	if errBuf.Len() > 0 {
		fmt.Fprintf(stderr, "  (audit-evidence-report) %s\n", strings.TrimSpace(errBuf.String()))
	}
	// Exit 1 = violations found; the report JSON is still valid — save it.
	if runErr != nil && (cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 1) {
		return runErr
	}
	return os.WriteFile(outFile, outBuf.Bytes(), 0o644)
}

// collectChainVerify invokes audit-verify --restore-drill and saves a summary JSON.
func collectChainVerify(outFile string, stderr io.Writer) error {
	bin, err := exec.LookPath("audit-verify")
	if err != nil {
		return fmt.Errorf("audit-verify not found in PATH; install via make build-cli")
	}
	cmd := exec.Command(bin, "--restore-drill", "--table", "all", "--verbose")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.Env = &outBuf, &errBuf, os.Environ()

	runErr := cmd.Run()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	if exitCode != 0 {
		fmt.Fprintf(stderr, "  (audit-verify) exit %d — failures recorded in summary\n", exitCode)
	}

	summary := map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"exit_code":    exitCode,
		"passed":       exitCode == 0,
		"stdout":       outBuf.String(),
		"stderr":       errBuf.String(),
	}
	data, _ := json.MarshalIndent(summary, "", "  ")
	if writeErr := os.WriteFile(outFile, data, 0o644); writeErr != nil {
		return writeErr
	}
	// exit 0 or exit 1 (verify failure) are both "collected" — operator sees the result.
	// Only a config/runtime error (exit 2 or exec failure) is a collection failure.
	if runErr != nil && exitCode == 2 {
		return fmt.Errorf("audit-verify config error (exit 2): %s", errBuf.String())
	}
	return nil
}

// buildCommit reads the VCS commit from runtime build info.
func buildCommit() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return ""
}

// sha256HexBytes returns the hex SHA256 of data.
func sha256HexBytes(data []byte) string {
	h := sha256.Sum256(data)
	const hexChars = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hexChars[b>>4]
		out[i*2+1] = hexChars[b&0xf]
	}
	return string(out)
}

// copyDir copies the contents of src to dst directory.
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		dstPath := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, 0o644)
	})
}

// zipDir creates a zip archive of src at dstZip.
func zipDir(src, dstZip string) error {
	zf, err := os.Create(dstZip)
	if err != nil {
		return err
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	defer zw.Close()
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
}

// jsonPackage is the single-file JSON output format.
type jsonPackage struct {
	Manifest *PackageManifest  `json:"manifest"`
	Files    map[string]string `json:"files"` // relative path → content
}

// writeJSONPackage embeds all files in a single JSON document.
func writeJSONPackage(workDir string, m *PackageManifest, outFile string) error {
	files := make(map[string]string)
	_ = filepath.WalkDir(workDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(workDir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = string(data)
		return nil
	})
	data, err := json.MarshalIndent(jsonPackage{Manifest: m, Files: files}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outFile, data, 0o644)
}

// collectAccessReview invokes audit-access-review and saves its JSON output.
// Runs in global mode to capture cross-org view; period-scoped for break-glass events.
func collectAccessReview(outFile, from, to string, stderr io.Writer) error {
	bin, err := exec.LookPath("audit-access-review")
	if err != nil {
		return fmt.Errorf("audit-access-review not found in PATH; install via make build-cli")
	}
	cmd := exec.Command(bin,
		"--global",
		"--from", from, "--to", to,
		"--format", "json",
	)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr, cmd.Env = &outBuf, &errBuf, os.Environ()

	runErr := cmd.Run()
	if errBuf.Len() > 0 {
		fmt.Fprintf(stderr, "  (audit-access-review) %s\n", strings.TrimSpace(errBuf.String()))
	}
	// Exit 1 = findings (still a valid JSON report — save it).
	if runErr != nil {
		if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() == 2 {
			return runErr // config/runtime error
		}
		// exit 1 = findings: report is valid JSON, save it
	}
	return os.WriteFile(outFile, outBuf.Bytes(), 0o644)
}

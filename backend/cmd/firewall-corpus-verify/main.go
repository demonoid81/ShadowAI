// Command firewall-corpus-verify validates a semantic_v2 corpus manifest before
// operators enable FIREWALL_SA_V2_ENABLED in shadow or enforce mode.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/shadowai/backend/internal/embedding"
)

const (
	exitOK         = 0
	exitValidation = 1
	exitConfig     = 2
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	*m = append(*m, strings.TrimSpace(v))
	return nil
}

type categoryReport struct {
	Name  string `json:"name"`
	Items int    `json:"items"`
}

type verifyReport struct {
	OK          bool             `json:"ok"`
	Corpus      string           `json:"corpus"`
	Version     int              `json:"version"`
	Provider    string           `json:"provider"`
	Model       string           `json:"model"`
	Dimension   int              `json:"dimension"`
	Normalized  bool             `json:"normalized"`
	Items       int              `json:"items"`
	Categories  []categoryReport `json:"categories"`
	GeneratedAt string           `json:"generated_at,omitempty"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("firewall-corpus-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var requiredCategories multiFlag
	corpusPath := fs.String("corpus", "", "semantic_v2 corpus manifest path (required)")
	expectProvider := fs.String("expect-provider", "", "expected corpus provider")
	expectModel := fs.String("expect-model", "", "expected corpus model")
	expectDimension := fs.Int("expect-dimension", 0, "expected vector dimension")
	minItems := fs.Int("min-items", 1, "minimum accepted corpus items")
	format := fs.String("format", "table", "output format: table|json")
	fs.Var(&requiredCategories, "require-category", "category that must exist in corpus (repeatable)")

	if err := fs.Parse(args); err != nil {
		return exitConfig
	}
	if *corpusPath == "" {
		fmt.Fprintln(stderr, "error: --corpus is required")
		fs.Usage()
		return exitConfig
	}
	if *minItems < 1 {
		fmt.Fprintln(stderr, "error: --min-items must be >= 1")
		return exitConfig
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintln(stderr, "error: --format must be table or json")
		return exitConfig
	}

	corpus, err := embedding.LoadCorpus(*corpusPath)
	if err != nil {
		fmt.Fprintf(stderr, "validation failed: %v\n", err)
		return exitValidation
	}

	report := buildReport(*corpusPath, corpus)
	if err := validateReport(report, *expectProvider, *expectModel, *expectDimension, *minItems, requiredCategories); err != nil {
		fmt.Fprintf(stderr, "validation failed: %v\n", err)
		return exitValidation
	}

	if *format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printTable(stdout, report)
	}
	return exitOK
}

func buildReport(path string, corpus *embedding.Corpus) verifyReport {
	counts := map[string]int{}
	for _, item := range corpus.Items {
		counts[item.Category]++
	}
	categories := make([]categoryReport, 0, len(counts))
	for name, n := range counts {
		categories = append(categories, categoryReport{Name: name, Items: n})
	}
	sort.Slice(categories, func(i, j int) bool { return categories[i].Name < categories[j].Name })

	generatedAt := ""
	if !corpus.GeneratedAt.IsZero() {
		generatedAt = corpus.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	return verifyReport{
		OK:          true,
		Corpus:      path,
		Version:     corpus.Version,
		Provider:    corpus.Provider,
		Model:       corpus.Model,
		Dimension:   corpus.Dimension,
		Normalized:  corpus.Normalized,
		Items:       len(corpus.Items),
		Categories:  categories,
		GeneratedAt: generatedAt,
	}
}

func validateReport(
	report verifyReport,
	expectProvider string,
	expectModel string,
	expectDimension int,
	minItems int,
	requiredCategories []string,
) error {
	if expectProvider != "" && report.Provider != expectProvider {
		return fmt.Errorf("provider mismatch: got %q, expected %q", report.Provider, expectProvider)
	}
	if expectModel != "" && report.Model != expectModel {
		return fmt.Errorf("model mismatch: got %q, expected %q", report.Model, expectModel)
	}
	if expectDimension > 0 && report.Dimension != expectDimension {
		return fmt.Errorf("dimension mismatch: got %d, expected %d", report.Dimension, expectDimension)
	}
	if report.Items < minItems {
		return fmt.Errorf("items count %d below required minimum %d", report.Items, minItems)
	}

	seen := make(map[string]struct{}, len(report.Categories))
	for _, cat := range report.Categories {
		seen[cat.Name] = struct{}{}
	}
	for _, required := range requiredCategories {
		if _, ok := seen[required]; !ok {
			return fmt.Errorf("required category %q missing", required)
		}
	}
	return nil
}

func printTable(w io.Writer, report verifyReport) {
	fmt.Fprintf(w, "semantic_v2 corpus OK\n")
	fmt.Fprintf(w, "path:       %s\n", report.Corpus)
	fmt.Fprintf(w, "provider:   %s\n", report.Provider)
	fmt.Fprintf(w, "model:      %s\n", report.Model)
	fmt.Fprintf(w, "dimension:  %d\n", report.Dimension)
	fmt.Fprintf(w, "items:      %d\n", report.Items)
	fmt.Fprintf(w, "normalized: %t\n", report.Normalized)
	if report.GeneratedAt != "" {
		fmt.Fprintf(w, "generated:  %s\n", report.GeneratedAt)
	}
	fmt.Fprintln(w, "categories:")
	for _, cat := range report.Categories {
		fmt.Fprintf(w, "  - %s: %d\n", cat.Name, cat.Items)
	}
}

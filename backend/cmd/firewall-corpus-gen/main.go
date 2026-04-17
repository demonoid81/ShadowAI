// Command firewall-corpus-gen генерирует manifest для semantic_v2
// corpus: читает patterns/*.txt (по файлу на категорию, одна строка —
// один pattern), вычисляет embedding через указанный provider и пишет
// готовый JSON в --output.
//
// Usage:
//
//	firewall-corpus-gen \
//	  --patterns ./firewall_corpus/patterns \
//	  --output   ./firewall_corpus/semantic_v2.json \
//	  --provider ollama --endpoint http://localhost:11434 \
//	  --model nomic-embed-text --dimension 768
//
// Генерация запускается оператором при первоначальной настройке
// или при расширении corpus. CI обычно этот шаг не делает (результат
// — committed artifact, см. ../../firewall_corpus/README.md).
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shadowai/backend/internal/embedding"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run — чистая CLI-логика (testable). Создаёт client, делегирует в Generate.
func run(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("firewall-corpus-gen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		patterns  = fs.String("patterns", "", "input directory with <category>.txt files (required)")
		output    = fs.String("output", "", "output corpus manifest path (required)")
		provider  = fs.String("provider", "ollama", "embedding provider: ollama|openai")
		endpoint  = fs.String("endpoint", "http://localhost:11434", "provider endpoint")
		model     = fs.String("model", "nomic-embed-text", "embedding model")
		apiKey    = fs.String("api-key", "", "API key (openai only)")
		dimension = fs.Int("dimension", 768, "expected vector dimension")
		timeout   = fs.Duration("timeout", 30*time.Second, "per-pattern embedding timeout")
	)
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *patterns == "" || *output == "" {
		fmt.Fprintln(stderr, "error: --patterns and --output are required")
		fs.Usage()
		return 1
	}

	client, err := embedding.NewClient(embedding.Config{
		Provider: *provider, Endpoint: *endpoint, Model: *model,
		APIKey: *apiKey, Timeout: *timeout, Dimension: *dimension,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	if err := Generate(context.Background(), *patterns, *output, client); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "corpus written: %s\n", *output)
	return 0
}

// Generate читает patterns-dir, embed'ит каждую строку и пишет manifest.
//
// Контракт:
//   - patterns/*.txt: category = filename без расширения;
//   - одна непустая строка в файле = один pattern;
//   - id auto-генерируется как <category>-<3-значный индекс>;
//   - порядок deterministic: категории сортируются по имени, pattern'ы
//     внутри — по line-number;
//   - при ошибке embedding любого pattern'а abort без частичного output.
func Generate(ctx context.Context, patternsDir, outPath string, emb embedding.Embedder) error {
	entries, err := os.ReadDir(patternsDir)
	if err != nil {
		return fmt.Errorf("read patterns dir: %w", err)
	}

	type patternRef struct {
		category string
		line     int
		text     string
	}

	var refs []patternRef
	var categoryNames []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".txt") {
			continue
		}
		cat := strings.TrimSuffix(name, ".txt")
		categoryNames = append(categoryNames, cat)
	}
	sort.Strings(categoryNames) // deterministic order

	for _, cat := range categoryNames {
		path := filepath.Join(patternsDir, cat+".txt")
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1<<20)
		lineNo := 0
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			lineNo++
			refs = append(refs, patternRef{category: cat, line: lineNo, text: line})
		}
		_ = f.Close()
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
	}

	if len(refs) == 0 {
		return fmt.Errorf("no patterns found in %s (expected <category>.txt files with content)", patternsDir)
	}

	items := make([]embedding.CorpusItem, 0, len(refs))
	for _, r := range refs {
		e, err := emb.Embed(ctx, r.text)
		if err != nil {
			return fmt.Errorf("embed %s line %d: %w", r.category, r.line, err)
		}
		items = append(items, embedding.CorpusItem{
			ID:        fmt.Sprintf("%s-%03d", r.category, r.line),
			Category:  r.category,
			Text:      r.text,
			Embedding: e.Vector,
		})
	}

	manifest := embedding.Corpus{
		Version:     1,
		Provider:    emb.Provider(),
		Model:       emb.Model(),
		Dimension:   emb.Dimension(),
		Normalized:  true, // client уже L2-нормализует
		GeneratedAt: time.Now().UTC(),
		Items:       items,
	}

	// Пишем во временный файл + rename: если что-то упадёт в json.Encode,
	// output-файл не будет частично записан.
	tmp := outPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(manifest); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shadowai/backend/internal/embedding"
)

type fixedEmbedder struct {
	embed func(string) ([]float64, error)
	provider, model string
	dimension int
}

func (f *fixedEmbedder) Embed(_ context.Context, text string) (embedding.Embedding, error) {
	v, err := f.embed(text)
	if err != nil {
		return embedding.Embedding{}, err
	}
	return embedding.Embedding{Vector: v}, nil
}
func (f *fixedEmbedder) Provider() string  { return f.provider }
func (f *fixedEmbedder) Model() string     { return f.model }
func (f *fixedEmbedder) Dimension() int    { return f.dimension }

// writePatterns создаёт структуру patterns/<category>.txt с заданным
// контентом. Возвращает корневой путь.
func writePatterns(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestGenerate_HappyPath — две категории (по файлу), embedder возвращает
// deterministic normalized vectors → manifest валиден, items в правильном
// порядке (по имени файла, затем по line-number).
func TestGenerate_HappyPath(t *testing.T) {
	root := writePatterns(t, map[string]string{
		"prompt_injection.txt": "ignore previous\nforget everything\n",
		"jailbreak.txt":        "dan mode\n",
	})
	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "corpus.json")

	// Embedder возвращает "unit vector в направлении hash(text)",
	// но для теста хватит фиксированного [1, 0].
	emb := &fixedEmbedder{
		embed: func(_ string) ([]float64, error) { return []float64{1, 0}, nil },
		provider: "ollama", model: "nomic-embed-text", dimension: 2,
	}

	if err := Generate(context.Background(), root, outPath, emb); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var c embedding.Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}

	if c.Provider != "ollama" || c.Model != "nomic-embed-text" || c.Dimension != 2 {
		t.Errorf("metadata = %+v", c)
	}
	if !c.Normalized {
		t.Error("normalized=false, want true (embedder уже возвращает unit-length)")
	}
	if len(c.Items) != 3 {
		t.Errorf("items = %d, want 3", len(c.Items))
	}
	// Проверим устойчивый порядок: jailbreak < prompt_injection,
	// затем по line-number внутри файла.
	wantIDs := []string{"jailbreak-001", "prompt_injection-001", "prompt_injection-002"}
	for i, want := range wantIDs {
		if c.Items[i].ID != want {
			t.Errorf("items[%d].ID = %q, want %q", i, c.Items[i].ID, want)
		}
	}
}

// TestGenerate_Validates_LoadableByLoadCorpus — сгенерированный файл
// должен без проблем загружаться LoadCorpus (тот же самый format
// contract). Это основной "не разъехались" regression.
func TestGenerate_Validates_LoadableByLoadCorpus(t *testing.T) {
	root := writePatterns(t, map[string]string{
		"prompt_injection.txt": "ignore\n",
	})
	outPath := filepath.Join(t.TempDir(), "c.json")
	emb := &fixedEmbedder{
		embed: func(_ string) ([]float64, error) { return []float64{1, 0}, nil },
		provider: "ollama", model: "m", dimension: 2,
	}

	if err := Generate(context.Background(), root, outPath, emb); err != nil {
		t.Fatal(err)
	}

	loaded, err := embedding.LoadCorpus(outPath)
	if err != nil {
		t.Fatalf("LoadCorpus после Generate: %v", err)
	}
	if loaded.Dimension != 2 || len(loaded.Items) != 1 {
		t.Errorf("loaded = %+v", loaded)
	}
}

// TestGenerate_AbortsOnEmbedError — если provider вернул error на
// любой pattern, Generate НЕ пишет частично-полный corpus (лучше
// отсутствующий файл, чем corrupt).
func TestGenerate_AbortsOnEmbedError(t *testing.T) {
	root := writePatterns(t, map[string]string{
		"prompt_injection.txt": "ok pattern\nfail pattern\n",
	})
	outPath := filepath.Join(t.TempDir(), "c.json")
	emb := &fixedEmbedder{
		embed: func(text string) ([]float64, error) {
			if text == "fail pattern" {
				return nil, errors.New("upstream 503")
			}
			return []float64{1, 0}, nil
		},
		provider: "ollama", model: "m", dimension: 2,
	}

	err := Generate(context.Background(), root, outPath, emb)
	if err == nil {
		t.Fatal("want error propagation from embedder")
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Error("output file не должен быть создан при ошибке embed")
	}
}

// TestGenerate_SkipsBlankLines — blank lines в patterns игнорируются.
func TestGenerate_SkipsBlankLines(t *testing.T) {
	root := writePatterns(t, map[string]string{
		"prompt_injection.txt": "line1\n\n  \nline2\n",
	})
	outPath := filepath.Join(t.TempDir(), "c.json")
	emb := &fixedEmbedder{
		embed: func(_ string) ([]float64, error) { return []float64{1, 0}, nil },
		provider: "ollama", model: "m", dimension: 2,
	}

	if err := Generate(context.Background(), root, outPath, emb); err != nil {
		t.Fatal(err)
	}

	loaded, _ := embedding.LoadCorpus(outPath)
	if len(loaded.Items) != 2 {
		t.Errorf("len = %d, want 2 (blank lines skipped)", len(loaded.Items))
	}
}

// TestGenerate_ReproducibleWithSourceDateEpoch — PR-6.0.1: два прогона
// с одинаковым SOURCE_DATE_EPOCH дают byte-identical output. Это
// позволит в будущем committed'ить production corpus без шумных
// timestamp-diff'ов, а также упрощает reproducible-builds pipelines
// (Debian / NixOS / Go release machinery).
func TestGenerate_ReproducibleWithSourceDateEpoch(t *testing.T) {
	root := writePatterns(t, map[string]string{
		"prompt_injection.txt": "ignore previous\nforget everything\n",
		"jailbreak.txt":        "dan mode\n",
	})
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

	emb := &fixedEmbedder{
		embed:    func(_ string) ([]float64, error) { return []float64{1, 0}, nil },
		provider: "ollama", model: "m", dimension: 2,
	}

	out1 := filepath.Join(t.TempDir(), "c1.json")
	if err := Generate(context.Background(), root, out1, emb); err != nil {
		t.Fatal(err)
	}
	// Отдельный tempdir для второго запуска — убеждает, что путь не
	// влияет на содержимое.
	out2 := filepath.Join(t.TempDir(), "c2.json")
	if err := Generate(context.Background(), root, out2, emb); err != nil {
		t.Fatal(err)
	}

	b1, err := os.ReadFile(out1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(out2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEqual(b1, b2) {
		t.Errorf("output не reproducible при фиксированном SOURCE_DATE_EPOCH:\n"+
			"run 1 (%d bytes):\n%s\n---\nrun 2 (%d bytes):\n%s",
			len(b1), string(b1), len(b2), string(b2))
	}

	// GeneratedAt в manifest должен отражать SOURCE_DATE_EPOCH
	// (не time.Now()), иначе override декоративный.
	var c embedding.Corpus
	if err := json.Unmarshal(b1, &c); err != nil {
		t.Fatal(err)
	}
	if c.GeneratedAt.Unix() != 1700000000 {
		t.Errorf("GeneratedAt.Unix() = %d, want 1700000000 (SOURCE_DATE_EPOCH)",
			c.GeneratedAt.Unix())
	}
}

// TestGenerate_InvalidSourceDateEpoch_FallsBackToNow — мусорное
// значение в SOURCE_DATE_EPOCH не должно ломать Generate; fallback
// на time.Now(). Misconfig в CI — дело оператора, а не причина
// отказать в генерации.
func TestGenerate_InvalidSourceDateEpoch_FallsBackToNow(t *testing.T) {
	root := writePatterns(t, map[string]string{
		"prompt_injection.txt": "x\n",
	})
	t.Setenv("SOURCE_DATE_EPOCH", "not-a-number")

	emb := &fixedEmbedder{
		embed:    func(_ string) ([]float64, error) { return []float64{1, 0}, nil },
		provider: "ollama", model: "m", dimension: 2,
	}
	out := filepath.Join(t.TempDir(), "c.json")
	if err := Generate(context.Background(), root, out, emb); err != nil {
		t.Fatal(err)
	}

	var c embedding.Corpus
	data, _ := os.ReadFile(out)
	_ = json.Unmarshal(data, &c)
	if c.GeneratedAt.IsZero() {
		t.Error("GeneratedAt пуст — invalid SOURCE_DATE_EPOCH должен был fallback'нуться на time.Now()")
	}
}

// bytesEqual — локальный helper чтобы не тянуть bytes package в test.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestGenerate_RejectsEmptyPatterns — папка без .txt файлов → error.
// Пустой corpus не имеет смысла (MaxSim на нём бессмысленен).
func TestGenerate_RejectsEmptyPatterns(t *testing.T) {
	root := t.TempDir() // пусто
	outPath := filepath.Join(t.TempDir(), "c.json")
	emb := &fixedEmbedder{
		embed: func(_ string) ([]float64, error) { return []float64{1, 0}, nil },
		provider: "ollama", model: "m", dimension: 2,
	}
	err := Generate(context.Background(), root, outPath, emb)
	if err == nil {
		t.Fatal("want error on empty patterns dir")
	}
}

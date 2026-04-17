package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockOllamaServer возвращает httptest.Server, который имитирует
// Ollama `/api/embeddings`:
//   - если prompt содержит любое из "threat words" (ignore/dan/pretend)
//     → vector [1.0, 0.0] (совпадает с corpus item-ом);
//   - иначе → [0.0, 1.0] (orthogonal, sim=0 → Allow).
// Это даёт deterministic P=1.0/R=1.0 на committed datasets.
func mockOllamaServer(t *testing.T) *httptest.Server {
	t.Helper()
	threatWords := []string{"ignore", "dan", "pretend", "disregard", "forget", "jailbreak", "bypass", "roleplay", "act as"}
	threatRU := []string{"игнорируй", "забудь", "притворись", "отмени"}
	threatWords = append(threatWords, threatRU...)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		lower := strings.ToLower(body.Prompt)
		vec := []float64{0.0, 1.0} // non-threat default
		for _, w := range threatWords {
			if strings.Contains(lower, w) {
				vec = []float64{1.0, 0.0}
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"embedding": vec})
	}))
}

// writeCorpus создаёт manifest на дисковом файле, подходящий mock'у:
// один item per category со embedding [1,0] (совпадает с "threat" prompt).
func writeCorpus(t *testing.T, dir, provider, model string) string {
	t.Helper()
	manifest := map[string]any{
		"version":     1,
		"provider":    provider,
		"model":       model,
		"dimension":   2,
		"normalized":  true,
		"generated_at": "2026-04-17T00:00:00Z",
		"items": []map[string]any{
			{"id": "prompt_injection-001", "category": "prompt_injection",
				"text": "ignore previous", "embedding": []float64{1.0, 0.0}},
			{"id": "jailbreak-001", "category": "jailbreak",
				"text": "dan mode", "embedding": []float64{1.0, 0.0}},
		},
	}
	b, _ := json.Marshal(manifest)
	p := filepath.Join(dir, "semantic_v2.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeBaselineWithSemanticV2 создаёт baseline.json с metadata lock
// для semantic_v2 + heuristic порогами (но не max_fpr, чтобы не
// дёргать heuristic-test'ы — они покрыты в main_test.go).
//
// Thresholds для semantic_v2 намеренно слабые: цель — верифицировать
// wiring (попал ли inspector в report, сработала ли metadata-проверка,
// сохраняется ли exit-код), а не качество mock-детектора. Жёсткие
// пороги (0.9/0.9/0.1) бессмысленны против keyword-mock'а, который не
// различает "act as <persona>" в positive и legitimate negative.
func writeBaselineWithSemanticV2(t *testing.T, dir string, provider, model string, corpusVersion int) string {
	t.Helper()
	manifest := map[string]any{
		"inspectors": map[string]any{
			"prompt_injection": map[string]any{
				"min_precision": 0.8, "min_recall": 0.2, "max_fpr": 0.05,
			},
			"jailbreak": map[string]any{
				"min_precision": 0.8, "min_recall": 0.01, "max_fpr": 0.05,
			},
			"semantic_v2": map[string]any{
				"provider": provider, "model": model, "corpus_version": corpusVersion,
				"min_precision": 0.5, "min_recall": 0.5, "max_fpr": 0.5,
			},
		},
	}
	b, _ := json.Marshal(manifest)
	p := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// configureEmbeddingEnv выставляет env для --with-embeddings прогона.
// t.Setenv авто-восстанавливает после теста.
func configureEmbeddingEnv(t *testing.T, endpoint, corpusPath, model string) {
	t.Helper()
	t.Setenv("FIREWALL_EMBEDDING_PROVIDER", "ollama")
	t.Setenv("FIREWALL_EMBEDDING_ENDPOINT", endpoint)
	t.Setenv("FIREWALL_EMBEDDING_MODEL", model)
	t.Setenv("FIREWALL_EMBEDDING_DIMENSION", "2")
	t.Setenv("FIREWALL_EMBEDDING_TIMEOUT", "2s")
	t.Setenv("FIREWALL_SA_V2_CORPUS_PATH", corpusPath)
	t.Setenv("FIREWALL_SA_V2_THRESHOLD", "0.75")
	t.Setenv("FIREWALL_SA_V2_BLOCK_THRESHOLD", "0.88")
}

// TestRun_WithEmbeddings_HappyPath — PR-6.1 core: с --with-embeddings
// бенчмарк выполняет semantic_v2 на mocked Ollama + temp corpus,
// получает precision/recall (ожидаемо близко к 1.0 на mock'е), exit 0.
func TestRun_WithEmbeddings_HappyPath(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	baselinePath := writeBaselineWithSemanticV2(t, tmp, "ollama", "nomic-embed-text", 1)

	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", code, stderr.String())
	}
	var report struct {
		Results []struct {
			Inspector string `json:"inspector"`
			Metrics   struct {
				Precision float64 `json:"precision"`
				Recall    float64 `json:"recall"`
			} `json:"metrics"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("parse json: %v\n%s", err, stdout.String())
	}

	found := false
	for _, r := range report.Results {
		if r.Inspector == "semantic_v2" {
			found = true
			// Смысл теста — wiring, а не метрики mock'а; убеждаемся лишь,
			// что inspector реально работал: detector выставил ненулевой
			// recall, не просто "все Allow по fail-open".
			if r.Metrics.Recall == 0 {
				t.Errorf("semantic_v2 отработал, но recall=0 — detector likely вырубился в fail-open; metrics = %+v", r.Metrics)
			}
		}
	}
	if !found {
		t.Errorf("semantic_v2 result отсутствует; results: %+v", report.Results)
	}
}

// TestRun_WithEmbeddings_MetadataMismatch — baseline.semantic_v2.provider
// зафиксирован как "openai", runtime поднимает ollama. Это misconfig, не
// regression → exit 1 с explicit diagnostic в stderr.
func TestRun_WithEmbeddings_MetadataMismatch(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	// Baseline зафиксирован под openai (mismatch).
	baselinePath := writeBaselineWithSemanticV2(t, tmp, "openai", "nomic-embed-text", 1)

	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit = %d, want 1 (metadata mismatch)\nstderr: %s", code, stderr.String())
	}
	errStr := stderr.String()
	if !strings.Contains(errStr, "metadata mismatch") {
		t.Errorf("stderr должен упомянуть 'metadata mismatch', got: %s", errStr)
	}
	if !strings.Contains(errStr, "openai") || !strings.Contains(errStr, "ollama") {
		t.Errorf("stderr должен показать и baseline (openai) и runtime (ollama): %s", errStr)
	}
}

// TestRun_WithoutFlag_SemanticV2Skipped — без --with-embeddings
// semantic_v2 НЕ запускается (даже если env и corpus настроены).
// Это защищает offline CI от случайной зависимости от embedding провайдера.
func TestRun_WithoutFlag_SemanticV2Skipped(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	baselinePath := writeBaselineWithSemanticV2(t, tmp, "ollama", "nomic-embed-text", 1)
	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--all", // без --with-embeddings
		"--data", testDataDir(t),
		"--baseline", baselinePath,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr: %s", code, stderr.String())
	}

	var report struct {
		Results []struct {
			Inspector string `json:"inspector"`
		} `json:"results"`
	}
	_ = json.Unmarshal(stdout.Bytes(), &report)
	for _, r := range report.Results {
		if r.Inspector == "semantic_v2" {
			t.Errorf("semantic_v2 появился в results без --with-embeddings (%+v)", report)
		}
	}
}

// TestRun_WithEmbeddingsAlone — `--with-embeddings` без --all/--inspector
// — валидный режим: прогоняем только semantic_v2.
func TestRun_WithEmbeddingsAlone(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	baselinePath := writeBaselineWithSemanticV2(t, tmp, "ollama", "nomic-embed-text", 1)
	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit = %d\nstderr: %s", code, stderr.String())
	}
	var report struct {
		Results []struct {
			Inspector string `json:"inspector"`
		} `json:"results"`
	}
	_ = json.Unmarshal(stdout.Bytes(), &report)
	if len(report.Results) != 1 || report.Results[0].Inspector != "semantic_v2" {
		t.Errorf("alone --with-embeddings: results = %+v, want только semantic_v2", report.Results)
	}
}

// writeBaselineWithoutSemanticV2 — baseline-файл с heuristic entries,
// но БЕЗ semantic_v2 (bootstrap-сценарий).
func writeBaselineWithoutSemanticV2(t *testing.T, dir string) string {
	t.Helper()
	manifest := map[string]any{
		"inspectors": map[string]any{
			"prompt_injection": map[string]any{"min_precision": 0.8, "min_recall": 0.2, "max_fpr": 0.05},
			"jailbreak":        map[string]any{"min_precision": 0.8, "min_recall": 0.01, "max_fpr": 0.05},
		},
	}
	b, _ := json.Marshal(manifest)
	p := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeBaselineWithIncompleteSemanticV2 — entry присутствует, но
// любое из provider/model/corpus_version пустое/ноль.
func writeBaselineWithIncompleteSemanticV2(t *testing.T, dir string) string {
	t.Helper()
	manifest := map[string]any{
		"inspectors": map[string]any{
			"semantic_v2": map[string]any{
				// provider = "" (incomplete metadata lock)
				"model": "nomic-embed-text", "corpus_version": 1,
				"min_precision": 0.5, "min_recall": 0.5, "max_fpr": 0.5,
			},
		},
	}
	b, _ := json.Marshal(manifest)
	p := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRun_WithEmbeddings_MissingSemanticV2Baseline_FailsHard — PR-6.1.1:
// если baseline не содержит entry для semantic_v2, run возвращает exit 1
// с explicit error в stderr. Это закрывает fail-open gap: до PR-6.1.1
// CI мог "успешно" пройти без реального regression gate.
func TestRun_WithEmbeddings_MissingSemanticV2Baseline_FailsHard(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	baselinePath := writeBaselineWithoutSemanticV2(t, tmp)
	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit = %d, want 1 (missing semantic_v2 entry)\nstderr: %s", code, stderr.String())
	}
	errStr := stderr.String()
	if !strings.Contains(errStr, "semantic_v2") {
		t.Errorf("stderr должен упомянуть semantic_v2: %s", errStr)
	}
	if !strings.Contains(errStr, "--allow-missing-baseline") {
		t.Errorf("stderr должен подсказать --allow-missing-baseline: %s", errStr)
	}
}

// TestRun_WithEmbeddings_IncompleteSemanticV2Metadata_FailsHard —
// entry присутствует, но metadata lock incomplete (provider = "").
// Без этого check semantic_v2 baseline с одними только thresholds и
// без привязки к embedding space был бы semantically fail-open.
func TestRun_WithEmbeddings_IncompleteSemanticV2Metadata_FailsHard(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	baselinePath := writeBaselineWithIncompleteSemanticV2(t, tmp)
	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit = %d, want 1 (incomplete metadata)\nstderr: %s", code, stderr.String())
	}
	errStr := stderr.String()
	if !strings.Contains(errStr, "incomplete metadata lock") {
		t.Errorf("stderr должен упомянуть incomplete metadata: %s", errStr)
	}
}

// TestRun_WithEmbeddings_MissingSemanticV2Baseline_WithAllowFlag —
// тот же bootstrap-сценарий, но с --allow-missing-baseline: warning и
// прогоняем без regression-check. Exit 0, если метрики mock'а валидны.
func TestRun_WithEmbeddings_MissingSemanticV2Baseline_WithAllowFlag(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	corpusPath := writeCorpus(t, tmp, "ollama", "nomic-embed-text")
	baselinePath := writeBaselineWithoutSemanticV2(t, tmp)
	configureEmbeddingEnv(t, srv.URL, corpusPath, "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--allow-missing-baseline",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
		"--format", "json",
	}, &stdout, &stderr)

	if code != 0 {
		t.Errorf("exit = %d, want 0 (bootstrap разрешён флагом)\nstderr: %s", code, stderr.String())
	}

	var report struct {
		Results []struct {
			Inspector string `json:"inspector"`
		} `json:"results"`
		Warnings []string `json:"warnings"`
	}
	_ = json.Unmarshal(stdout.Bytes(), &report)

	found := false
	for _, r := range report.Results {
		if r.Inspector == "semantic_v2" {
			found = true
		}
	}
	if !found {
		t.Errorf("semantic_v2 должен быть в results даже в bootstrap mode")
	}
	warnedAboutBaseline := false
	for _, w := range report.Warnings {
		if strings.Contains(w, "semantic_v2") && strings.Contains(w, "allow-missing-baseline") {
			warnedAboutBaseline = true
		}
	}
	if !warnedAboutBaseline {
		t.Errorf("должен быть warning про bootstrap-режим, got warnings: %v", report.Warnings)
	}
}

// TestRun_WithEmbeddings_InitFailureReturnsRuntime — если embedding
// endpoint недоступен при init (client build сам по себе ок, но первый
// реальный call, который произойдёт в Embed, упадёт), мы всё равно
// дойдём до Run и просто получим все Allow (fail-open). Это regression
// по recall (но не exit 1 — нет init-ошибки). Чтобы CI поймал это,
// baseline.min_recall делает своё дело.
//
// Здесь же проверяем, что если corpus файл не существует → exit 1
// (init error, не regression).
func TestRun_WithEmbeddings_MissingCorpus_FailsInit(t *testing.T) {
	srv := mockOllamaServer(t)
	defer srv.Close()
	tmp := t.TempDir()
	baselinePath := writeBaselineWithSemanticV2(t, tmp, "ollama", "nomic-embed-text", 1)
	// Не создаём corpus file.
	configureEmbeddingEnv(t, srv.URL, filepath.Join(tmp, "no-such-corpus.json"), "nomic-embed-text")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--with-embeddings",
		"--data", testDataDir(t),
		"--baseline", baselinePath,
	}, &stdout, &stderr)

	if code != 1 {
		t.Errorf("exit = %d, want 1 (missing corpus)\nstderr: %s", code, stderr.String())
	}
}

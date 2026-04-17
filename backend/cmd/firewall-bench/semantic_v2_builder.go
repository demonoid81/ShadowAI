package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/shadowai/backend/internal/embedding"
	"github.com/shadowai/backend/internal/firewall"
)

// semanticV2Setup — runtime-результат построения semantic_v2 inspector'а
// для бенчмарка. Полный метадата-комплект (Provider/Model/CorpusVersion)
// нужен CLI для сверки с baseline ДО запуска, чтобы не тратить
// HTTP-квоту embedding API на заведомо misconfigured прогон.
type semanticV2Setup struct {
	Inspector     firewall.Inspector
	Provider      string
	Model         string
	CorpusVersion int
}

// buildSemanticV2FromEnv собирает inspector из env-vars (те же имена,
// что читает backend/cmd/shadowai/main.go — сохраняем one source of
// truth для config shape).
//
// Returns error при любой init-ошибке (invalid env, client build fail,
// corpus load fail, metadata mismatch client ↔ corpus) — CLI выведет
// её и завершится exit 1.
func buildSemanticV2FromEnv() (*semanticV2Setup, error) {
	cfg, err := readEmbeddingEnv()
	if err != nil {
		return nil, err
	}

	client, err := embedding.NewClient(cfg.client)
	if err != nil {
		return nil, fmt.Errorf("embedding client: %w", err)
	}

	corpus, err := embedding.LoadCorpus(cfg.corpusPath)
	if err != nil {
		return nil, fmt.Errorf("corpus load: %w", err)
	}

	insp, err := firewall.NewSemanticV2Inspector(firewall.SemanticV2Config{
		Enabled:        true,
		Threshold:      cfg.threshold,
		BlockThreshold: cfg.blockThreshold,
	}, client, corpus)
	if err != nil {
		return nil, fmt.Errorf("inspector init: %w", err)
	}

	return &semanticV2Setup{
		Inspector:     insp,
		Provider:      client.Provider(),
		Model:         client.Model(),
		CorpusVersion: corpus.Version,
	}, nil
}

type embeddingCLIEnv struct {
	client         embedding.Config
	corpusPath     string
	threshold      float64
	blockThreshold float64
}

func readEmbeddingEnv() (embeddingCLIEnv, error) {
	provider := envOr("FIREWALL_EMBEDDING_PROVIDER", "ollama")
	endpoint := envOr("FIREWALL_EMBEDDING_ENDPOINT", "http://localhost:11434")
	model := envOr("FIREWALL_EMBEDDING_MODEL", "nomic-embed-text")
	apiKey := os.Getenv("FIREWALL_EMBEDDING_API_KEY")
	corpusPath := envOr("FIREWALL_SA_V2_CORPUS_PATH", "firewall_corpus/semantic_v2.json")

	dim, err := parseEnvInt("FIREWALL_EMBEDDING_DIMENSION", 768)
	if err != nil {
		return embeddingCLIEnv{}, err
	}
	timeout, err := parseEnvDuration("FIREWALL_EMBEDDING_TIMEOUT", 10*time.Second)
	if err != nil {
		return embeddingCLIEnv{}, err
	}
	threshold, err := parseEnvFloat("FIREWALL_SA_V2_THRESHOLD", 0.75)
	if err != nil {
		return embeddingCLIEnv{}, err
	}
	blockThreshold, err := parseEnvFloat("FIREWALL_SA_V2_BLOCK_THRESHOLD", 0.88)
	if err != nil {
		return embeddingCLIEnv{}, err
	}

	return embeddingCLIEnv{
		client: embedding.Config{
			Provider:  provider,
			Endpoint:  endpoint,
			Model:     model,
			APIKey:    apiKey,
			Dimension: dim,
			Timeout:   timeout,
		},
		corpusPath:     corpusPath,
		threshold:      threshold,
		blockThreshold: blockThreshold,
	}, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseEnvInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid int %q: %w", key, v, err)
	}
	return n, nil
}

func parseEnvFloat(key string, fallback float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid float %q: %w", key, v, err)
	}
	return f, nil
}

func parseEnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q: %w", key, v, err)
	}
	return d, nil
}

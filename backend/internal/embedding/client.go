// Package embedding предоставляет HTTP-клиент для внешних embedding-
// провайдеров. Используется в firewall/semantic_v2 для вычисления
// embeddings запросов и сравнения с precomputed corpus через cosine
// similarity.
//
// Особенности:
//   - L2-нормализация результата: cosine similarity на hot path
//     превращается в dot-product.
//   - Strict dimension check: если провайдер вернул vector другого
//     размера, это error (защита от рассогласования corpus vs runtime).
//   - Provider-specific request/response shapes инкапсулированы.
//   - Metrics observability (PR-6): requests/fail/timeout counters +
//     latency histogram, label (provider, model).
package embedding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/shadowai/backend/internal/metrics"
)

// Embedding — результат Embed-вызова. Vector всегда L2-нормализован
// (|v| = 1), так что cosine(a, b) = dot(a, b).
type Embedding struct {
	Vector []float64 `json:"vector"`
}

// Config — конфигурация клиента. Dimension обязателен: мы проверяем
// ответ провайдера против него, чтобы не допустить тихое рассогласование
// corpus metadata vs runtime (cosine между разными embedding spaces
// не имеет смысла).
type Config struct {
	Provider  string
	Endpoint  string
	Model     string
	APIKey    string // required for openai
	Timeout   time.Duration
	Dimension int
}

// Embedder — контракт для consumers (firewall/semantic_v2). Позволяет
// unit-тестировать inspector с fake-клиентом без HTTP-моков. Client
// из этого же пакета реализует интерфейс.
type Embedder interface {
	Embed(ctx context.Context, text string) (Embedding, error)
	Provider() string
	Model() string
	Dimension() int
}

// Client — тонкая абстракция над provider-specific API. Не интерфейс
// в Go-смысле (только одна реализация на MVP), но все методы exported,
// чтобы caller мог mockать через type alias или wrapping struct.
type Client struct {
	cfg Config
	http *http.Client
}

// NewClient создаёт клиент и валидирует конфиг. Fail-fast: если
// provider/endpoint/model/dimension/timeout не заданы — error.
func NewClient(cfg Config) (*Client, error) {
	switch cfg.Provider {
	case "ollama", "openai":
	default:
		return nil, fmt.Errorf("embedding: unsupported provider %q (want ollama|openai)", cfg.Provider)
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("embedding: endpoint required")
	}
	if cfg.Model == "" {
		return nil, fmt.Errorf("embedding: model required")
	}
	if cfg.Dimension <= 0 {
		return nil, fmt.Errorf("embedding: dimension must be > 0 (expected vector length from provider)")
	}
	if cfg.Timeout <= 0 {
		return nil, fmt.Errorf("embedding: timeout must be > 0")
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// Provider возвращает имя провайдера (для metrics labels и corpus
// metadata match-check).
func (c *Client) Provider() string { return c.cfg.Provider }

// Model возвращает имя модели (для metrics labels и corpus match).
func (c *Client) Model() string { return c.cfg.Model }

// Dimension возвращает ожидаемую размерность вектора.
func (c *Client) Dimension() int { return c.cfg.Dimension }

// Embed вычисляет embedding для текста. Возвращает L2-normalized vector.
//
// Семантика ошибок (для caller-инспектора, различающего metric-buckets):
//   - IsTimeout(err) == true — inc timeout counter
//   - иначе inc fail counter
// В обоих случаях caller обычно деградирует в ActionAllow (fail-open).
func (c *Client) Embed(ctx context.Context, text string) (Embedding, error) {
	metrics.RecordEmbeddingRequest(c.cfg.Provider, c.cfg.Model)
	start := time.Now()

	raw, err := c.fetchRaw(ctx, text)
	if err != nil {
		if isTimeoutErr(err) {
			metrics.RecordEmbeddingTimeout(c.cfg.Provider, c.cfg.Model)
		} else {
			metrics.RecordEmbeddingFail(c.cfg.Provider, c.cfg.Model)
		}
		return Embedding{}, err
	}

	if len(raw) != c.cfg.Dimension {
		metrics.RecordEmbeddingFail(c.cfg.Provider, c.cfg.Model)
		return Embedding{}, fmt.Errorf("embedding: provider returned dimension %d, expected %d", len(raw), c.cfg.Dimension)
	}

	normalized, err := l2Normalize(raw)
	if err != nil {
		metrics.RecordEmbeddingFail(c.cfg.Provider, c.cfg.Model)
		return Embedding{}, fmt.Errorf("embedding: %w", err)
	}

	metrics.ObserveEmbeddingLatency(c.cfg.Provider, c.cfg.Model, time.Since(start).Seconds())
	return Embedding{Vector: normalized}, nil
}

func (c *Client) fetchRaw(ctx context.Context, text string) ([]float64, error) {
	switch c.cfg.Provider {
	case "ollama":
		return c.fetchOllama(ctx, text)
	case "openai":
		return c.fetchOpenAI(ctx, text)
	default:
		return nil, fmt.Errorf("embedding: unsupported provider %q", c.cfg.Provider)
	}
}

func (c *Client) fetchOllama(ctx context.Context, text string) ([]float64, error) {
	body, _ := json.Marshal(map[string]string{
		"model":  c.cfg.Model,
		"prompt": text,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.cfg.Endpoint, "/")+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embedding: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding: ollama call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding: ollama http %d: %s", resp.StatusCode, string(b))
	}

	var out struct {
		Embedding []float64 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("embedding: parse ollama response: %w", err)
	}
	if len(out.Embedding) == 0 {
		return nil, fmt.Errorf("embedding: ollama returned empty vector")
	}
	return out.Embedding, nil
}

func (c *Client) fetchOpenAI(ctx context.Context, text string) ([]float64, error) {
	body, _ := json.Marshal(map[string]string{
		"model": c.cfg.Model,
		"input": text,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.cfg.Endpoint, "/")+"/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("embedding: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding: openai call: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("embedding: openai http %d: %s", resp.StatusCode, string(b))
	}

	var out struct {
		Data []struct {
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("embedding: parse openai response: %w", err)
	}
	if len(out.Data) == 0 || len(out.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embedding: openai returned empty data")
	}
	return out.Data[0].Embedding, nil
}

// l2Normalize приводит вектор к единичной длине. Zero-вектор — degenerate
// response провайдера, возвращаем error (в corpus-matching даст cosine=0
// для всего подряд, что равнозначно бессмысленному детектору).
func l2Normalize(v []float64) ([]float64, error) {
	var sumSq float64
	for _, x := range v {
		sumSq += x * x
	}
	if sumSq == 0 {
		return nil, errors.New("zero-magnitude embedding (degenerate response)")
	}
	norm := math.Sqrt(sumSq)
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = x / norm
	}
	return out, nil
}

// IsTimeout — true если ошибка пришла от client.Timeout / context deadline.
// Экспортируется, чтобы caller мог инкрементить правильный metrics counter
// (отдельные alerting'ы на timeout-spikes vs transport-errors).
func IsTimeout(err error) bool {
	return isTimeoutErr(err)
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	return false
}

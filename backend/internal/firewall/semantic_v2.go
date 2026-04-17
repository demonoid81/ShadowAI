package firewall

import (
	"context"
	"fmt"
	"log"

	"github.com/shadowai/backend/internal/embedding"
)

// SemanticV2Config — конфиг embedding-based inspector'а. Threshold +
// BlockThreshold обязательны (в pure-Enabled scenario): ниже Threshold —
// Allow, между ним и BlockThreshold — Flag, выше BlockThreshold — Block.
type SemanticV2Config struct {
	Enabled        bool
	Threshold      float64 // flag threshold
	BlockThreshold float64 // block threshold (>= Threshold)
}

// SemanticV2Inspector — inspector, работающий на cosine similarity
// между embedding запроса и precomputed corpus known-атак.
//
// Fail-fast контракт:
//   - Corpus.Provider/Model/Dimension ДОЛЖНЫ совпадать с client'ом.
//     Иначе init возвращает error и pipeline регистрация не происходит
//     (main.go видит ошибку, логирует и либо падает с exit 1, либо
//     пропускает inspector — решение caller'а).
//
// Fail-open на hot path:
//   - Любая runtime-ошибка embedding (timeout/HTTP/malformed) →
//     ActionAllow. Embedding client уже инкрементировал соответствующий
//     metrics counter (timeout/fail), дублирования здесь нет.
type SemanticV2Inspector struct {
	config SemanticV2Config
	client embedding.Embedder
	corpus *embedding.Corpus
}

// NewSemanticV2Inspector создаёт inspector с compile-time-like проверкой,
// что runtime embedding space совпадает с corpus-vector space.
func NewSemanticV2Inspector(cfg SemanticV2Config, client embedding.Embedder, corpus *embedding.Corpus) (*SemanticV2Inspector, error) {
	if client == nil {
		return nil, fmt.Errorf("semantic_v2: embedder client required")
	}
	if corpus == nil {
		return nil, fmt.Errorf("semantic_v2: corpus required")
	}
	if client.Provider() != corpus.Provider {
		return nil, fmt.Errorf("semantic_v2: provider mismatch (client=%q, corpus=%q)",
			client.Provider(), corpus.Provider)
	}
	if client.Model() != corpus.Model {
		return nil, fmt.Errorf("semantic_v2: model mismatch (client=%q, corpus=%q)",
			client.Model(), corpus.Model)
	}
	if client.Dimension() != corpus.Dimension {
		return nil, fmt.Errorf("semantic_v2: dimension mismatch (client=%d, corpus=%d)",
			client.Dimension(), corpus.Dimension)
	}

	// Пороговая валидация только если Enabled=true. Disabled inspector
	// с нулевыми порогами должен создаваться без ошибок (для ops-
	// сценария "pre-configure before corpus is ready").
	if cfg.Enabled {
		if cfg.Threshold <= 0 || cfg.Threshold > 1 {
			return nil, fmt.Errorf("semantic_v2: threshold must be in (0, 1], got %g", cfg.Threshold)
		}
		if cfg.BlockThreshold <= 0 || cfg.BlockThreshold > 1 {
			return nil, fmt.Errorf("semantic_v2: block_threshold must be in (0, 1], got %g", cfg.BlockThreshold)
		}
		if cfg.BlockThreshold < cfg.Threshold {
			return nil, fmt.Errorf("semantic_v2: block_threshold (%g) must be >= threshold (%g)",
				cfg.BlockThreshold, cfg.Threshold)
		}
	}

	return &SemanticV2Inspector{
		config: cfg,
		client: client,
		corpus: corpus,
	}, nil
}

// Name — идентификатор инспектора в pipeline/status/metrics. Отличается
// от V1 "semantic", чтобы можно было одновременно регистрировать оба.
func (s *SemanticV2Inspector) Name() string { return "semantic_v2" }

// InspectRequest вычисляет embedding запроса и сравнивает с corpus.
// Fail-open на любую ошибку embedding client'а.
func (s *SemanticV2Inspector) InspectRequest(ctx context.Context, p *Payload) (*Decision, error) {
	if !s.config.Enabled {
		return &Decision{Action: ActionAllow}, nil
	}
	if p == nil || p.Text == "" {
		return &Decision{Action: ActionAllow}, nil
	}

	emb, err := s.client.Embed(ctx, p.Text)
	if err != nil {
		// Fail-open. Client уже инкрементировал embedding_fail/timeout
		// metrics. Inspector-side log один раз, чтобы оператор видел
		// деградацию даже без metrics-скрейпа.
		log.Printf("semantic_v2: embed error (fail-open): %v", err)
		return &Decision{Action: ActionAllow}, nil
	}

	sim, match := s.corpus.MaxSim(emb.Vector)
	if match == nil {
		// Corpus пуст или dimension mismatch (не должно случаться —
		// проверено при init, но runtime-safety). Fail-open.
		return &Decision{Action: ActionAllow}, nil
	}

	if sim >= s.config.BlockThreshold {
		return &Decision{
			Action:   ActionBlock,
			Reason:   fmt.Sprintf("semantic_v2: high similarity to known threat (%s)", match.Category),
			Severity: SeverityCritical,
			Findings: []Finding{semanticV2Finding(sim, match)},
		}, nil
	}
	if sim >= s.config.Threshold {
		return &Decision{
			Action:   ActionFlag,
			Reason:   fmt.Sprintf("semantic_v2: suspicious similarity to known threat (%s)", match.Category),
			Severity: SeverityMedium,
			Findings: []Finding{semanticV2Finding(sim, match)},
		}, nil
	}

	return &Decision{Action: ActionAllow}, nil
}

// InspectResponse не исполняется: Semantic V2 работает только на request.
func (s *SemanticV2Inspector) InspectResponse(_ context.Context, _ *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

func semanticV2Finding(sim float64, match *embedding.CorpusItem) Finding {
	return Finding{
		Type:     "semantic_v2:" + match.Category,
		Severity: SeverityHigh,
		Match:    match.Text,
		Meta: map[string]string{
			"similarity": fmt.Sprintf("%.4f", sim),
			"match_id":   match.ID,
			"category":   match.Category,
		},
	}
}

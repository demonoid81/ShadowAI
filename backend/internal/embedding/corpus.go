package embedding

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"time"
)

// currentCorpusVersion — schema version для forward-compat. LoadCorpus
// откажется грузить manifest с другой version (чтобы не интерпретировать
// новые поля как известные).
const currentCorpusVersion = 1

// cosineStrictnessEps — допуск для проверки normalized-vector при load.
// Вычисленные embeddings обычно имеют numeric noise, ±1e-6 безопасно.
const cosineStrictnessEps = 1e-5

// Corpus — precomputed набор attack-embeddings для semantic_v2.
// Metadata (Provider/Model/Dimension) обязательны: runtime inspector
// сравнивает их с client.Config и отказывается стартовать при mismatch
// (cosine между разными embedding spaces бессмысленен).
type Corpus struct {
	Version     int          `json:"version"`
	Provider    string       `json:"provider"`
	Model       string       `json:"model"`
	Dimension   int          `json:"dimension"`
	Normalized  bool         `json:"normalized"`
	GeneratedAt time.Time    `json:"generated_at,omitempty"`
	Items       []CorpusItem `json:"items"`
}

// CorpusItem — одно "known attack" embedding.
type CorpusItem struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"` // prompt_injection | jailbreak | ...
	Text      string    `json:"text"`
	Embedding []float64 `json:"embedding"`
}

// LoadCorpus читает manifest и валидирует его структуру:
//   - version == currentCorpusVersion (иначе forward-compat risk);
//   - provider/model/dimension/items — обязательны;
//   - каждый item.embedding той же dimension, что и manifest;
//   - если normalized=true, каждый vector действительно unit-length.
func LoadCorpus(path string) (*Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("corpus: read %s: %w", path, err)
	}
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("corpus: parse %s: %w", path, err)
	}

	if c.Version != currentCorpusVersion {
		return nil, fmt.Errorf("corpus: unsupported version %d (want %d)", c.Version, currentCorpusVersion)
	}
	if c.Provider == "" {
		return nil, fmt.Errorf("corpus: provider is required")
	}
	if c.Model == "" {
		return nil, fmt.Errorf("corpus: model is required")
	}
	if c.Dimension <= 0 {
		return nil, fmt.Errorf("corpus: dimension must be > 0")
	}
	if len(c.Items) == 0 {
		return nil, fmt.Errorf("corpus: items list is empty (nothing to match against)")
	}

	for i, item := range c.Items {
		if item.ID == "" {
			return nil, fmt.Errorf("corpus: item[%d] missing id", i)
		}
		if len(item.Embedding) != c.Dimension {
			return nil, fmt.Errorf("corpus: item[%d] (id=%s) dimension mismatch: got %d, expected %d",
				i, item.ID, len(item.Embedding), c.Dimension)
		}
		if c.Normalized {
			if !isUnitVector(item.Embedding, cosineStrictnessEps) {
				return nil, fmt.Errorf("corpus: item[%d] (id=%s) не нормализован (manifest.normalized=true)", i, item.ID)
			}
		}
	}

	return &c, nil
}

// MaxSim возвращает максимальную cosine similarity (= dot-product для
// нормализованных векторов) между query и items. Вход query ожидается
// L2-нормализованным.
//
// Безопасна к edge cases:
//   - пустой items → sim=0, match=nil;
//   - dimension mismatch → sim=0, match=nil (caller сам решит, как
//     эскалировать эту ошибку; MaxSim не panic'ит на hot path).
func (c *Corpus) MaxSim(query []float64) (float64, *CorpusItem) {
	if c == nil || len(c.Items) == 0 {
		return 0, nil
	}
	if len(query) != c.Dimension {
		return 0, nil
	}

	var best *CorpusItem
	maxSim := math.Inf(-1)
	for i := range c.Items {
		item := &c.Items[i]
		sim := dot(query, item.Embedding)
		if sim > maxSim {
			maxSim = sim
			best = item
		}
	}
	if math.IsInf(maxSim, -1) {
		return 0, nil
	}
	return maxSim, best
}

func dot(a, b []float64) float64 {
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

func isUnitVector(v []float64, eps float64) bool {
	var sumSq float64
	for _, x := range v {
		sumSq += x * x
	}
	return math.Abs(math.Sqrt(sumSq)-1.0) < eps
}

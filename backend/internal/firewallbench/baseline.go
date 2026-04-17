package firewallbench

import (
	"encoding/json"
	"fmt"
	"os"
)

// Baseline — committed thresholds per inspector (testdata/firewall_bench/baseline.json).
//
// Смысл: MVP-контракт "CI падает, если любая метрика хуже baseline".
// Когда вы сознательно хотите обновить baseline (улучшили patterns или
// datasets), меняете файл в PR — diff виден ревьюеру.
//
// Почему НЕ last-run записывается в репо: CI не должен модифицировать
// repo state. Runner вместо этого печатает current metrics в stdout/JSON,
// CI загружает их как artifact; сравнение с baseline делает сам runner.
type Baseline struct {
	Inspectors map[string]InspectorBaseline `json:"inspectors"`
}

// InspectorBaseline — пороги для одного инспектора. Значение 0 означает
// "threshold отсутствует" и соответствующая проверка пропускается, что
// позволяет частично конфигурировать thresholds при постепенном вводе
// нового инспектора в бенчмарк.
//
// Provider/Model/CorpusVersion (PR-6.1) — optional metadata lock для
// embedding-based инспекторов. Если заданы, CLI обязан проверить
// совпадение runtime provider/model/corpus_version перед use,
// иначе сравнение метрик бессмысленно (metрики на одном provider не
// переносимы на другой).
type InspectorBaseline struct {
	MinPrecision  float64 `json:"min_precision"`
	MinRecall     float64 `json:"min_recall"`
	MaxFPR        float64 `json:"max_fpr"`
	Provider      string  `json:"provider,omitempty"`
	Model         string  `json:"model,omitempty"`
	CorpusVersion int     `json:"corpus_version,omitempty"`
}

// Regression — описание одного нарушения threshold'а.
// Threshold — baseline-значение, Actual — текущий замер.
// Field — "precision" | "recall" | "fpr" (для форматирования в отчёте).
type Regression struct {
	Inspector string  `json:"inspector"`
	Field     string  `json:"field"`
	Threshold float64 `json:"threshold"`
	Actual    float64 `json:"actual"`
}

// LoadBaseline читает JSON-файл baseline.json.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if b.Inspectors == nil {
		b.Inspectors = make(map[string]InspectorBaseline)
	}
	return &b, nil
}

// HasInspector — true, если в baseline есть запись для инспектора.
func (b *Baseline) HasInspector(name string) bool {
	if b == nil {
		return false
	}
	_, ok := b.Inspectors[name]
	return ok
}

// CheckInspectorMetadata (PR-6.1) сравнивает зафиксированные в baseline
// provider/model/corpus_version с runtime-значениями. Возвращает список
// несовпадений; пустой — metadata совпадает ИЛИ baseline не содержит
// эти поля (backward compat с heuristic инспекторами).
//
// CLI должен падать с exit 1 при len(result) > 0. Это не regression
// (у нас нет метрик для сравнения), а misconfig: baseline thresholds
// выставлены для другого embedding space, применять их нельзя.
func (b *Baseline) CheckInspectorMetadata(name, provider, model string, corpusVersion int) []Regression {
	if b == nil {
		return nil
	}
	rule, ok := b.Inspectors[name]
	if !ok {
		return nil
	}
	var out []Regression
	if rule.Provider != "" && rule.Provider != provider {
		out = append(out, Regression{
			Inspector: name, Field: "provider",
			Actual: 0, Threshold: 0,
		})
		// Threshold/Actual float бесполезны для строковых полей, но
		// сохраняем тот же тип для единого отчёта. Метаданные выносим
		// в Reason через отдельный метод ниже.
	}
	if rule.Model != "" && rule.Model != model {
		out = append(out, Regression{Inspector: name, Field: "model"})
	}
	if rule.CorpusVersion != 0 && rule.CorpusVersion != corpusVersion {
		out = append(out, Regression{
			Inspector: name, Field: "corpus_version",
			Threshold: float64(rule.CorpusVersion),
			Actual:    float64(corpusVersion),
		})
	}
	return out
}

// MetadataFor возвращает copy зафиксированных metadata для инспектора
// (provider/model/corpus_version). Пустая строка/0 означает "не задано".
// Используется CLI для форматирования ошибок metadata-mismatch.
func (b *Baseline) MetadataFor(name string) (provider, model string, corpusVersion int) {
	if b == nil {
		return "", "", 0
	}
	rule, ok := b.Inspectors[name]
	if !ok {
		return "", "", 0
	}
	return rule.Provider, rule.Model, rule.CorpusVersion
}

// CheckRegression сравнивает m против thresholds инспектора и возвращает
// список нарушений. Если инспектора нет в baseline — []Regression{}
// (CLI отдельно сообщит "no baseline").
//
// Threshold == 0 пропускается (allows partial config'ю).
func (b *Baseline) CheckRegression(name string, m Metrics) []Regression {
	if b == nil {
		return nil
	}
	rule, ok := b.Inspectors[name]
	if !ok {
		return nil
	}
	var out []Regression

	if rule.MinPrecision > 0 && m.Precision < rule.MinPrecision {
		out = append(out, Regression{
			Inspector: name, Field: "precision",
			Threshold: rule.MinPrecision, Actual: m.Precision,
		})
	}
	if rule.MinRecall > 0 && m.Recall < rule.MinRecall {
		out = append(out, Regression{
			Inspector: name, Field: "recall",
			Threshold: rule.MinRecall, Actual: m.Recall,
		})
	}
	if rule.MaxFPR > 0 && m.FPR > rule.MaxFPR {
		out = append(out, Regression{
			Inspector: name, Field: "fpr",
			Threshold: rule.MaxFPR, Actual: m.FPR,
		})
	}
	return out
}

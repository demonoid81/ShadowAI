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
type InspectorBaseline struct {
	MinPrecision float64 `json:"min_precision"`
	MinRecall    float64 `json:"min_recall"`
	MaxFPR       float64 `json:"max_fpr"`
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

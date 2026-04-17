// Package firewallbench реализует FP/FN benchmark harness для
// firewall-инспекторов (PR-5).
//
// Design highlights:
//   - Offline, детерминистичный запуск: инспекторы конструируются без
//     LLM-judge (judge=nil), чтобы бенчмарк был воспроизводим на CI
//     без сетевых зависимостей.
//   - Data-driven через JSONL в backend/testdata/firewall_bench/<name>/.
//   - Committed baseline.json с пороговыми значениями; regression =
//     любая метрика ниже baseline → non-zero exit из CLI.
//   - Сам пакет не импортирует CLI-хелперы: CLI (cmd/firewall-bench)
//     строится поверх.
package firewallbench

// Metrics — сводка FP/FN бенчмарка для одного инспектора.
// Все float64 защищены от NaN/Inf (см. Compute): это критично для
// JSON-serialization (NaN не валиден в JSON по RFC 8259) и для сравнения
// с baseline, где NaN != NaN сломало бы регрессионную логику.
type Metrics struct {
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	FPR       float64 `json:"fpr"`
	F1        float64 `json:"f1"`
}

// Compute строит Metrics из counts. Защищает от деления на ноль:
// любая "нулевая" комбинация возвращает 0.0 для соответствующей метрики.
func Compute(tp, fp, tn, fn int) Metrics {
	m := Metrics{TP: tp, FP: fp, TN: tn, FN: fn}

	if tp+fp > 0 {
		m.Precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		m.Recall = float64(tp) / float64(tp+fn)
	}
	if fp+tn > 0 {
		m.FPR = float64(fp) / float64(fp+tn)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	return m
}

// Positives возвращает размер класса "угрозы" в dataset'е (TP + FN).
func (m Metrics) Positives() int { return m.TP + m.FN }

// Negatives возвращает размер класса "не-угрозы" (FP + TN).
func (m Metrics) Negatives() int { return m.FP + m.TN }

// Total — общий размер dataset'а.
func (m Metrics) Total() int { return m.TP + m.FP + m.TN + m.FN }

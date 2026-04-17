package firewallbench

import "context"

// DetectFunc — абстрактный "детектор" для runner'а.
//
// Возвращает true, если инспектор считает текст угрозой
// (т.е. Decision.Action != ActionAllow).
//
// Принимает ctx, чтобы CLI мог прервать долгий прогон через SIGINT.
type DetectFunc func(ctx context.Context, text string) bool

// Result — итог бенчмарка одного инспектора на одной паре
// (positive, negative) dataset'ов.
type Result struct {
	Inspector string  `json:"inspector"`
	Metrics   Metrics `json:"metrics"`
}

// Run прогоняет detector через positive и negative датасеты и считает
// TP/FP/TN/FN + производные метрики. Порядок обхода: сначала positive
// (TP vs FN), затем negative (FP vs TN). Это делает вывод runner'а
// стабильным и reproducible для CI diff'ов.
func Run(ctx context.Context, name string, detect DetectFunc, positive, negative []Example) Result {
	var tp, fp, tn, fn int

	for _, ex := range positive {
		if detect(ctx, ex.Text) {
			tp++
		} else {
			fn++
		}
	}
	for _, ex := range negative {
		if detect(ctx, ex.Text) {
			fp++
		} else {
			tn++
		}
	}

	return Result{
		Inspector: name,
		Metrics:   Compute(tp, fp, tn, fn),
	}
}

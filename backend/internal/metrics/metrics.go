// Package metrics централизованно объявляет Prometheus-метрики ShadowAI
// для scrape-endpoint /metrics.
//
// Метрики сгруппированы по доменам:
//   - audit: pipeline здоровье (queue_depth, dropped, inserted, failed)
//   - firewall: решения инспекторов по фазе/action
//   - proxy: budget блокировки, stream usage parse ошибки
//
// Все имена — в snake_case с префиксом `shadowai_` согласно Prometheus
// best practice. Суффиксы _total для счётчиков.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// AuditQueueDepth — текущая глубина audit-очереди (gauge).
	// Высокие значения → worker не успевает писать, риск drop'ов.
	AuditQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "shadowai_audit_queue_depth",
		Help: "Current depth of the audit log queue. High values indicate DB slowdown.",
	})

	// AuditDroppedTotal — счётчик записей, отброшенных из-за переполнения канала.
	// Любое значение > 0 — security-событие (потеря audit trail).
	AuditDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_audit_dropped_total",
		Help: "Total number of audit entries dropped due to full queue.",
	})

	// AuditInsertedTotal — счётчик успешно вставленных в БД записей.
	AuditInsertedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_audit_inserted_total",
		Help: "Total number of audit entries successfully persisted.",
	})

	// AuditFailedTotal — счётчик ошибок при вставке в БД.
	// Рост → проблемы с Postgres/network, риск потери audit trail.
	AuditFailedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "shadowai_audit_failed_total",
		Help: "Total number of audit insert errors.",
	})

	// FirewallDecisionsTotal — распределение решений firewall по
	// фазе (request/response), инспектору (pii, dlp, policy, jailbreak, ...)
	// и action (allow/flag/sanitize/block).
	FirewallDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_firewall_decisions_total",
		Help: "Total firewall inspector decisions grouped by phase, inspector, action.",
	}, []string{"phase", "inspector", "action"})

	// ProxyBudgetBlocksTotal — счётчик 402 блокировок по бюджету.
	// Label `streaming` = "true"/"false".
	ProxyBudgetBlocksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_proxy_budget_blocks_total",
		Help: "Total requests blocked due to budget exceeded.",
	}, []string{"streaming"})

	// StreamUsageParseFailTotal — счётчик случаев, когда ParseResponse
	// вернул 0 tokens для streaming-ответа. Известный gap: SSE без usage.
	// Label `provider` — имя провайдера.
	StreamUsageParseFailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_stream_usage_parse_fail_total",
		Help: "Total streaming responses where usage could not be parsed (likely SSE without include_usage).",
	}, []string{"provider"})

	// --- LLM-as-Judge observability ---
	//
	// Cardinality constraint: label provider+threat_type даёт умеренный
	// набор (≤ 6 providers × ≤ 4 threat_types = 24 комбинации). НЕ
	// добавлять user/model/tenant — это взорвёт cardinality.

	// JudgeRequestsTotal — все вызовы Evaluate (enabled judge, не disabled).
	// Знаменатель для вычисления fail-rate.
	JudgeRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_judge_requests_total",
		Help: "Total LLM-as-Judge Evaluate() calls (enabled configuration).",
	}, []string{"provider", "threat_type"})

	// JudgeFailTotal — любая категория неуспеха judge. Сумма
	// fail == timeout + malformed + error (transport/HTTP/build).
	JudgeFailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_judge_fail_total",
		Help: "Total judge failures (transport, HTTP, build errors). Does not include timeout/malformed (see separate counters).",
	}, []string{"provider", "threat_type"})

	// JudgeTimeoutTotal — отдельный счётчик timeout'ов для alerting
	// (обычно требует отдельной реакции от infra/scale).
	JudgeTimeoutTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_judge_timeout_total",
		Help: "Judge request timeouts (client.Timeout exceeded).",
	}, []string{"provider", "threat_type"})

	// JudgeMalformedTotal — провайдер вернул 200 OK, но body не парсится
	// (invalid JSON в choices/message/content или schema mismatch).
	// КРИТИЧНО для security: malformed = judge "сказал not threat" из-за
	// деградации, а не из-за реального анализа. Рост → drift API провайдера.
	JudgeMalformedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_judge_malformed_total",
		Help: "Judge returned 200 but response body is malformed. Silent security degradation if growing.",
	}, []string{"provider", "threat_type"})

	// JudgeFallbackTotal — случаи, когда Evaluate вернул degraded result
	// (IsThreat=false с причиной "malformed response"). Это ИНСПЕКТОР
	// увидел fallback-путь. Для dashboards этот счётчик отделён от fail_total,
	// потому что fallback = решение не блокировать (visible security choice).
	JudgeFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_judge_fallback_total",
		Help: "Judge returned soft-allow fallback (IsThreat=false) due to malformed/degraded response.",
	}, []string{"provider", "threat_type"})

	// JudgeLatencySeconds — распределение latency для judge-вызовов.
	// Включает только success и malformed (не timeout/transport — там
	// нет осмысленного latency). Buckets подобраны под LLM latency
	// profile: 100ms .. 30s.
	JudgeLatencySeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "shadowai_judge_latency_seconds",
		Help:    "LLM-as-Judge call latency in seconds (from request start to response parsed).",
		Buckets: []float64{0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0},
	}, []string{"provider", "threat_type"})
)

// RecordAuditQueue обновляет gauge очереди. Вызывать из периодического
// sampler'а в audit service (или из /metrics handler).
func RecordAuditQueue(depth int) {
	AuditQueueDepth.Set(float64(depth))
}

// RecordFirewallDecision инкрементирует счётчик решений.
func RecordFirewallDecision(phase, inspector, action string) {
	FirewallDecisionsTotal.WithLabelValues(phase, inspector, action).Inc()
}

// RecordBudgetBlock инкрементирует budget-block счётчик.
func RecordBudgetBlock(streaming bool) {
	label := "false"
	if streaming {
		label = "true"
	}
	ProxyBudgetBlocksTotal.WithLabelValues(label).Inc()
}

// RecordStreamUsageParseFail инкрементирует счётчик парсинга usage для streaming.
func RecordStreamUsageParseFail(provider string) {
	StreamUsageParseFailTotal.WithLabelValues(provider).Inc()
}

// RecordJudgeRequest инкрементирует счётчик всех judge вызовов.
func RecordJudgeRequest(provider, threatType string) {
	JudgeRequestsTotal.WithLabelValues(provider, threatType).Inc()
}

// RecordJudgeFail инкрементирует счётчик transport/HTTP/build ошибок.
func RecordJudgeFail(provider, threatType string) {
	JudgeFailTotal.WithLabelValues(provider, threatType).Inc()
}

// RecordJudgeTimeout инкрементирует счётчик timeout'ов.
func RecordJudgeTimeout(provider, threatType string) {
	JudgeTimeoutTotal.WithLabelValues(provider, threatType).Inc()
}

// RecordJudgeMalformed инкрементирует счётчик malformed responses.
func RecordJudgeMalformed(provider, threatType string) {
	JudgeMalformedTotal.WithLabelValues(provider, threatType).Inc()
}

// RecordJudgeFallback инкрементирует счётчик degraded soft-allow path.
func RecordJudgeFallback(provider, threatType string) {
	JudgeFallbackTotal.WithLabelValues(provider, threatType).Inc()
}

// ObserveJudgeLatency записывает latency в histogram.
func ObserveJudgeLatency(provider, threatType string, seconds float64) {
	JudgeLatencySeconds.WithLabelValues(provider, threatType).Observe(seconds)
}

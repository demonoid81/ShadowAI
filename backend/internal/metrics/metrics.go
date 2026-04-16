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

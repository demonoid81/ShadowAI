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
	// фазе (request/response), инспектору (pii, dlp, policy, jailbreak, ...),
	// action (allow/flag/sanitize/block) и mode (enforce/shadow).
	//
	// PR-4: label `mode` добавлен, чтобы отделить shadow-наблюдения от
	// enforce-действий в dashboards. disabled-инспекторы метрику не пишут.
	// Cardinality: ≤ 2 phase × ≤ 10 inspector × 4 action × 2 mode = 160,
	// что в пределах бюджета Prometheus.
	FirewallDecisionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_firewall_decisions_total",
		Help: "Total firewall inspector decisions grouped by phase, inspector, action, mode.",
	}, []string{"phase", "inspector", "action", "mode"})

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

	// PR-F7.1: streaming transport layer metrics. Cardinality safe:
	// labels ограничены provider (≤ 7 values из SupportedProviders)
	// + mode ("buffered"/"incremental"/"shadow") для mode-total;
	// reason для fallback — fixed vocabulary ("unsupported_provider"
	// / "decoder_error" / позже в F7.2 "judge_inspector" и т.п.).

	// StreamingModeTotal — сколько streaming-запросов какому режиму
	// пошло. Используется для rollout visibility (Stage 0 → все
	// buffered, Stage 1 → растёт incremental).
	StreamingModeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_streaming_mode_total",
		Help: "Streaming requests by transport mode and provider.",
	}, []string{"mode", "provider"})

	// StreamingMalformedChunkTotal — количество frame'ов, которые
	// decoder не смог распарсить (unknown_chunk из-за JSON error
	// или неподдержанной структуры). Alerting signal для parser
	// regression'ов.
	StreamingMalformedChunkTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_streaming_malformed_chunk_total",
		Help: "Streaming frames decoder could not parse into a known event.",
	}, []string{"provider"})

	// StreamingEmitFailTotal — emit error при записи в downstream
	// writer. Обычно означает client disconnect, но может быть
	// upstream http.Flusher contract violation.
	//
	// Invariant: инкрементится ТОЛЬКО в emit-phase; decoder-fatal
	// errors идут в StreamingDecoderFatalTotal. Caller не должен
	// повторно инкрементить этот счётчик при transport error
	// (иначе double-count + смешение с decode failures).
	StreamingEmitFailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_streaming_emit_fail_total",
		Help: "Streaming downstream emit failures (client disconnect, writer errors). Emit-phase only; decoder-fatal tracked separately.",
	}, []string{"provider"})

	// StreamingDecoderFatalTotal — decoder вернул non-cancel error.
	// Это upstream read failure (connection reset, unexpected EOF с
	// real data loss) или parser fatal. Отдельный счётчик от
	// StreamingEmitFailTotal, чтобы alerting мог различать "client
	// disconnect / writer broken" от "upstream / parser broken".
	StreamingDecoderFatalTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_streaming_decoder_fatal_total",
		Help: "Streaming decoder returned non-cancel fatal error (upstream read failure, parser fatal). Separate from emit failures.",
	}, []string{"provider"})

	// StreamingFallbackTotal — transition из incremental в buffered
	// path по причине. В F7.1 только "unsupported_provider"; в F7.2
	// добавится "judge_inspector" (RFC §12.6) и прочие.
	StreamingFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_streaming_fallback_total",
		Help: "Streaming transitions from incremental to buffered fallback.",
	}, []string{"provider", "reason"})

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

	// JudgeFailTotal — НЕ-overlapping с timeout/malformed. Содержит
	// только transport errors (DNS, refused, reset), HTTP ошибки
	// (non-2xx), и build errors (JSON marshal, request construction).
	// Timeout и malformed имеют отдельные counters и НЕ включаются сюда.
	// Для "total non-success rate" в dashboard складывайте:
	//   rate(fail) + rate(timeout) + rate(malformed).
	JudgeFailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_judge_fail_total",
		Help: "Judge transport/HTTP/build errors. Non-overlapping with timeout_total and malformed_total.",
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

	// --- Embedding observability (PR-6) ---
	//
	// Semantic V2 inspector делает HTTP-call к embedding provider
	// (Ollama/OpenAI) на каждый inspect. Деградация embedding layer
	// превращает inspector в soft-allow (fail-open), поэтому нужны
	// отдельные counters для различения "провайдер здоров" vs
	// "инспектор молча пропускает всё из-за timeout'ов". Если
	// обобщать в firewall_decisions_total, эта деградация скроется.
	//
	// Cardinality constraint: provider × model. Для MVP = 2 × ≤3 = 6.
	// НЕ добавлять user/tenant/text-hash — cardinality взорвётся.

	// EmbeddingRequestsTotal — все вызовы client.Embed.
	// Знаменатель для fail-rate: rate(fail+timeout) / rate(requests).
	EmbeddingRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_embedding_requests_total",
		Help: "Total embedding calls to external embedding provider.",
	}, []string{"provider", "model"})

	// EmbeddingFailTotal — transport/HTTP/JSON/shape ошибки.
	// НЕ перекрывается с timeout — timeout идёт в отдельный counter.
	EmbeddingFailTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_embedding_fail_total",
		Help: "Embedding transport/HTTP/parse errors (non-overlapping with timeout).",
	}, []string{"provider", "model"})

	// EmbeddingTimeoutTotal — client.Timeout exceeded.
	// Отдельный counter для alerting (обычно другой response runbook).
	EmbeddingTimeoutTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "shadowai_embedding_timeout_total",
		Help: "Embedding request timeouts (context or client deadline exceeded).",
	}, []string{"provider", "model"})

	// EmbeddingLatencySeconds — latency distribution для success'ных
	// вызовов. Timeout'ы и transport-errors в эту гистограмму НЕ
	// попадают (у них нет смысловой latency). Buckets для embedding
	// API: 50ms .. 10s (embedding обычно быстрее чем LLM completion).
	EmbeddingLatencySeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "shadowai_embedding_latency_seconds",
		Help:    "Embedding API call latency (success only).",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0},
	}, []string{"provider", "model"})
)

// RecordAuditQueue обновляет gauge очереди. Вызывать из периодического
// sampler'а в audit service (или из /metrics handler).
func RecordAuditQueue(depth int) {
	AuditQueueDepth.Set(float64(depth))
}

// RecordFirewallDecision инкрементирует счётчик решений.
// mode — "enforce" | "shadow" (disabled не пишет, не доходит сюда).
func RecordFirewallDecision(phase, inspector, action, mode string) {
	FirewallDecisionsTotal.WithLabelValues(phase, inspector, action, mode).Inc()
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

// RecordStreamingMode — помечает streaming-запрос transport-режимом.
// mode ∈ {"buffered","incremental","shadow"}.
func RecordStreamingMode(mode, provider string) {
	StreamingModeTotal.WithLabelValues(mode, provider).Inc()
}

// RecordStreamingMalformedChunk — decoder не смог распарсить frame.
func RecordStreamingMalformedChunk(provider string) {
	StreamingMalformedChunkTotal.WithLabelValues(provider).Inc()
}

// RecordStreamingEmitFail — emit в downstream writer не удался
// (client disconnect / writer error). Только emit-phase.
func RecordStreamingEmitFail(provider string) {
	StreamingEmitFailTotal.WithLabelValues(provider).Inc()
}

// RecordStreamingDecoderFatal — decoder вернул non-cancel error
// (upstream read failure / parser fatal). Отдельно от emit fails.
func RecordStreamingDecoderFatal(provider string) {
	StreamingDecoderFatalTotal.WithLabelValues(provider).Inc()
}

// RecordStreamingFallback — incremental path downgraded в buffered.
// reason ∈ {"unsupported_provider","decoder_error", ...}.
func RecordStreamingFallback(provider, reason string) {
	StreamingFallbackTotal.WithLabelValues(provider, reason).Inc()
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

// RecordEmbeddingRequest — каждый embed-call (до resolution статуса).
func RecordEmbeddingRequest(provider, model string) {
	EmbeddingRequestsTotal.WithLabelValues(provider, model).Inc()
}

// RecordEmbeddingFail — transport/HTTP/parse ошибка (не timeout).
func RecordEmbeddingFail(provider, model string) {
	EmbeddingFailTotal.WithLabelValues(provider, model).Inc()
}

// RecordEmbeddingTimeout — client.Timeout / context.DeadlineExceeded.
func RecordEmbeddingTimeout(provider, model string) {
	EmbeddingTimeoutTotal.WithLabelValues(provider, model).Inc()
}

// ObserveEmbeddingLatency — только для успешных вызовов.
func ObserveEmbeddingLatency(provider, model string, seconds float64) {
	EmbeddingLatencySeconds.WithLabelValues(provider, model).Observe(seconds)
}

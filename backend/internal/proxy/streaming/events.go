// Package streaming — PR-F7.1: transport-level abstraction для
// provider streaming responses. Разделяет parsing of wire format
// (SSE/NDJSON) от security decisions, accounting и audit (они
// придут в PR-F7.2/F7.3).
//
// Контракт из RFC 2026-04-pr-f7 §8:
//   - decoder читает provider stream и эмитит normalized Event'ы;
//   - для allow path каждый Event.RawBytes обязан быть идентичен
//     оригинальному frame'у провайдера, чтобы emitter мог переслать
//     данные клиенту без re-encoding (bytes-identity preservation);
//   - emitter для non-modified events всегда пишет RawBytes; для
//     sanitize делает provider-specific re-encoding (пока
//     capability-surface, active usage — в F7.2);
//   - emitter поддерживает terminal error frame как transport
//     primitive для будущего mid-stream block в F7.2.
//
// F7.1 сознательно НЕ делает:
//   - security decisions (inspector calls);
//   - audit outcome classification;
//   - budget/accounting changes поверх существующего parseStreamingUsage;
//   - active sanitize rewrite (surface есть, caller'ов нет);
//   - удаление legacy buffered path (остаётся как fallback).
package streaming

// EventType описывает семантический класс normalized event'а.
// Значения совпадают с константами §8.2 RFC и используются для
// диспатча в inspection pipeline'е F7.2.
type EventType string

const (
	// EventDeltaText — фрагмент текстового ответа модели
	// (assistant delta content). Inspection pipeline F7.2 будет
	// собирать из них sliding window.
	EventDeltaText EventType = "delta_text"

	// EventUsageUpdate — частичный или финальный usage report.
	// Accounting side-channel в F7.3 будет собирать эти events.
	// Для emitter'а usage events ВСЕГДА identity — даже если
	// inspection модифицировала соседний delta_text (§8.6 RFC).
	EventUsageUpdate EventType = "usage_update"

	// EventMessageStop — провайдер сигнализирует завершение
	// последнего message'а. Ровно один на stream (если провайдер
	// его шлёт). Для SSE [DONE] sentinel — тоже message_stop.
	EventMessageStop EventType = "message_stop"

	// EventProviderError — структурированная ошибка провайдера
	// внутри stream'а. Emitter передаёт identity, handler layer
	// решает как трактовать (в F7.1 — pass-through).
	EventProviderError EventType = "provider_error"

	// EventUnknownChunk — провайдер прислал событие, не известное
	// adapter'у. Emitter обязан передать RawBytes без попытки
	// распарсить или переписать (identity). Метрика
	// streaming_malformed_chunk_total отмечает факт.
	EventUnknownChunk EventType = "unknown_chunk"
)

// Event — normalized streaming event. Пара decoder/emitter гарантирует
// round-trip identity: emit(decode(X)) == X на canonical fixtures.
//
// Инварианты:
//   - RawBytes всегда заполнен и содержит байты frame'а в том виде,
//     в котором провайдер их прислал (включая терминаторы вроде \n\n
//     для SSE или \n для NDJSON). Это требуется для allow-path
//     identity preservation (§8.6 RFC).
//   - Text заполнен для EventDeltaText и EventProviderError (message);
//     для остальных типов может быть пустым.
//   - Usage заполнен только для EventUsageUpdate.
//   - ProviderErr заполнен только для EventProviderError.
//   - EventName — для SSE провайдеров, использующих `event:` поле
//     (Anthropic). Для data-only SSE (OpenAI, Gemini) и NDJSON
//     (Ollama) — пусто.
//   - Meta — provider-specific служебные поля (например, model из
//     frame'а), которые могут быть полезны в F7.2/F7.3 без
//     re-parsing RawBytes.
type Event struct {
	Type        EventType
	Text        string
	RawBytes    []byte
	EventName   string
	Usage       *Usage
	ProviderErr *ProviderError
	Meta        map[string]string
}

// Usage — локальная minimal копия usage-reporta. Вынесена из
// proxy.StreamUsage, чтобы пакет streaming оставался self-contained
// (не импортировал родительский proxy). Handler-слой конвертирует
// в proxy.StreamUsage когда accounting редизайн пройдёт в F7.3.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	CostUSD          float64
	// Model из frame'а (некоторые провайдеры включают model version в
	// каждый chunk — Anthropic, Gemini). Может быть пусто.
	Model string
}

// ProviderError — структурированная ошибка провайдера внутри stream'а.
// F7.1 адаптеры парсят provider-native error shapes в этот вид;
// handler-слой в F7.1 трактует как identity passthrough.
type ProviderError struct {
	Code    string
	Message string
	// Raw — provider-native bytes ошибки для debugging/audit.
	// В F7.1 дублирует Event.RawBytes; отдельное поле оставлено для
	// возможного использования в F7.3 audit metadata.
	Raw []byte
}

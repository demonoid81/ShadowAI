package proxy

// StreamUsage — результат парсинга usage из буферизованного SSE-ответа.
//
// Семантика Found:
//   - Found=true означает, что в потоке было хотя бы одно usage-поле
//     с осмысленными токенами или cost. Parser может прислать Found=true
//     даже если один из counters равен 0 (например, только output_tokens).
//   - Found=false означает, что usage не пришёл: провайдер не поддерживает
//     include_usage, stream был interrupted до usage chunk'а, или docs
//     не фиксируют наличие usage в stream для этого провайдера.
//
// Found=false НЕ является ошибкой парсинга — это штатный fallback path.
// Handler должен зарегистрировать shadowai_stream_usage_parse_fail_total
// для соответствующего провайдера и продолжить с 0 tokens / 0 cost.
//
// error возвращается только на malformed SSE frames или I/O — то есть
// на случаи, требующие внимания разработчика, а не на отсутствие usage.
type StreamUsage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	CostUSD          float64
	// Model — модель, фактически использованная провайдером (из финального
	// usage chunk'а). Может отличаться от requested — например, OpenRouter
	// может маршрутизировать к другому underlying модели. Может быть "",
	// если провайдер не вернул model в stream.
	Model string
	Found bool
}

// StreamUsageProvider — опциональный interface провайдера, умеющего
// парсить usage из буферизованного SSE-ответа.
//
// Провайдеры, не реализующие этот interface, не ломают streaming —
// parseStreamingUsage() вернёт StreamUsage{Found:false}, handler
// зарегистрирует метрику и продолжит soft-path.
type StreamUsageProvider interface {
	// ParseStreamUsage парсит usage из SSE-body, полностью прочитанного
	// из upstream-response. requestModel — модель, с которой клиент
	// отправил запрос (нужна для pricing lookup, если провайдер не
	// возвращает model в stream).
	//
	// Контракт:
	//   - Нормальный случай: Found=true, поля заполнены.
	//   - Usage отсутствует в stream: Found=false, err=nil. Это ОК.
	//   - Malformed SSE или неожиданный framing: err != nil, Found=false.
	//   - Cost = 0 допустим, если провайдер возвращает usage, но pricing
	//     неизвестен; обратное (cost > 0 при Found=false) запрещено.
	ParseStreamUsage(body []byte, requestModel string) (StreamUsage, error)
}

// parseStreamingUsage — soft-fail helper для handler'ов. Используется
// в streaming-ветках ProxyChat и UnifiedChat вместо provider.ParseResponse
// (ParseResponse ожидает единый JSON и семантически неприменим к
// буферизованному SSE-потоку).
//
// Если провайдер не реализует StreamUsageProvider, возвращает
// StreamUsage{Found:false} без ошибки — migration contract по плану
// Stage 1: провайдеры добавляют поддержку поэтапно, non-supporting
// продолжают работать в soft mode.
func parseStreamingUsage(p Provider, body []byte, requestModel string) (StreamUsage, error) {
	if p == nil {
		return StreamUsage{}, nil
	}
	sp, ok := p.(StreamUsageProvider)
	if !ok {
		return StreamUsage{}, nil
	}
	return sp.ParseStreamUsage(body, requestModel)
}

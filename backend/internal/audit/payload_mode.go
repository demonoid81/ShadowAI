package audit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/pii"
)

// ResolvePIIFindings scan'ит text заново, если caller не передал
// готовые findings. В handler.go findings для request уже посчитаны,
// но для response — нет; fallback scan исключает дублирующий API.
func resolvePIIFindings(text string, existing []pii.Finding) []pii.Finding {
	if existing != nil {
		return existing
	}
	if text == "" {
		return nil
	}
	return pii.Scan(text)
}

// PayloadMode управляет тем, что сохраняется в audit_logs.request_body
// и .response_body (PR-A).
//
//   - PayloadModeNone      — bodies пустые (NULL в DB).
//   - PayloadModeMetadata  — JSON-summary: {"stored":"metadata","bytes":N,...}.
//   - PayloadModeRedacted  — DLP.Sanitize. Fallback в Metadata если DLP=nil.
//   - PayloadModeFull      — сохраняет raw (с truncation до maxAuditBodyChars).
//     Startup warning рекомендуется при этом режиме.
//
// Default для prod — PayloadModeRedacted (secure-by-default).
type PayloadMode string

const (
	PayloadModeNone     PayloadMode = "none"
	PayloadModeMetadata PayloadMode = "metadata"
	PayloadModeRedacted PayloadMode = "redacted"
	PayloadModeFull     PayloadMode = "full"
)

// maxAuditBodyChars — hard cap для Full/Redacted result, чтобы не
// забивать DB гигантскими payload'ами. Значение соответствует лимиту
// в handler.go (перенесено сюда для единой точки контроля).
const maxAuditBodyChars = 4000

// truncMarker дописывается к truncated строкам для визуальной подсказки.
// ASCII, не unicode-ellipsis, чтобы было легко grep'ать и чтобы тесты
// не зависели от terminal encoding.
const truncMarker = "...truncated"

// ParsePayloadMode распознаёт строку case-insensitive + trim. Мусор —
// ошибка (оператор должен видеть опечатку в env).
func ParsePayloadMode(s string) (PayloadMode, error) {
	switch PayloadMode(strings.ToLower(strings.TrimSpace(s))) {
	case PayloadModeNone:
		return PayloadModeNone, nil
	case PayloadModeMetadata:
		return PayloadModeMetadata, nil
	case PayloadModeRedacted:
		return PayloadModeRedacted, nil
	case PayloadModeFull:
		return PayloadModeFull, nil
	default:
		return "", fmt.Errorf("unknown audit payload mode %q (want none|metadata|redacted|full)", s)
	}
}

// TransformBodies применяет PayloadMode к raw request/response bodies
// перед сохранением в audit_logs.
//
// Для Redacted режима требуется валидный dlpSvc + piiFindings — если
// dlpSvc == nil, fallback в Metadata (НЕ в Full: "не уверены = меньше данных").
//
// Возвращает пару строк, готовых к присваиванию log.RequestBody /
// log.ResponseBody.
func TransformBodies(mode PayloadMode, rawReq, rawResp string, dlpSvc *dlp.Service, piiFindings []pii.Finding) (string, string) {
	switch mode {
	case PayloadModeNone:
		return "", ""

	case PayloadModeMetadata:
		return metadataSummary(rawReq, true), metadataSummary(rawResp, false)

	case PayloadModeRedacted:
		if dlpSvc == nil {
			// Fallback: без DLP нельзя гарантировать PII-чистку, лучше
			// деградировать до metadata, чем молча сохранить raw.
			return metadataSummary(rawReq, true), metadataSummary(rawResp, false)
		}
		reqFindings := resolvePIIFindings(rawReq, piiFindings)
		respFindings := resolvePIIFindings(rawResp, nil)
		red := dlpSvc.Sanitize(rawReq, reqFindings)
		respRed := dlpSvc.Sanitize(rawResp, respFindings)
		return truncate(red), truncate(respRed)

	case PayloadModeFull:
		return truncate(rawReq), truncate(rawResp)

	default:
		// Неизвестный mode (не должно случиться после ParsePayloadMode)
		// — fail-safe в None.
		return "", ""
	}
}

// metadataSummary — для requestBody также пытается вытащить messages
// count из JSON body (best-effort). Для response — только bytes.
// Выходной JSON всегда валиден.
func metadataSummary(raw string, includeMessages bool) string {
	meta := map[string]any{
		"stored": "metadata",
		"bytes":  len(raw),
	}
	if includeMessages {
		if n := parseMessagesCount(raw); n > 0 {
			meta["messages"] = n
		}
	}
	b, _ := json.Marshal(meta)
	return string(b)
}

// parseMessagesCount пытается извлечь число сообщений из JSON
// request body (OpenAI-style). Возвращает 0, если body не парсится
// или messages-field нет — это корректный fallback (omitempty в JSON).
func parseMessagesCount(raw string) int {
	var body struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		return 0
	}
	return len(body.Messages)
}

// truncate отрезает до maxAuditBodyChars и добавляет маркер, если
// усечение произошло. Чтобы оператор видел в audit-выгрузке, что
// дальше данные есть, но не были сохранены.
func truncate(s string) string {
	if len(s) <= maxAuditBodyChars {
		return s
	}
	return s[:maxAuditBodyChars] + truncMarker
}

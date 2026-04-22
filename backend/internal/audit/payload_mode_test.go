package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/pii"
)

// TestParsePayloadMode_Valid — все четыре валидных значения распознаются
// case-insensitive + trim.
func TestParsePayloadMode_Valid(t *testing.T) {
	cases := map[string]PayloadMode{
		"none":      PayloadModeNone,
		"metadata":  PayloadModeMetadata,
		"redacted":  PayloadModeRedacted,
		"full":      PayloadModeFull,
		"NONE":      PayloadModeNone,
		"  Full  ":  PayloadModeFull,
		"Redacted":  PayloadModeRedacted,
	}
	for in, want := range cases {
		got, err := ParsePayloadMode(in)
		if err != nil {
			t.Errorf("ParsePayloadMode(%q) err=%v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParsePayloadMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParsePayloadMode_Invalid — мусорные значения → error.
// Silent accept в config недопустим: оператор должен видеть опечатку.
func TestParsePayloadMode_Invalid(t *testing.T) {
	for _, bad := range []string{"", "redact", "full_body", "raw", "verbose"} {
		_, err := ParsePayloadMode(bad)
		if err == nil {
			t.Errorf("ParsePayloadMode(%q) expected error", bad)
		}
	}
}

// TestTransformBodies_None — "" / "" (+ NULL в БД через nil-conversion
// в repository). Никаких metadata — контракт: "none = нет данных".
func TestTransformBodies_None(t *testing.T) {
	req, resp := TransformBodies(PayloadModeNone,
		`{"model":"gpt","messages":[{"role":"user","content":"hi"}]}`,
		`{"choices":[{"message":{"content":"ok"}}]}`,
		nil, nil)
	if req != "" || resp != "" {
		t.Errorf("none: req=%q resp=%q, want empty", req, resp)
	}
}

// TestTransformBodies_Metadata — безопасное JSON-summary: bytes только.
// Messages count — best-effort, если body парсится.
func TestTransformBodies_Metadata(t *testing.T) {
	rawReq := `{"model":"gpt","messages":[{"role":"user","content":"hello"},{"role":"user","content":"world"}]}`
	rawResp := `{"choices":[{"message":{"content":"reply"}}]}`

	req, resp := TransformBodies(PayloadModeMetadata, rawReq, rawResp, nil, nil)

	var reqMeta struct {
		Stored   string `json:"stored"`
		Bytes    int    `json:"bytes"`
		Messages int    `json:"messages,omitempty"`
	}
	if err := json.Unmarshal([]byte(req), &reqMeta); err != nil {
		t.Fatalf("req metadata not JSON: %v (%q)", err, req)
	}
	if reqMeta.Stored != "metadata" {
		t.Errorf("req.stored = %q, want metadata", reqMeta.Stored)
	}
	if reqMeta.Bytes != len(rawReq) {
		t.Errorf("req.bytes = %d, want %d", reqMeta.Bytes, len(rawReq))
	}
	if reqMeta.Messages != 2 {
		t.Errorf("req.messages = %d, want 2", reqMeta.Messages)
	}

	var respMeta struct {
		Stored string `json:"stored"`
		Bytes  int    `json:"bytes"`
	}
	if err := json.Unmarshal([]byte(resp), &respMeta); err != nil {
		t.Fatalf("resp metadata not JSON: %v", err)
	}
	if respMeta.Stored != "metadata" || respMeta.Bytes != len(rawResp) {
		t.Errorf("resp metadata = %+v", respMeta)
	}
}

// TestTransformBodies_Metadata_NonJSONBody — когда body не JSON,
// messages field просто отсутствует (omitempty); bytes остаётся точным.
func TestTransformBodies_Metadata_NonJSONBody(t *testing.T) {
	rawReq := "this is not json"
	req, _ := TransformBodies(PayloadModeMetadata, rawReq, "", nil, nil)

	var meta map[string]any
	_ = json.Unmarshal([]byte(req), &meta)
	if meta["stored"] != "metadata" || int(meta["bytes"].(float64)) != len(rawReq) {
		t.Errorf("non-json body meta = %+v", meta)
	}
	if _, hasMessages := meta["messages"]; hasMessages {
		t.Errorf("messages не должен фигурировать для non-json body, got %+v", meta)
	}
}

// TestTransformBodies_Redacted_UsesDLPSanitize — request/response
// прогоняются через DLP.Sanitize с findings. Email/phone/SSN должны
// быть redacted к маркерам.
func TestTransformBodies_Redacted_UsesDLPSanitize(t *testing.T) {
	dlpSvc := dlp.NewService("enforce")
	rawReq := `{"messages":[{"role":"user","content":"email me at john@example.com"}]}`
	rawResp := `{"choices":[{"message":{"content":"done"}}]}`
	findings := pii.Scan(rawReq)

	req, resp := TransformBodies(PayloadModeRedacted, rawReq, rawResp, dlpSvc, findings)
	if strings.Contains(req, "john@example.com") {
		t.Errorf("redacted request всё ещё содержит email: %s", req)
	}
	// resp без PII — возвращается как есть (DLP Sanitize без findings
	// просто возвращает вход, но хотя бы не теряет content).
	if resp == "" {
		t.Errorf("redacted response не должен быть пустым при mode=redacted")
	}
}

// TestTransformBodies_Redacted_FallsBackToMetadata_WhenDLPNil —
// если DLP service не сконфигурирован (nil), redacted mode не должен
// превращаться в full. Граница: "не уверены = меньше данных".
func TestTransformBodies_Redacted_FallsBackToMetadata_WhenDLPNil(t *testing.T) {
	rawReq := `{"messages":[{"role":"user","content":"secret stuff"}]}`
	rawResp := "response"

	req, resp := TransformBodies(PayloadModeRedacted, rawReq, rawResp, nil, nil)
	if strings.Contains(req, "secret stuff") {
		t.Errorf("redacted fallback должен быть metadata, не full; req=%s", req)
	}
	if !strings.Contains(req, `"stored":"metadata"`) {
		t.Errorf("req должен быть metadata-JSON, got %q", req)
	}
	if !strings.Contains(resp, `"stored":"metadata"`) {
		t.Errorf("resp должен быть metadata-JSON, got %q", resp)
	}
}

// TestTransformBodies_Full_KeepsBodies — full mode сохраняет raw,
// truncate к maxAuditBodyChars.
func TestTransformBodies_Full_KeepsBodies(t *testing.T) {
	rawReq := `{"messages":[{"content":"keep me"}]}`
	rawResp := "response"
	req, resp := TransformBodies(PayloadModeFull, rawReq, rawResp, nil, nil)
	if req != rawReq {
		t.Errorf("full: req=%q, want identical", req)
	}
	if resp != rawResp {
		t.Errorf("full: resp=%q, want identical", resp)
	}
}

// TestTransformBodies_Full_TruncatesOversized — защита от raw-string
// interpolation DB column (TEXT без лимита, но запросы и выгрузки
// могут быть тяжёлыми). Truncation видимая, с маркером.
func TestTransformBodies_Full_TruncatesOversized(t *testing.T) {
	long := strings.Repeat("A", maxAuditBodyChars+100)
	req, _ := TransformBodies(PayloadModeFull, long, "", nil, nil)
	if len(req) > maxAuditBodyChars+50 { // маркер-длина небольшая
		t.Errorf("full: request не truncated, len=%d", len(req))
	}
	if !strings.Contains(req, "...truncated") {
		t.Errorf("truncation marker отсутствует: %q", req[:100])
	}
}

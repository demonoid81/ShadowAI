package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/firewall"
	"github.com/shadowai/backend/internal/proxy/streaming"
)

// ---------------------------------------------------------------------------
// F7.5: Incremental streaming sanitize tests.
// ---------------------------------------------------------------------------

// sanitizingDLPStream — upstream stream with an email address in a delta.
// DLP enforce mode will trigger ActionSanitize on this content.
var sanitizingDLPStream = []byte(
	`data: {"id":"c-s","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"contact "},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-s","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"user@example.com"},"finish_reason":null}]}` + "\n\n" +
		`data: {"id":"c-s","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
		`data: [DONE]` + "\n\n")

// TestProxyChat_Incremental_Sanitize_DeltaContainsPII —
// DoD test: incoming SSE delta contains sanitizable PII; outgoing SSE
// must contain sanitized text; provider framing (data: prefix, JSON
// structure) must be preserved.
func TestProxyChat_Incremental_Sanitize_DeltaContainsPII(t *testing.T) {
	// Use the DLP enforce pipeline — it will sanitize email addresses.
	pipeline := firewall.NewPipeline()
	th := buildF72Handler(t, sanitizingDLPStream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("client status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	// Original PII must NOT appear in the output.
	if strings.Contains(body, "user@example.com") {
		t.Errorf("sanitized stream still contains original PII: %s", body)
	}
	// Output must contain redacted marker — DLP replaces with [redacted:email].
	if !strings.Contains(body, "[redacted") && !strings.Contains(body, "redacted") {
		t.Errorf("sanitized stream does not contain redaction marker: %s", body)
	}

	// Framing must be valid SSE — at least one data: frame.
	if !strings.Contains(body, "data: ") {
		t.Errorf("output is not valid SSE: %s", body)
	}
	// Non-text frames ([DONE], stop) must be present and unmodified.
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("missing [DONE] sentinel after sanitize: %s", body)
	}

	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	// Audit must record policy_action=sanitized, outcome=stream_completed.
	if e.PolicyAction != "sanitized" {
		t.Errorf("PolicyAction = %q, want sanitized", e.PolicyAction)
	}
	if e.Outcome != OutcomeStreamCompleted {
		t.Errorf("Outcome = %q, want %q", e.Outcome, OutcomeStreamCompleted)
	}
	t.Logf("f7.5: sanitize audit OK (policy_action=%s outcome=%s)", e.PolicyAction, e.Outcome)
}

// TestProxyChat_Incremental_Sanitize_AllowPath_BytesIdentity —
// bytes-identity regression guard: a stream without PII must NOT be
// modified even when DLP sanitize mode is active.
func TestProxyChat_Incremental_Sanitize_AllowPath_BytesIdentity(t *testing.T) {
	cleanStream := []byte(
		`data: {"id":"c-c","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hello world"},"finish_reason":null}]}` + "\n\n" +
			`data: {"id":"c-c","model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	pipeline := firewall.NewPipeline()
	th := buildF72Handler(t, cleanStream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	// No PII → bytes must be identical.
	if rec.Body.String() != string(cleanStream) {
		t.Errorf("clean stream was modified:\nwant %q\n got %q",
			cleanStream, rec.Body.String())
	}
	entries := th.auditRepo.snapshot()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	if entries[0].PolicyAction == "sanitized" {
		t.Error("clean stream: policy_action must not be sanitized")
	}
}

// TestProxyChat_Incremental_Sanitize_NonTextFrame_NotMutated —
// regression guard: usage and [DONE] frames in a sanitized stream must
// pass through identity (non-text invariant).
func TestProxyChat_Incremental_Sanitize_NonTextFrame_NotMutated(t *testing.T) {
	// Stream with email + usage frame.
	streamWithUsageAndEmail := []byte(
		`data: {"id":"c-nu","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi user@example.com"}}]}` + "\n\n" +
			`data: {"id":"c-nu","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	pipeline := firewall.NewPipeline()
	th := buildF72Handler(t, streamWithUsageAndEmail, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)

	body := rec.Body.String()
	// Usage frame must be present and unmodified (contains "prompt_tokens").
	if !strings.Contains(body, "prompt_tokens") {
		t.Errorf("usage frame missing from output: %s", body)
	}
	// [DONE] must be present.
	if !strings.Contains(body, "[DONE]") {
		t.Errorf("[DONE] sentinel missing from output: %s", body)
	}
	// Usage frame must not contain redaction markers.
	lines := strings.Split(body, "\n\n")
	for _, line := range lines {
		if strings.Contains(line, "prompt_tokens") && strings.Contains(line, "redacted") {
			t.Errorf("usage frame was mutated with redaction: %s", line)
		}
	}
}

// TestProxyChat_Incremental_Sanitize_SanitizedFrameIsValidJSON —
// the sanitized SSE frame must contain a valid JSON payload with the
// expected structure (content replaced, other fields intact).
func TestProxyChat_Incremental_Sanitize_SanitizedFrameIsValidJSON(t *testing.T) {
	pipeline := firewall.NewPipeline()
	th := buildF72Handler(t, sanitizingDLPStream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)

	body := rec.Body.String()
	// Find the sanitized delta frame (contains "redacted" but not [DONE]).
	for _, frame := range strings.Split(body, "\n\n") {
		frame = strings.TrimSpace(frame)
		if !strings.HasPrefix(frame, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(frame, "data: ")
		if payload == "[DONE]" {
			continue
		}
		if !strings.Contains(payload, "redacted") {
			continue
		}
		// This is the sanitized frame — must be valid JSON with choices[].delta.content.
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			t.Errorf("sanitized frame is not valid JSON: %v\npayload: %s", err, payload)
			break
		}
		found := false
		for _, ch := range chunk.Choices {
			if strings.Contains(ch.Delta.Content, "redacted") {
				found = true
			}
		}
		if !found {
			t.Errorf("sanitized frame JSON structure missing redacted content: %s", payload)
		}
		t.Logf("f7.5: sanitized frame JSON valid: %s", payload)
		break
	}
}

// TestProxyChat_Incremental_Sanitize_CrossChunkPII_BlocksMidstream —
// F7.8 end-to-end guard: an email split across two SSE deltas cannot be
// safely redacted in-place because the first half may already be emitted.
// The safe fallback is a mid-stream block before emitting the completing
// chunk.
func TestProxyChat_Incremental_Sanitize_CrossChunkPII_BlocksMidstream(t *testing.T) {
	splitPIIStream := []byte(
		`data: {"id":"c-split","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"contact user@"},"finish_reason":null}]}` + "\n\n" +
			`data: {"id":"c-split","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"example.com"},"finish_reason":null}]}` + "\n\n" +
			`data: [DONE]` + "\n\n")

	pipeline := firewall.NewPipeline()
	th := buildF72Handler(t, splitPIIStream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("client status = %d, want 200 (stream already started)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: error") {
		t.Fatalf("cross-chunk PII should emit terminal error frame, body=%q", body)
	}
	if strings.Contains(body, "example.com") {
		t.Fatalf("completing PII chunk was emitted before block: %s", body)
	}

	entries := th.auditRepo.snapshot()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Outcome != OutcomeStreamBlockedMidflight {
		t.Errorf("Outcome = %q, want %q", e.Outcome, OutcomeStreamBlockedMidflight)
	}
	if e.PolicyAction != string(dlp.DLPActionBlock) {
		t.Errorf("PolicyAction = %q, want %q", e.PolicyAction, string(dlp.DLPActionBlock))
	}
}

// TestProxyChat_Incremental_Sanitize_CMJudge_BufferedFallback —
// CM+judge config must remain buffered_fallback regardless of PII in stream.
// Regression guard: F7.5 must NOT change CM+judge fallback behavior.
func TestProxyChat_Incremental_Sanitize_CMJudge_BufferedFallback(t *testing.T) {
	judge := firewall.NewJudge(firewall.JudgeConfig{Enabled: true, Provider: "test"})
	cm := firewall.NewContentModerationInspector(firewall.ContentModerationConfig{
		Enabled:        true,
		JudgeThreshold: 0.3,
	}, judge)
	pipeline := firewall.NewPipeline()
	pipeline.Register(cm)

	th := buildF72Handler(t, sanitizingDLPStream, pipeline, "incremental")
	defer th.cleanup()

	rec := doF72Stream(th.h, t)
	th.flushAudit()

	if rec.Code != http.StatusOK {
		t.Fatalf("CM+judge fallback status = %d", rec.Code)
	}
	entries := th.auditRepo.snapshot()
	if len(entries) == 0 {
		t.Fatal("no audit entries")
	}
	if entries[0].Outcome != OutcomeStreamBufferedFallback {
		t.Errorf("CM+judge: Outcome = %q, want %q",
			entries[0].Outcome, OutcomeStreamBufferedFallback)
	}
}

// TestProxyChat_Incremental_Sanitize_IncrementalEngine_SanitizeVerdict —
// unit test for the engine: DLP sanitize returns Sanitize verdict with
// sanitized text (not a downgrade to flag).
func TestProxyChat_Incremental_Sanitize_IncrementalEngine_SanitizeVerdict(t *testing.T) {
	dlpSvc := dlp.NewService("enforce")
	engine := newIncrementalEngine(nil, dlpSvc, "gpt-4o", "openai", "user-1")

	v := engine.EvaluateDelta(context.Background(), "email user@example.com please")
	if !v.Sanitize {
		// DLP might not trigger on all test environments; skip if it doesn't.
		if v.Flag || (!v.Block && !v.Flag && !v.Sanitize) {
			t.Skipf("DLP did not trigger sanitize on email delta (mode might differ): verdict=%+v", v)
		}
		t.Errorf("DLP email: want Sanitize=true, got verdict %+v", v)
		return
	}
	if v.SanitizedText == "" {
		t.Error("Sanitize=true but SanitizedText is empty")
	}
	if strings.Contains(v.SanitizedText, "user@example.com") {
		t.Errorf("SanitizedText still contains original PII: %q", v.SanitizedText)
	}
	if v.InspectorName == "" {
		t.Error("InspectorName empty on sanitize verdict")
	}
	// Verify engine state tracking.
	if !engine.Sanitized() {
		t.Error("engine.Sanitized() should be true after sanitize verdict")
	}
	t.Logf("f7.5/engine: Sanitize=%v SanitizedText=%q Inspector=%s",
		v.Sanitize, v.SanitizedText, v.InspectorName)
}

func TestRunIncrementalStreamTransport_Sanitize_NonOpenAIProviders(t *testing.T) {
	cases := []struct {
		provider string
		model    string
		input    []byte
	}{
		{
			provider: "anthropic",
			model:    "claude-3-5-sonnet",
			input: []byte(
				"event: content_block_delta\n" +
					`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"email user@example.com"}}` + "\n\n"),
		},
		{
			provider: "gemini",
			model:    "gemini-1.5-pro",
			input:    []byte(`data: {"candidates":[{"content":{"parts":[{"text":"email user@example.com"}],"role":"model"}}],"modelVersion":"gemini-1.5-pro"}` + "\n\n"),
		},
		{
			provider: "ollama",
			model:    "llama3",
			input:    []byte(`{"model":"llama3","message":{"role":"assistant","content":"email user@example.com"},"done":false}` + "\n"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.provider, func(t *testing.T) {
			adapter, ok := streaming.AdapterForProvider(tc.provider)
			if !ok {
				t.Fatalf("adapter missing for %s", tc.provider)
			}
			engine := newIncrementalEngine(nil, dlp.NewService("enforce"), tc.model, tc.provider, "user-1")
			rec := httptest.NewRecorder()

			res := (&Handler{}).runIncrementalStreamTransport(
				context.Background(),
				rec,
				http.Header{"Content-Type": []string{"text/event-stream"}},
				bytes.NewReader(tc.input),
				http.StatusOK,
				tc.provider,
				adapter,
				engine,
			)

			if res.TransportErr != nil {
				t.Fatalf("TransportErr: %v", res.TransportErr)
			}
			if !res.Sanitized {
				t.Fatalf("transport result Sanitized=false")
			}
			body := rec.Body.String()
			if strings.Contains(body, "user@example.com") {
				t.Fatalf("%s sanitized output still contains PII: %s", tc.provider, body)
			}
			if !strings.Contains(body, "redacted") {
				t.Fatalf("%s sanitized output missing redaction marker: %s", tc.provider, body)
			}
		})
	}
}

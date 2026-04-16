package proxy

import (
	"errors"
	"strings"
	"testing"
)

// collect обёртка для тестов: собирает все events в слайс.
func collect(body []byte) ([]sseEvent, error) {
	var got []sseEvent
	err := walkSSE(body, func(e sseEvent) error {
		// Копируем Data, чтобы не держать ссылку на буфер.
		data := append([]byte(nil), e.Data...)
		got = append(got, sseEvent{Event: e.Event, Data: data})
		return nil
	})
	return got, err
}

func TestWalkSSE_SingleDataEvent(t *testing.T) {
	body := []byte("data: hello\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if string(got[0].Data) != "hello" {
		t.Errorf("data = %q, want %q", got[0].Data, "hello")
	}
	if got[0].Event != "" {
		t.Errorf("event = %q, want empty (default 'message')", got[0].Event)
	}
}

func TestWalkSSE_MultipleEvents(t *testing.T) {
	body := []byte("data: first\n\ndata: second\n\ndata: third\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("events = %d, want 3", len(got))
	}
	want := []string{"first", "second", "third"}
	for i, w := range want {
		if string(got[i].Data) != w {
			t.Errorf("event[%d] = %q, want %q", i, got[i].Data, w)
		}
	}
}

func TestWalkSSE_MultiLineData(t *testing.T) {
	// Спецификация: два подряд data: склеиваются через \n.
	body := []byte("data: line one\ndata: line two\ndata: line three\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (multi-line data склеивается в одно событие)", len(got))
	}
	want := "line one\nline two\nline three"
	if string(got[0].Data) != want {
		t.Errorf("data = %q, want %q", got[0].Data, want)
	}
}

func TestWalkSSE_Comments(t *testing.T) {
	// OpenRouter шлёт ": OPENROUTER PROCESSING" чтобы connection не закрывался.
	// Такие строки обязаны игнорироваться, а не попадать в data.
	body := []byte(": OPENROUTER PROCESSING\n\ndata: actual\n\n: another comment\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (комментарии не должны эмитить события)", len(got))
	}
	if string(got[0].Data) != "actual" {
		t.Errorf("data = %q, want %q", got[0].Data, "actual")
	}
}

func TestWalkSSE_NamedEvent(t *testing.T) {
	// Anthropic использует named events: message_start, content_block_delta, ...
	body := []byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\nevent: ping\ndata: {}\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2", len(got))
	}
	if got[0].Event != "message_start" {
		t.Errorf("event[0] = %q, want message_start", got[0].Event)
	}
	if got[1].Event != "ping" {
		t.Errorf("event[1] = %q, want ping", got[1].Event)
	}
}

func TestWalkSSE_NoTrailingBlankLine(t *testing.T) {
	// Реальные stream'ы иногда заканчиваются без финальной пустой строки.
	// Parser обязан flush'ить pending event.
	body := []byte("data: hello")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (flush pending на EOF)", len(got))
	}
	if string(got[0].Data) != "hello" {
		t.Errorf("data = %q, want %q", got[0].Data, "hello")
	}
}

func TestWalkSSE_CRLFLineEndings(t *testing.T) {
	// Спецификация допускает \r\n и \r; bufio.Scanner в default режиме
	// корректно обрабатывает \r\n.
	body := []byte("data: hello\r\n\r\ndata: world\r\n\r\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2 (CRLF support)", len(got))
	}
	if string(got[0].Data) != "hello" || string(got[1].Data) != "world" {
		t.Errorf("data = %q, %q; want hello, world", got[0].Data, got[1].Data)
	}
}

func TestWalkSSE_LeadingSpaceStripped(t *testing.T) {
	// Спецификация: "If value starts with a single U+0020 SPACE character,
	// then remove it from value." Только ОДИН пробел.
	cases := []struct {
		in   string
		want string
		desc string
	}{
		{"data: hello\n\n", "hello", "одиночный пробел убирается"},
		{"data:hello\n\n", "hello", "без пробела — как есть"},
		{"data:  double\n\n", " double", "два пробела: убирается только первый"},
		{"data:\t tab_first\n\n", "\t tab_first", "tab — не пробел, не убирается"},
	}
	for _, c := range cases {
		got, err := collect([]byte(c.in))
		if err != nil {
			t.Errorf("[%s] unexpected error: %v", c.desc, err)
			continue
		}
		if len(got) != 1 {
			t.Errorf("[%s] events = %d, want 1", c.desc, len(got))
			continue
		}
		if string(got[0].Data) != c.want {
			t.Errorf("[%s] data = %q, want %q", c.desc, got[0].Data, c.want)
		}
	}
}

func TestWalkSSE_IgnoresIDAndRetry(t *testing.T) {
	body := []byte("id: 42\nretry: 5000\ndata: payload\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	if string(got[0].Data) != "payload" {
		t.Errorf("data = %q, want %q (id/retry должны игнорироваться)", got[0].Data, "payload")
	}
}

func TestWalkSSE_UnknownField(t *testing.T) {
	// Неизвестные поля игнорируются (whatwg spec).
	body := []byte("foo: bar\ndata: payload\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Data) != "payload" {
		t.Errorf("unknown field должен игнорироваться; got=%+v", got)
	}
}

func TestWalkSSE_LineWithoutColon(t *testing.T) {
	// Спецификация: line без ":" — это поле с пустым значением.
	// Не должно ломать parser.
	body := []byte("data\ndata: after\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	// "data" без значения добавляет "", потом "after" → склейка "\nafter"
	want := "\nafter"
	if string(got[0].Data) != want {
		t.Errorf("data = %q, want %q", got[0].Data, want)
	}
}

// TestWalkSSE_EventWithoutDataNotDispatched — WHATWG EventSource spec §9.2.6:
// если data buffer пустой, dispatch НЕ происходит. Только сбрасывается state.
//
// Практический случай: Anthropic может прислать "event: ping\n\n" keepalive
// без data; provider parser не должен получить спуриозный empty event.
func TestWalkSSE_EventWithoutDataNotDispatched(t *testing.T) {
	body := []byte("event: ping\n\ndata: real\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (event: без data: не должно dispatch'иться)", len(got))
	}
	if got[0].Event != "" {
		t.Errorf("event = %q, want '' (ping не должен остаться в state)", got[0].Event)
	}
	if string(got[0].Data) != "real" {
		t.Errorf("data = %q, want 'real'", got[0].Data)
	}
}

// TestWalkSSE_EventWithEmptyDataDispatched — регрессия-guard для границы:
// "event: x\ndata:\n\n" имеет data:-строку (пусть с пустым value),
// поэтому dispatch ДОЛЖЕН произойти.
func TestWalkSSE_EventWithEmptyDataDispatched(t *testing.T) {
	body := []byte("event: message_stop\ndata:\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1 (data: даже с пустым value → dispatch)", len(got))
	}
	if got[0].Event != "message_stop" {
		t.Errorf("event = %q, want message_stop", got[0].Event)
	}
	if string(got[0].Data) != "" {
		t.Errorf("data = %q, want empty", got[0].Data)
	}
}

func TestWalkSSE_EmptyBody(t *testing.T) {
	got, err := collect(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("events = %d, want 0 для пустого body", len(got))
	}
}

func TestWalkSSE_OnlyComments(t *testing.T) {
	body := []byte(": keepalive\n: another\n\n")
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("events = %d, want 0 (только comments)", len(got))
	}
}

func TestWalkSSE_CallbackErrorStops(t *testing.T) {
	body := []byte("data: first\n\ndata: second\n\ndata: third\n\n")
	target := errors.New("stop")
	count := 0
	err := walkSSE(body, func(e sseEvent) error {
		count++
		if count == 2 {
			return target
		}
		return nil
	})
	if err != target {
		t.Errorf("err = %v, want %v", err, target)
	}
	if count != 2 {
		t.Errorf("processed %d events, want 2 (остановка на error от callback)", count)
	}
}

func TestWalkSSE_OpenAICompatRealFrame(t *testing.T) {
	// Hand-crafted — близко к реальному OpenAI SSE: несколько delta
	// chunks и финальный usage chunk перед [DONE].
	body := []byte(
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" +
			"data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n" +
			"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n" +
			"data: [DONE]\n\n",
	)
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("events = %d, want 4", len(got))
	}
	// [DONE] всё ещё приходит в data — parser-уровень не обязан его
	// интерпретировать. Это забота provider-specific parser'а.
	if !strings.Contains(string(got[3].Data), "[DONE]") {
		t.Errorf("expected [DONE] in last event, got %q", got[3].Data)
	}
	// Usage chunk должен содержать поле usage.
	if !strings.Contains(string(got[2].Data), "\"usage\"") {
		t.Errorf("expected usage in 3rd event, got %q", got[2].Data)
	}
}

func TestWalkSSE_AnthropicRealFrame(t *testing.T) {
	// Hand-crafted Anthropic-style: named events + JSON data.
	body := []byte(
		"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10}}}\n\n" +
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"hi\"}}\n\n" +
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n" +
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
	)
	got, err := collect(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("events = %d, want 4", len(got))
	}
	wantEvents := []string{"message_start", "content_block_delta", "message_delta", "message_stop"}
	for i, we := range wantEvents {
		if got[i].Event != we {
			t.Errorf("event[%d] = %q, want %q", i, got[i].Event, we)
		}
	}
}

package streaming

import (
	"context"
	"io"
)

// Emitter пишет normalized Event'ы обратно в provider-compatible
// wire format (SSE или NDJSON).
//
// Контракт (PR-F7.1, соответствие RFC §8.6):
//
//   1. Allow / identity path — если Event.RawBytes непустой и не
//      был модифицирован inspection'ом, emitter ОБЯЗАН записать
//      именно RawBytes без re-encoding. Это safety-critical
//      (RFC §8.6 bytes-identity preservation): re-encoding может
//      поломать незнакомые provider-specific поля, которые decoder
//      пропускает как unknown. F7.1 реализует именно этот
//      identity-first путь для всех Event-типов.
//
//   2. Sanitize path — capability surface присутствует, но активно
//      НЕ используется в F7.1. PR-F7.2 введёт вызовы emitter'а с
//      модифицированным Event.Text; тогда adapter обязан собрать
//      новый valid frame в том же wire format, сохранив event name,
//      id и non-text JSON-поля. Реализация sanitize-re-encode —
//      ответственность конкретного adapter'а; общая заглушка
//      EmitSanitized (если нужна будет) пока не добавляется, чтобы
//      не зафиксировать API до F7.2.
//
//   3. Block / terminal error — EmitError пишет provider-specific
//      terminal error frame + сигнал завершения. Для SSE:
//      `event: error\ndata: {...}\n\n`. Для NDJSON: одна строка JSON
//      с error payload + `\n`. Это transport primitive для F7.2
//      mid-stream block; в F7.1 caller'ов нет, но тест coverage
//      обязателен (round-trip и unit).
//
//   4. Flush — каждый Emit обязан убедиться, что bytes доставлены
//      клиенту немедленно, если writer реализует http.Flusher.
//      Это требование real-time UX из RFC §7.1.
type Emitter interface {
	// Emit пишет Event в w. По умолчанию — identity (RawBytes).
	// sanitize mode активируется в F7.2 через отдельный call path
	// (или расширение этого метода); в F7.1 Emit всегда identity.
	Emit(ctx context.Context, w io.Writer, ev Event) error

	// EmitError пишет terminal error frame. code — machine-readable
	// идентификатор ошибки (например, "blocked", "upstream_error"),
	// message — user-visible текст. После вызова EmitError никаких
	// последующих Emit на том же writer'е делать не следует —
	// connection должен быть закрыт caller'ом.
	EmitError(ctx context.Context, w io.Writer, code, message string) error
}

// flushIfPossible — helper для adapter'ов. Если writer реализует
// http.Flusher (httptest.ResponseRecorder или http.ResponseWriter в
// prod), вызывает Flush. Тихо игнорирует если не реализует
// (io.Discard, bytes.Buffer в тестах).
func flushIfPossible(w io.Writer) {
	type flusher interface{ Flush() }
	if f, ok := w.(flusher); ok {
		f.Flush()
	}
}

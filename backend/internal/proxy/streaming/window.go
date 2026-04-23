package streaming

// InspectionWindow — bounded sliding буфер над delta_text events.
// Используется incremental inspection engine (F7.2) как context для
// pattern-matching inspector'ов (PII, DLP, OutputValidation): они
// видят не только последний chunk, но и несколько предыдущих bytes,
// чтобы matching не ломался на границах chunk'ов (secret, размазанный
// через 2-3 frame'а).
//
// Window хранит два состояния:
//   - Sliding window (ограничен WindowCap): последние N bytes
//     delta_text. Именно на нём работает inspector.
//   - Accumulated full text (ограничен AccumCap): всё, что успело
//     прийти за stream. Используется для audit finalization, если
//     понадобится. Ограничение защищает от DoS длинных стримов.
//
// F7.1 invariant не затрагивается: window работает только на
// streaming.Event.Text, не на RawBytes. Emitter'ская bytes-identity
// сохраняется отдельно.
type InspectionWindow struct {
	WindowCap int
	AccumCap  int

	window     []byte
	accumulated []byte
}

// NewInspectionWindow. Дефолты подобраны консервативно: 8 KiB window
// покрывает cross-chunk matching для известных secret/PII паттернов
// (API keys ≤ 64 chars, SSN 11 chars, credit cards 16-19 chars).
// 256 KiB accumulated cap — ограничение на size одного streaming
// response'а, за которое мы готовы заплатить memory'ю ради audit
// fidelity.
func NewInspectionWindow() *InspectionWindow {
	return &InspectionWindow{
		WindowCap: 8 * 1024,
		AccumCap:  256 * 1024,
	}
}

// Append добавляет delta text. Window и accumulated усекаются с
// начала, если переваливают через cap — это стандартный trailing-N
// semantic sliding window.
func (w *InspectionWindow) Append(delta string) {
	if delta == "" {
		return
	}
	b := []byte(delta)
	w.window = append(w.window, b...)
	if len(w.window) > w.WindowCap {
		drop := len(w.window) - w.WindowCap
		w.window = w.window[drop:]
	}
	w.accumulated = append(w.accumulated, b...)
	if len(w.accumulated) > w.AccumCap {
		drop := len(w.accumulated) - w.AccumCap
		w.accumulated = w.accumulated[drop:]
	}
}

// Window возвращает текущий sliding window как string. Inspector
// работает на нём. Безопасно вызывать concurrently с Append'ом
// НЕЛЬЗЯ — caller обеспечивает serialization (в proxy каждый stream
// обслуживается одной goroutine).
func (w *InspectionWindow) Window() string {
	return string(w.window)
}

// Accumulated возвращает полный накопленный text (до AccumCap).
func (w *InspectionWindow) Accumulated() string {
	return string(w.accumulated)
}

// Len возвращает текущий размер sliding window'а (не accumulated).
func (w *InspectionWindow) Len() int {
	return len(w.window)
}

package proxy

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

// sseEvent — один обработанный SSE event после склейки multi-line data:
// и применения правил парсинга из whatwg EventSource spec.
//
// Для наших целей значимы только два поля:
//   - Event — имя из event:, может быть пустым (default "message")
//   - Data — полное содержимое data:, для multi-line склеено через \n
//
// id:, retry:, comments (строки, начинающиеся с ":") — игнорируются.
// [DONE] sentinel не обрабатывается на этом уровне — это семантика
// конкретного провайдера (OpenAI/OpenRouter/Groq/Mistral), parser
// принимает решение пропустить такие data-фреймы.
type sseEvent struct {
	Event string
	Data  []byte
}

// walkSSE проходит SSE-поток и вызывает fn для каждого завершённого
// event. Соответствует https://html.spec.whatwg.org/multipage/server-sent-events.html
// в объёме, достаточном для LLM-провайдеров:
//
//   - Событие завершается пустой строкой (\n\n или \r\n\r\n).
//   - Строка ": ..." — comment, игнорируется (сохраняет SSE-coneзс от прокси
//     типа OpenRouter, которые шлют ": OPENROUTER PROCESSING").
//   - "data:" + value — данные (multi-line склеиваются через \n).
//   - "event:" + value — имя события, применяется к следующему flush.
//   - Остальные поля (id, retry) — игнорируются.
//   - Терминирующая пустая строка в конце НЕ обязательна; если поток
//     закончился без неё, pending event всё равно flush'ится.
//
// Если fn вернул error, обход останавливается и error пробрасывается.
// I/O ошибки bufio.Scanner пробрасываются как есть.
func walkSSE(body []byte, fn func(sseEvent) error) error {
	sc := bufio.NewScanner(bytes.NewReader(body))
	// Увеличенный буфер: SSE-фреймы с LLM-ответами бывают длиннее
	// default 64KB (single chunk может содержать delta + usage).
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		curEvent string
		curData  []string
	)

	flush := func() error {
		// WHATWG EventSource spec §9.2.6: если data buffer пустой (не
		// было ни одной "data:" строки), событие НЕ dispatch'ится —
		// state просто сбрасывается. Одинокое "event: ping\n\n"
		// обновляет event type buffer, но callback не вызывается.
		if len(curData) == 0 {
			curEvent = ""
			return nil
		}
		ev := sseEvent{
			Event: curEvent,
			Data:  []byte(strings.Join(curData, "\n")),
		}
		curEvent = ""
		curData = curData[:0]
		return fn(ev)
	}

	for sc.Scan() {
		line := sc.Text()

		// Пустая строка — граница события.
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}

		// Comment. Спецификация: строка, начинающаяся с ":".
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Разделитель поле/значение — первое двоеточие.
		colon := strings.IndexByte(line, ':')
		var field, value string
		if colon < 0 {
			// Line without colon: всё имя поля, значение пустое.
			field = line
			value = ""
		} else {
			field = line[:colon]
			value = line[colon+1:]
			// Спецификация: единственный ведущий пробел отбрасывается.
			if strings.HasPrefix(value, " ") {
				value = value[1:]
			}
		}

		switch field {
		case "data":
			curData = append(curData, value)
		case "event":
			curEvent = value
		case "id", "retry":
			// Не нужны для usage parsing.
		default:
			// Unknown field — игнорируем (whatwg spec предписывает это же).
		}
	}

	if err := sc.Err(); err != nil && err != io.EOF {
		return err
	}

	// Flush pending event, если поток закончился без терминирующей blank line.
	return flush()
}

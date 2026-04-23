package streaming

import (
	"bufio"
	"bytes"
	"io"
)

// sseFrame — один законченный SSE frame в той форме, в которой он
// пришёл от провайдера. Адаптеры (openai_compat, anthropic, gemini)
// берут frame и мапят его на streaming.Event.
//
// Отличия от walkSSE из stream_usage_sse.go:
//   - этот reader ОБЯЗАН сохранять raw bytes frame'а (включая
//     терминирующую blank line и все \n), чтобы emitter мог
//     переслать frame byte-to-byte (RFC §8.6 identity preservation);
//   - walkSSE читает через bufio.Scanner и теряет line endings, что
//     для accounting OK, но для transport-identity недопустимо.
type sseFrame struct {
	// Raw — все bytes frame'а как пришли с провайдера, включая
	// терминирующую пустую строку. Пустой Raw означает, что frame
	// был пустой (две blank lines подряд) — caller должен игнорировать.
	Raw []byte
	// EventName — значение `event:` поля, если было. Для data-only
	// SSE (OpenAI / Gemini) всегда пусто.
	EventName string
	// Data — склеенное значение `data:` полей (multi-line frame'ы
	// объединены через \n). Префикс "data: " и ведущий пробел уже
	// убраны.
	Data []byte
	// Comment — true, если frame содержал ТОЛЬКО comment-строки
	// (начинающиеся с ":"). Такие frame'ы используются некоторыми
	// провайдерами (OpenRouter "OPENROUTER PROCESSING") как
	// keepalive. Adapter может эмитить их как EventUnknownChunk с
	// RawBytes для identity passthrough.
	Comment bool
}

// readSSEFrames читает SSE поток из r и вызывает fn для каждого
// завершённого frame'а. Frame завершается пустой строкой (`\n` или
// `\r\n` на пустой строке после data/event полей).
//
// WHATWG EventSource spec соответствие:
//   - multi-line `data:` поля склеиваются через `\n`;
//   - строки, начинающиеся с `:`, — comments;
//   - поля id/retry распознаются, но игнорируются в Data/EventName;
//   - неизвестные поля пропускаются;
//   - если поток заканчивается без терминирующей blank line,
//     pending frame всё равно flush'ится.
//
// Returns:
//   - nil после успешного чтения всего потока;
//   - error от fn — если fn вернул non-nil (abort-path);
//   - error от reader'а — кроме io.EOF, который трактуется как
//     конец потока.
//
// Buffer size: 1 MiB на строку (достаточно для delta+usage в одном
// chunk'е у любого известного провайдера).
func readSSEFrames(r io.Reader, fn func(sseFrame) error) error {
	br := bufio.NewReaderSize(r, 1024*1024)

	var (
		frameRaw    bytes.Buffer
		dataLines   [][]byte
		eventName   string
		onlyComment = true
	)

	reset := func() {
		frameRaw.Reset()
		dataLines = dataLines[:0]
		eventName = ""
		onlyComment = true
	}

	flush := func() error {
		// Пустой frame без полей — ничего не делаем.
		if frameRaw.Len() == 0 {
			return nil
		}
		// Собираем Data из накопленных data-lines (склеиваем \n).
		var data []byte
		if len(dataLines) > 0 {
			data = bytes.Join(dataLines, []byte{'\n'})
		}
		f := sseFrame{
			Raw:       append([]byte(nil), frameRaw.Bytes()...),
			EventName: eventName,
			Data:      data,
			Comment:   onlyComment && len(dataLines) == 0,
		}
		err := fn(f)
		reset()
		return err
	}

	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			// Всегда добавляем в raw frame, включая blank line.
			frameRaw.Write(line)

			// Удаляем terminator для field parsing: поддерживаем
			// \r\n и \n.
			trimmed := line
			if n := len(trimmed); n > 0 && trimmed[n-1] == '\n' {
				trimmed = trimmed[:n-1]
			}
			if n := len(trimmed); n > 0 && trimmed[n-1] == '\r' {
				trimmed = trimmed[:n-1]
			}

			if len(trimmed) == 0 {
				// Blank line — граница frame'а.
				if err := flush(); err != nil {
					return err
				}
			} else if trimmed[0] == ':' {
				// Comment. Не снимает onlyComment flag.
			} else {
				onlyComment = false
				// Разбираем field: value (первое двоеточие).
				colon := bytes.IndexByte(trimmed, ':')
				var field, value []byte
				if colon < 0 {
					field = trimmed
					value = nil
				} else {
					field = trimmed[:colon]
					value = trimmed[colon+1:]
					// WHATWG: единственный ведущий пробел обрезается.
					if len(value) > 0 && value[0] == ' ' {
						value = value[1:]
					}
				}
				switch string(field) {
				case "data":
					dataLines = append(dataLines, append([]byte(nil), value...))
				case "event":
					eventName = string(value)
				case "id", "retry":
					// Распознаём, но игнорируем для наших целей.
				default:
					// Неизвестное поле — WHATWG предписывает игнорировать.
				}
			}
		}
		if err != nil {
			if err == io.EOF {
				// Если стрим закончился без терминирующей blank line —
				// всё равно flush pending frame.
				return flush()
			}
			return err
		}
	}
}

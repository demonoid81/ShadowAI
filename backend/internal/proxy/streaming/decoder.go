package streaming

import (
	"context"
	"io"
)

// Decoder читает provider streaming response из io.Reader и
// эмитит normalized Event'ы через callback `emit`.
//
// Контракт (PR-F7.1):
//   - каждый Event.RawBytes содержит байты исходного frame'а в
//     том виде, в котором провайдер их прислал (identity-preservation
//     на стороне decoder'а);
//   - decoder НЕ принимает security decisions — никогда не фильтрует,
//     не модифицирует, не агрегирует events; вся такая логика — в
//     inspection pipeline F7.2;
//   - decoder honor'ит ctx.Done() и возвращает ctx.Err() если
//     reader блокирован на момент cancel'а;
//   - если emit callback возвращает error — decoder останавливается
//     и пробрасывает error вверх (abort path);
//   - io.EOF НЕ является error: стрим просто завершён;
//   - malformed frame'ы эмитятся как EventUnknownChunk с RawBytes,
//     содержащим "сырой" проблемный кусок; инкремент соответствующей
//     метрики — ответственность caller'а (handler), чтобы decoder
//     оставался чистым от инфраструктуры.
type Decoder interface {
	Decode(ctx context.Context, r io.Reader, emit func(Event) error) error
}

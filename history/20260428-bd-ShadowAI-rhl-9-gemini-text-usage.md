# bd ShadowAI-rhl.9 — Gemini text+usage streaming inspection

## Контекст

После F7.7 review найден edge case в Gemini adapter: один SSE frame может
содержать и `usageMetadata`, и `candidates[].content.parts[].text`. Старый
decoder отдавал такой frame как `EventUsageUpdate`, поэтому incremental
response-side inspection не видел текст.

## Цель

Сделать text+usage frame inspection-first: если в Gemini frame есть text, он
должен стать `EventDeltaText`, пройти sanitize/block/flag path и при этом
сохранить `RawBytes` для identity emit и downstream accounting.

## Scope In

- Red test на Gemini text+usage classification.
- Regression на sanitize rewrite для text+usage frame.
- Минимальное изменение ordering внутри Gemini decoder.

## Scope Out

- Общая dual-role Event model.
- Cross-chunk PII sanitize.

## Размышления

Рассмотрены варианты:

- Оставить usage priority как есть — отклонено: text bypasses inspection.
- Эмитить два events на один RawBytes frame — отклонено: нарушит one frame →
  one emit identity invariant.
- Классифицировать text+usage как `EventDeltaText` и сохранить `Usage` внутри
  event — принято: transport пишет frame один раз, inspection видит text, а
  accumulated raw bytes всё равно доступны parser/accounting layer.

## Проверка

- `go test ./internal/proxy/streaming ./internal/proxy -count=1`
- `go test -tags enterprise ./... -count=1`
- `go test ./... -count=1`
- `git diff --check`

## Результат реализации

- Gemini decoder теперь сначала извлекает text из candidates.
- Если text непустой, frame классифицируется как `EventDeltaText` даже при
  наличии `usageMetadata`.
- `Event.Usage` сохраняется на delta event, чтобы metadata не терялась.
- Usage-only final frame остаётся прежним usage path.
- Sanitize test подтверждает, что text+usage frame редактируется и сохраняет
  `usageMetadata`.

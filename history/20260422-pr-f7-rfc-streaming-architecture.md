# PR-F7-RFC — Streaming Architecture RFC

**Дата:** 2026-04-22
**Ветка:** `pr-l2-3-four-eyes-approver` (RFC-документ коммитится вместе
с текущей веткой; в отдельном PR-F7 branch не нуждается — чисто
document artifact).
**Artefact:** `docs/rfcs/2026-04-pr-f7-streaming-architecture.md`

---

## Контекст

Пользователь запросил оформить RFC для перехода от fully-buffered
streaming path к bounded / incremental streaming для ShadowAI proxy.
Предоставил готовый скелет с 18-ю разделами и списком решений,
которые должны быть зафиксированы (Stage 1 boundaries, provider
matrix, budget/audit/rollout contracts).

## Цель

Зафиксировать:

1. Current behavior на ссылках на реальный код (не описательно).
2. Hard invariants, которые не должна нарушать любая реализация.
3. Target semantics для allow/flag/block/sanitize с явными Stage 1
   ограничениями.
4. Provider coverage matrix с mapping на текущие `stream_usage_*.go`
   парсеры.
5. Commit criterion для удаления legacy buffered path.

## Выполненные работы

- верифицирован текущий streaming path в коде:
  - `backend/internal/proxy/handler.go:430-576` — ProxyChat
    streaming branch (buffered);
  - `backend/internal/proxy/handler.go:1466-1600+` — UnifiedChat
    streaming branch (buffered, same pattern);
  - `handler.go:440`, `handler.go:1467` — точки `io.ReadAll`;
  - `handler.go:522-527` — `parseStreamingUsage` + soft-fail metric;
  - `internal/proxy/stream_usage_sse.go` — существующий
    WHATWG-compliant SSE walker;
- инвентаризированы providers (`provider_*.go`) и stream-usage
  parsers (`stream_usage_*.go`);
- инвентаризированы response-side firewall inspectors
  (`firewall/*.go` с `InspectResponse`);
- создан `docs/rfcs/` как новый каталог под RFC-документы;
- написан RFC с 21 разделом, включающими все пункты acceptance
  criteria пользователя;
- провайдер-матрица расписана с текущим mapping на parser-файлы и
  Stage 1 статусом (Ollama явно помечен upgrade path — нет
  отдельного stream-usage parser'а, Stage 1 PR обязан добавить).

## Принятые решения (зафиксированы в RFC §21)

1. Stage 1 не пытается "идеально" sanitize — только deterministic
   chunk-local transforms; прочее → flag или buffered_fallback.
2. Mid-stream block рвёт upstream и downstream немедленно, не ждёт
   EOF.
3. Streaming cache не трогаем (cache.ShouldCache уже исключает
   stream=true).
4. Legacy buffered path остаётся как fallback per-provider и
   per-inspector; видимость через `streaming_mode_total` метрику и
   `stream_buffered_fallback` audit outcome.
5. Legacy branch (`handler.go:430-576` и `handler.go:1466-1600+`)
   удаляется только по commit criterion §13.4 — 5 условий, включая
   production-traffic-проверку в ≥ 30 дней на нуль-fallback.

## Рассмотренные альтернативы

- Keep fully-buffered: отклонено (UX, hardened-default ambitions).
- Fully passthrough + post-hoc audit: отклонено (security regression).
- Incremental + bounded fallback: выбран подход Stage 1.
- SSE→WebSocket rewrite: out-of-scope F7.

## Open questions, которые RFC сознательно оставляет на implementation PR'ы

- точный список inspector'ов, совместимых с incremental-safe Stage 1
  (PR-F7.2);
- multi-chunk secret sanitize policy (PR-F7.2);
- exact client-visible behavior на mid-stream block — SSE error event
  vs HTTP trailer (предпочтение: SSE `event: error`, фиксируется в
  PR-F7.1);
- приоритет `usage_update` vs `message_stop` в single-frame edge case
  (PR-F7.1);
- граница между `buffered_fallback` и `hard deny unsupported`
  (Stage 2).

## Definition of Done для RFC

- [x] Файл `docs/rfcs/2026-04-pr-f7-streaming-architecture.md`
      создан.
- [x] Все 7 acceptance criteria пользователя (§20 RFC) закрыты
      явными ссылками на разделы RFC.
- [x] Provider matrix с mapping на существующие parser-файлы.
- [x] Commit criterion для legacy removal зафиксирован.
- [x] Current-behavior ссылается на реальные file:line, а не
      описательно.
- [ ] Commit + merge в feature-ветку.

## Примечания

RFC-документ *artefact-only* — кода не меняет. Реализация будет в
серии implementation PR-ов (PR-F7.1 через PR-F7.4+, §19 RFC).
Текущая ветка `pr-l2-3-four-eyes-approver` фиксирует его в истории
вместе с PR-L2.3 / PR-L2.3.1 artefacts, потому что отдельный PR-F7
branch для чисто документационного изменения был бы overhead.

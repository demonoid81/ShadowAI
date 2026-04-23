# RFC: PR-F7 — Streaming Architecture for Real-Time LLM Firewall

| Field   | Value                                                                             |
|---------|-----------------------------------------------------------------------------------|
| Status  | Draft                                                                             |
| Date    | 2026-04-22                                                                        |
| Owners  | ShadowAI maintainers                                                              |
| Scope   | `backend/internal/proxy`, `backend/internal/firewall`, streaming request/response |
| Related | PR-4 (inspector modes), PR-6 (semantic_v2), PR-S1 (SIEM), PR-G1/G2 (governance)   |

---

## 1. Summary

Этот RFC описывает переход от текущего **fully-buffered streaming path**
(`backend/internal/proxy/handler.go:430-576` для `ProxyChat` и
`handler.go:1466-1600+` для `UnifiedChat`) к **bounded / incremental
streaming architecture** для ShadowAI proxy.

Цели:

- сохранить security guarantees для response-side firewall и DLP;
- убрать latency penalty текущего streaming path (tpg-to-first-byte ≈
  полное время генерации upstream'а);
- не сломать budget/accounting/audit invariants, установленные
  PR-F5/PR-F6;
- подготовить базу для hardened default в broader runtime product.

---

## 2. Problem

Сейчас streaming response:

1. полностью читается из upstream (`io.ReadAll(resp.Body)` в
   `handler.go:440` и `handler.go:1467`);
2. целиком сканируется firewall (`firewallPipeline.InspectResponse`,
   `handler.go:454`);
3. целиком сканируется DLP (`dlp.Evaluate` + `pii.Scan`,
   `handler.go:487-488`);
4. только потом отправляется клиенту (`w.Write(responsePayload)`,
   `handler.go:575`).

Это обеспечивает strong safety (never-leak semantics), но ломает
real-time UX и не соответствует target-state для production-grade
streaming firewall. Handler явно предупреждает о compromise'e в
комментарии `handler.go:431-439`:

> ВНИМАНИЕ: текущая реализация streaming НЕ является real-time
> passthrough.

RFC фиксирует архитектуру замещения без потери инвариантов.

---

## 3. Goals

- дать real-time или near-real-time streaming passthrough для
  безопасных ответов;
- сохранить enforcement для response-side threats (harmful content,
  secrets leak, PII);
- сохранить provider-agnostic proxy model (SSE + NDJSON adapters);
- сохранить корректный budget accounting (PR-F5 `parseStreamingUsage`
  контракт);
- сохранить корректный audit trail с явной разметкой outcome'ов;
- дать staged rollout path с возможностью per-provider/per-inspector
  fallback'а на buffered поведение.

---

## 4. Non-Goals

Явно вне scope этого RFC и всей F7-серии:

- tool / MCP / agent security;
- tenant isolation;
- streaming cache (см. `cache.ShouldCache` — streaming уже исключён,
  не трогаем);
- переписывание всех provider adapters;
- полная re-architecture policy / governance layer;
- vendor-specific UI changes;
- response cache или response replay поверх streaming;
- SSE-to-WebSocket или HTTP/3 server push rewrites.

---

## 5. Current Behavior

### 5.1 Request path

Request-side уже enforce-safe: firewall → DLP → policy → budget
выполняются **до** upstream call. Для streaming контракт тот же
(`handler.go:350-428` приблизительно). Этот RFC request-side
поведение не меняет.

### 5.2 Response streaming path (state of `master`)

Обе ветви (`ProxyChat` и `UnifiedChat`) реализуют идентичный pipeline
при `chatReq.Stream=true`:

1. `io.ReadAll(resp.Body)` — буферизация всего upstream-stream
   (`handler.go:440`, `handler.go:1467`).
2. `firewallPipeline.InspectResponse` на полном буфере.
3. `shadowDecisions` append (для audit только).
4. `pii.Scan` + `dlpSvc.Evaluate` на полном буфере.
5. `mergePolicyAction` + flag correlation.
6. `dlpSvc.Sanitize` (если нужно) на полном буфере.
7. `parseStreamingUsage(provider, respBytes, model)` — SSE/NDJSON
   parser извлекает usage из буфера. Soft-fail: `Found=false`
   отмечается метрикой, не является ошибкой.
8. `budgetSvc.CheckBudgetAfterUsage` — post-call accounting.
9. `auditLog` с финальным outcome + `w.Write(responsePayload)`.

### 5.3 Current strengths

- never-leak semantics для response block/sanitize гарантированы
  временным порядком (inspect → write);
- единая reasoning model;
- единый audit-site, без state machine для partial outcome'ов;
- provider accounting работает на полном stream buffer — parser не
  держит state.

### 5.4 Current weaknesses

- нет real-time chunk delivery: TTFB ≈ время полной генерации
  upstream;
- память O(N) на полный response (возможна атакуемая деградация на
  long-context моделях);
- хуже UX для long outputs;
- сложнее позиционировать как hardened runtime firewall для регулируемых
  enterprise-клиентов.

---

## 6. Hard Invariants

Следующие свойства **нельзя потерять** ни в Stage 1, ни в Stage 2:

1. **Safety**: harmful response не должен утечь из-за нового
   streaming path. Любой chunk, который был бы заблокирован в текущем
   full-buffer pipeline, должен быть либо заблокирован здесь, либо
   явно классифицирован как `buffered_fallback`.
2. **Budget**: accounting должен остаться корректным для all-normal
   случаев; mid-stream block должен иметь deterministic accounting
   policy (см. §10).
3. **Audit**: trail должен оставаться консистентным. Каждый stream
   должен завершиться ровно одной `audit_log` записью с явным
   outcome.
4. **Governance / policy**: decisions остаются before-upstream
   (request path не меняется).
5. **Provider compatibility**: SSE / NDJSON семантика не деградирует
   silently. Любой новый баг в парсере должен быть наблюдаемым через
   метрику и, если он приводит к misclassification, переводить
   provider на `buffered_fallback`.
6. **Legacy fallback**: buffered path остаётся **explicit** (явный
   флаг или per-provider/per-inspector решение), а не implicit. Commit
   criterion для удаления — см. §13.4.

---

## 7. Target Semantics

Действия inspector'а — уже существующие `firewall.Action*` /
`dlp.DLPAction*` — в streaming path трактуются следующим образом:

### 7.1 Allow

- safe chunks передаются downstream **без ожидания полного
  завершения stream**;
- inspector может быть вызван повторно по мере поступления новых
  chunks (incremental);
- flush к клиенту происходит сразу после allow-решения на chunk'е.

### 7.2 Flag

- stream продолжается как в allow;
- audit / metrics фиксируют `stream_flagged` outcome;
- enforcement не останавливает stream;
- flagged chunk — это именно streaming-level flag, он семантически
  аналогичен текущему `firewallFlagged` (handler.go:477).

### 7.3 Block

- downstream stream прерывается немедленно (close connection или
  trailer-based error — см. §12);
- upstream stream cancel/close инициируется немедленно (`resp.Body.Close`
  + context cancel для in-flight reader'а);
- partial response audit'ится как `stream_blocked_midflight` с
  accumulated partial body (bounded);
- клиент получает deterministic error / termination semantics —
  см. §11.

### 7.4 Sanitize

**Stage 1** (namely: deliberately conservative):

- incremental sanitize разрешён **только для deterministic
  chunk-local transforms** — тех, где замена в границах одного chunk'а
  не ломает semantic integrity потока.
- Примеры safe-for-Stage-1: secret pattern token (API key, AWS key,
  JWT) — целиком помещается в один SSE `data:` frame на практике.
- Примеры **не** safe: multi-chunk secrets (secret растянут через
  несколько chunks), Unicode normalization across chunk boundaries,
  semantic sanitize (LLM-based rewrite).
- Всё остальное → либо `flag`, либо `buffered_fallback` (см. §9.2).

**Stage 2**: расширение sanitize support после доказанной
корректности на production traffic в shadow mode.

---

## 8. Proposed Architecture

### 8.1 High-level pipeline

```
client ──► request path (unchanged) ──► upstream connection
                                            │
                                            ▼
                                  provider-specific decoder
                                            │
                                            ▼
                                normalized stream event bus
                                            │
                     ┌──────────────────────┼─────────────────────┐
                     ▼                      ▼                     ▼
            inspection pipeline     accounting parser        audit builder
           (incremental decisions)  (usage / tokens)    (outcome classifier)
                     │
                     ▼
                  verdict
                ┌────┴────────┐
                ▼             ▼
        emit chunk      abort stream
        downstream      (block path)
```

### 8.2 Normalized chunk abstraction

Вводится internal normalized event type. Минимальный обязательный
набор для каждого provider adapter:

| Event            | Смысл                                                      |
|------------------|------------------------------------------------------------|
| `delta_text`     | фрагмент текста ответа модели (assistant delta content)    |
| `usage_update`   | частичный / финальный usage report от провайдера           |
| `message_stop`   | провайдер сигнализирует завершение последнего message'а    |
| `provider_error` | структурированная ошибка провайдера внутри stream'а        |
| `unknown_chunk`  | провайдер прислал событие, не известное adapter'у          |

Provider adapter обязан:

- конвертировать provider-native events в этот набор без потерь
  (или, для `unknown_chunk`, честно репортить unknown);
- **не** модифицировать payload между decode и dispatch — Stage 1
  делает только identity-decode (для accounting остаётся возможность
  повторного парса сырых bytes, как сейчас).

### 8.3 Inspection window (bounded)

Для incremental inspection вводится **bounded inspection window**:

- sliding text window: конкатенированный `delta_text` из последних
  N байт / K chunks (configurable; defaults предлагаются в Stage 1
  implementation PR);
- optional full accumulated text — **только** для audit builder'а и
  только при non-allow outcome;
- hard cap на in-memory accumulation (защита от памяти-атак);
- overflow policy: при достижении cap — либо force-flush (Stage 1
  default для allow-stream), либо promotion в `buffered_fallback`
  (если inspector требует non-bounded state).

### 8.4 Enforcement boundary

- **Request-side**: unchanged (`InspectRequest`, DLP request
  evaluation, policy, pre-call budget).
- **Response-side**: incremental `InspectResponse` на normalized
  event stream'е. Контракт существующего inspector interface
  (`firewall/*.go` — `InspectRequest(ctx, *Payload)` /
  `InspectResponse(ctx, *Payload)`) сохраняется; incrementality
  достигается через **повторные** вызовы с обновлённым
  `Payload.Text` (sliding window) и flag на inspector'e о
  совместимости со streaming (см. §11.2 inspector inventory).

### 8.5 Accounting side-channel

`parseStreamingUsage` в текущем виде работает на `[]byte` буфере
всего stream'а. Для incremental path:

- либо stream клонируется tee-ридером: один хвост идёт в inspection,
  второй накапливается специально для accounting-parsing в конце;
- либо parser становится stateful stream-parser (Anthropic SSE,
  OpenAI-compat SSE, Gemini SSE, Ollama NDJSON — все построчно
  декодируемы).

Stage 1 дефолт — **tee в bounded buffer + parse на close**,
параллельно с incremental inspection. Это сохраняет контракт
PR-F5 (`parseStreamingUsage` API, метрика
`metrics.RecordStreamUsageParseFail`) без изменений.

### 8.6 Outbound re-encoding contract

После inspection decision decoded normalized event должен быть
упакован обратно в **provider-compatible wire format** для клиента.
Эту сторону выполняет per-provider **downstream emitter**
(симметричный decoder'у из §8.2). Контракт:

- **Allow path** — **bytes-identity preservation**: если событие не
  модифицируется inspection pipeline'ом, emitter обязан переслать
  исходные bytes frame'а без реенкодинга. Это не optimization, а
  safety: re-encoding может ломать незнакомые поля (provider-specific
  fields, кастомные event names), которые decoder сознательно
  игнорирует по §8.2 ("конвертировать без потерь, unknown →
  `unknown_chunk`"). Идентичность байт → отсутствие классов багов
  "клиент видит чуть-чуть не то, что прислал провайдер".
- **Sanitize path** — **provider-specific re-encoding**: emitter
  получает модифицированный `delta_text` и формирует валидный frame
  в том же wire format, что прислал provider. Для SSE: `data: {...}\n\n`
  с сохранением event name, если он был. Для NDJSON: одна строка JSON
  с `\n`. Contract:
  - sanitize НЕ меняет event name, `id`, `retry` и прочие служебные
    поля — только те JSON-path'ы внутри `data:`, которые содержат
    санитизируемый текст;
  - JSON-поля, не относящиеся к тексту (tool_calls, function_call,
    logprobs, provider metadata), **пропускаются as-is**;
  - если inspector хочет модифицировать не-текстовые поля → Stage 1
    это **не поддержано**, promote в `buffered_fallback`.
- **Block path** — emitter **не формирует** финальный content frame.
  Вместо этого пишется terminal error frame (для SSE —
  `event: error\ndata: {"error":"..."}\n\n` + connection close; для
  NDJSON — одна строка JSON с error payload + close). См. также §12
  и Open Question §17.3.
- **Unknown / provider_error events** — emitter передаёт исходные
  bytes как есть (identity path), чтобы клиент увидел то же, что
  пришло от провайдера.

**Параллельный контракт с `parseStreamingUsage`** — usage frames
идут через emitter **немодифицированными**, даже если inspection
pipeline сработал на соседнем `delta_text`. Accounting side-channel
не должен быть затронут sanitize/block действиями на текстовом
канале.

Provider adapter в PR-F7.1 обязан поставлять **оба** направления
(decoder + emitter) как парный интерфейс и иметь round-trip тест
"decode(X) → emit = X" на canonical fixtures (как regression guard
для identity-preservation в allow path).

---

## 9. Provider Coverage

### 9.1 Stream formats (текущий inventory)

| Provider        | StreamFormat              | Usage parser             | Статус Stage 1         |
|-----------------|---------------------------|--------------------------|------------------------|
| OpenAI          | SSE                       | `stream_usage_openai_compat.go` | in scope        |
| OpenAI-compat\* | SSE                       | shared openai_compat     | in scope               |
| Anthropic       | SSE                       | `stream_usage_anthropic.go`     | in scope        |
| Gemini          | SSE                       | `stream_usage_gemini.go`        | in scope        |
| Ollama          | NDJSON                    | нет отдельного parser'а† | in scope (upgrade path)|
| Groq            | SSE (openai-compat)       | shared                   | in scope               |
| Mistral         | SSE (openai-compat)       | shared                   | in scope               |
| OpenRouter      | SSE (openai-compat + `: OPENROUTER PROCESSING` keepalive) | shared | in scope |

\* `StreamSSE` через общий `walkSSE` в `stream_usage_sse.go` — парсер
уже WHATWG-compliant (handles multi-line `data:`, comments, unknown
fields, `[DONE]` sentinel делегируется провайдерам).

† Ollama NDJSON — line-delimited JSON, Stage 1 PR обязан добавить
`parseOllamaStreamUsage` как часть unified coverage (иначе fallback
→ `ParseResponse` на буфере).

### 9.2 Fallback policy

Если provider / event shape не поддерживается безопасно (unknown
frame mix, undocumented keepalive, ParseStreamUsage soft-fail на
каждом ответе):

- explicit fallback на buffered path;
- отдельная метрика `streaming_fallback_total{provider,reason}`;
- admin-log визуализация;
- не делается **silent downgrade** на incremental без inspection (это
  нарушило бы Hard Invariant #1).

### 9.3 Stage 2

- расширение provider parity;
- reduction of `buffered_fallback` цепочек до нуля для Tier-1
  providers (OpenAI, Anthropic, Gemini).

---

## 10. Budget / Accounting Contract

### 10.1 Requirements (invariant)

- post-call accounting must remain accurate для `stream_completed`
  outcome;
- `parseStreamingUsage(provider, body, model)` API сохраняется;
- interrupted streams must have deterministic accounting behavior —
  см. §10.2;
- `metrics.RecordStreamUsageParseFail(provider)` продолжает
  срабатывать на `!Found || err` (уже работает в `handler.go:525-527`).

### 10.2 Mid-stream block policy

Определить и зафиксировать следующим implementation PR (PR-F7.3),
но **direction** RFC:

- **tokens, которые upstream уже сгенерировал до block'а, считаются
  billable**, даже если они не дошли до клиента. Обоснование: провайдер
  уже выставит счёт; accounting должен соответствовать реальной
  стоимости.
- **audit** фиксирует tokens=best-effort из partial usage (если
  provider успел прислать intermediate usage frame) или tokens=0 при
  абсолютно ранней блокировке до первого `delta_text`/`usage_update`.
- **budget service** получает RecordUsage на том же partial значении;
  `CheckBudgetAfterUsage` выполняется до audit write.
- outcome в audit: `stream_blocked_midflight` + `usage_source` в
  metadata (см. §11).

### 10.3 Missing usage / interrupted / malformed

- **`Found=false`** (нормальный soft-fail): метрика + audit
  `usage_source="unavailable"`; budget RecordUsage пропускается,
  post-call check выполняется на 0 tokens (может блокировать по
  прошлому долгу);
- **interrupted stream**: последние успешно декодированные events
  → best-effort usage; не считается ошибкой parser'а;
- **malformed chunk**: метрика
  `streaming_malformed_chunk_total{provider}` + promotion текущего
  stream'а в inspection-only buffered mode (см. §12.2);
- **upstream 5xx mid-stream**: `stream_upstream_error` outcome.

---

## 11. Audit Contract

Для streaming path audit builder должен различать минимум следующие
outcomes (будут отражаться в `audit_logs.policy_action` +
`audit_logs.metadata`):

| Outcome                              | Когда                                                        |
|--------------------------------------|--------------------------------------------------------------|
| `stream_completed`                   | normal clean flow, все chunks passed                         |
| `stream_flagged`                     | один или более flag, stream прошёл целиком                   |
| `stream_sanitized`                   | Stage 1 sanitize применён (deterministic chunk-local)        |
| `stream_blocked_midflight`           | inspector вернул block, stream прерван                       |
| `stream_upstream_error`              | provider вернул error mid-stream (5xx / stream error event)  |
| `stream_usage_parse_failed`          | uplink ok, usage не извлечён — soft-fail (существующая метрика) |
| `stream_buffered_fallback`           | promotion на legacy buffered path (explicit)                 |
| `streaming_transport_error`          | PR-F7.1: decoder/emitter failed с non-cancel error. Audit StatusCode=502. Buffered path в аналогичной ситуации (io.ReadAll err) audit не пишет вовсе — F7.1 incremental честнее. |
| `streaming_budget_exceeded_soft`     | PR-F7.1: post-call CheckBudgetAfterUsage вернул over-budget, но body уже ушёл клиенту. Audit StatusCode=200 (отражает real client outcome); маркер явно признаёт divergence от buffered (где был бы 402 + блок body). RecordBudgetBlock инкрементит счётчик для следующих запросов. |

### 11.1 Request body

Same privacy rules as today (`AUDIT_PAYLOAD_MODE`, existing
`sanitizePayload` / `auditPayload` helpers). Этот RFC не меняет
privacy semantics request body.

### 11.2 Response body

- partial body rules должны быть **явными**: bounded storage cap
  (например, same cap как inspection window, или configurable
  отдельно);
- при `stream_blocked_midflight` сохраняются **только accumulated до
  момента блока** байты, не весь upstream-till-EOF;
- sanitize / block семантика видна через metadata
  (`sanitize_count`, `block_inspector`, `block_reason`, `usage_source`).

---

## 12. Failure Model

### 12.1 Inspector error

Fail-open vs fail-closed — per inspector class. Текущий inventory
response-side inspector'ов + streaming-compatibility:

| Inspector             | File                              | Stage 1 fail mode | Streaming compat |
|-----------------------|-----------------------------------|-------------------|------------------|
| OutputValidation      | `firewall/output_validation.go`   | fail-closed (safety-critical) | incremental (heuristic/regex) |
| PII / DLP             | `firewall/pii_inspector.go`, `firewall/dlp_inspector.go` | fail-closed | incremental (pattern-based) |
| ContentModeration (heuristic-only) | `firewall/content_moderation.go` | fail-closed | incremental |
| ContentModeration + judge (enabled) | `firewall/content_moderation.go` + `firewall/judge.go` | fail-closed | **buffered_fallback** (см. §12.6) |
| Semantic / SemanticV2 | `firewall/semantic.go`, `firewall/semantic_v2.go` | fail-open (latency-sensitive) | buffered_fallback |
| PolicyInspector       | `firewall/policy_inspector.go`    | fail-closed      | incremental      |
| Judge (direct)        | `firewall/judge.go`               | fail-open (latency-sensitive) | NOT activated mid-stream (см. §12.6) |

Принцип: safety-critical inspectors → fail-closed,
advisory/latency-sensitive → fail-open. Дефолты фиксируются
implementation PR (PR-F7.2).

### 12.2 Provider malformed stream

- explicit handling через normalized `unknown_chunk` event;
- метрика `streaming_malformed_chunk_total{provider}`;
- audit outcome `stream_upstream_error` (если parse-error) или
  `stream_buffered_fallback` (если promotion policy triggers).

### 12.3 Upstream disconnect

- partial audit записывается с best-effort accounting;
- deterministic client outcome: либо zero-length flush + SSE done,
  либо явный error event — implementation PR выбирает одну форму,
  единую для всех провайдеров.

### 12.4 Client disconnect

- `r.Context().Done()` триггерит early cancel upstream
  (`http.Request.Context` + `resp.Body.Close`);
- audit всё равно финализируется best-effort с outcome
  `stream_completed` или `stream_upstream_error` в зависимости от
  того, что успел собрать;
- тesting: integration-тест с abort mid-stream обязателен в Stage 1
  test plan.

### 12.5 Timeout

- request timeout (полное время) и inspector timeout (per-call)
  разведены:
  - request timeout: глобальный HTTP server deadline;
  - inspector timeout: per-inspector, per-call, mapped на
    fail-open/closed по §12.1.

### 12.6 LLM-as-Judge interaction (incremental streaming)

Judge (`firewall/judge.go`) — **LLM-based classifier**, который в
текущей архитектуре условно вызывается из `ContentModerationInspector`
когда heuristic score переходит `JudgeThreshold`
(`content_moderation.go:70-76`). Contract в streaming path:

- **Judge НЕ вызывается mid-stream в Stage 1.** Обоснование:
  judge-call — это отдельный upstream LLM round-trip с latency
  порядка секунд; исполнять его на каждый chunk'овый sliding window
  неприемлемо (latency regression + cost multiplication +
  потенциальная рекурсия judge→proxy→judge, см. §15).
- **Политика для CM+judge-enabled config в incremental streaming —
  `buffered_fallback`**, не heuristic-only downgrade. Обоснование:
  heuristic-only downgrade сохранит incrementality, но **ослабит
  safety parity** с buffered path (buffered сегодня видит judge
  verdict на полном ответе; incremental-heuristic-only его не
  получит — это silent safety regression, нарушает Hard Invariant
  §6.1). Явный fallback на buffered mode сохраняет текущий judge
  verdict ценой UX этого конкретного stream'а.
- **Маркеры**: отдельная метрика
  `streaming_fallback_total{reason="judge_inspector"}` + audit
  outcome `stream_buffered_fallback` + `metadata.fallback_reason="cm_judge_enabled"`.
- **Альтернатива (НЕ Stage 1)**: async judge на полной accumulated
  text'е в конце stream'а, с rollback / redaction emitted chunks —
  отклонено для Stage 1 (rollback already-sent bytes невозможен на
  HTTP level; потребовал бы delayed-emit буферизации всех chunks
  до end-of-stream, что эквивалентно buffered_fallback по
  latency).
- **Hard deny unsupported как альтернатива fallback** (§17.5) —
  доступно как policy knob для high-compliance deploy'ев в Stage 2,
  не Stage 1 default.

Этот пункт явно фиксируется до PR-F7.1, чтобы implementation не
выбрал тихо heuristic-only downgrade.

---

## 13. Rollout Plan

### 13.1 Stage 0 (этот RFC)

- approval;
- provider coverage inventory (§9.1 выше) — уже fixed;
- metrics additions спланированы (§14);
- feature flag зарегистрирован (`STREAMING_MODE` ∈
  `buffered` | `shadow` | `incremental`; default `buffered` до опт-ина).

### 13.2 Stage 1

- incremental allow/flag/block;
- ограниченный sanitize (deterministic chunk-local);
- explicit `buffered_fallback` для unsupported inspectors / providers;
- shadow mode (опционально): incremental inspection работает
  **параллельно** с buffered path, решение incremental сравнивается с
  buffered, divergence пишется в admin log. Flip на enforce делается
  только после того, как divergence rate < threshold на production
  traffic в течение установленного окна.

**Prod opt-in gate (PR-F7.1, review fix)**: включение
`STREAMING_MODE=incremental` в `APP_ENV=production` требует отдельного
флага `STREAMING_ALLOW_INCREMENTAL_IN_PROD=true`. Без него
`ValidateStartupConfig` отвергает startup. Причины:

- F7.1 incremental отключает response-side firewall/DLP inspection
  (F7.2 это вернёт);
- budget enforcement в incremental mode становится soft-record:
  audit пишет `streaming_budget_exceeded_soft`, но client получает
  полный body (в buffered было бы 402 + блок body).

Gate существует, чтобы эти compromise'ы не включились молча.
После F7.2+F7.3 gate будет переосмыслен (возможно, удалён или
преобразован в per-inspector override).

### 13.3 Stage 2

- broader sanitize support;
- fewer legacy fallbacks;
- hardened default: `STREAMING_MODE=incremental` как default для
  Tier-1 providers.

### 13.4 Commit criterion для удаления legacy buffered path

Удаление buffered branch в `handler.go:430-576` и
`handler.go:1466-1600+` допустимо **только если все следующие
условия выполнены**:

1. Stage 2 достиг zero-fallback состояния для all supported providers
   в production traffic в течение ≥ 30 дней;
2. `streaming_fallback_total` метрика показала 0 non-synthetic events
   за это окно;
3. shadow-mode divergence rate < 0.1% на aggregate traffic;
4. `docs/firewall.md` имеет раздел "Streaming mode" (новая
   §11 в firewall doc, владелец — PR-F7.4) с описанием incremental
   path, метрик §14, fallback-поведения §12.6 и operator
   troubleshooting'ом;
5. отдельный PR (`PR-F7.5` или позже) удаляет buffered код +
   соответствующие тесты, с явным release note.

До всех пяти галок buffered path остаётся в репо как fallback.

---

## 14. Metrics

Новые / уточнённые (implementation — PR-F7.1+):

| Метрика                                         | Labels                 | Смысл                                |
|-------------------------------------------------|------------------------|--------------------------------------|
| `streaming_mode_total`                          | `mode, provider`       | `incremental` vs `buffered_fallback` |
| `streaming_midstream_block_total`               | `provider, inspector`  | mid-stream block events              |
| `streaming_partial_abort_total`                 | `provider, reason`     | early aborts (client/upstream)       |
| `streaming_malformed_chunk_total`               | `provider`             | parser ran into unknown/broken frame |
| `streaming_inspection_latency_seconds`          | `provider, inspector`  | per-chunk inspection latency         |
| `streaming_memory_accumulated_bytes`            | `provider` (histogram) | observed inspection window size      |
| `shadow_divergence_total` (shadow mode only)    | `provider, outcome`    | incremental vs buffered disagreement |

Существующая `metrics.RecordStreamUsageParseFail` (см.
`handler.go:526`) сохраняется без изменений.

---

## 15. Security Considerations

- **no harmful chunk may pass** due to parser gaps: любой провайдер
  без verified adapter идёт в `buffered_fallback`, не в silent
  passthrough;
- **no hidden downgrade** от incremental к unsafe passthrough:
  promotion в `buffered_fallback` всегда фиксируется метрикой и
  audit outcome'ом, никогда не происходит neutrally;
- **no audit/accounting blind spots** на interrupted streams: каждый
  stream завершается ровно одной audit записью;
- **no recursion through judge path**: judge inspector уже выделен
  отдельно, streaming его не активирует mid-stream в Stage 1 (judge
  — buffered only, см. §12.6);
- **no silent safety regression при CM+judge**: см. §12.6 — деплой
  с judge-enabled `ContentModeration` получает explicit
  `buffered_fallback`, не heuristic-only downgrade, чтобы сохранить
  parity с текущим buffered path;
- **provider-specific parser trust assumptions** явно
  документируются (таблица §9.1 — baseline, implementation PR
  расширяет);
- **memory exhaustion**: inspection window имеет hard cap, overflow
  → `buffered_fallback` или `stream_upstream_error` (политика
  фиксируется в PR-F7.2).

---

## 16. Alternatives Considered

### A. Keep fully-buffered streaming

**Pros:** simplest, strongest current safety (status quo).

**Cons:** poor UX, weak runtime positioning, memory O(response_size),
блокирует hardened-default ambitions.

### B. Fully passthrough with post-hoc audit only

**Pros:** best UX, zero latency.

**Cons:** unacceptable security regression — harmful chunk утекает
до принятия решения, compliance-grade продукт такого не допускает.

### C. Incremental streaming with bounded fallback

**Chosen approach for Stage 1.** Комбинирует UX выигрыш с
сохранением safety invariants + даёт явный downgrade path.

### D. SSE → WebSocket rewrite

Отклонено: меняет протокольный контракт с клиентами, выходит за
scope F7, портит provider-agnostic положение.

---

## 17. Open Questions

Следующие вопросы помечаются как решаемые в implementation PR-ах
(не блокируют approval RFC):

1. **Какие inspectors реально можно сделать incremental-safe в
   Stage 1?** — предполагается regex/pattern-based (PII, DLP,
   OutputValidation на deterministic patterns); semantic*/judge
   остаются buffered. Подтверждается в PR-F7.2.
2. **Что делать с `sanitize` для multi-chunk secrets?** — Stage 1:
   либо задержка release chunk'а до завершения pattern window, либо
   promotion → buffered_fallback. Политика фиксируется в PR-F7.2.
3. **Какой exact client-visible behavior для mid-stream block?** —
   варианты: (a) SSE `event: error\ndata: {...}\n\n` + close; (b)
   HTTP trailer с error; (c) silent close. Предпочтение (a) для SSE,
   line-delimited JSON error для NDJSON. Фиксируется в PR-F7.1.
4. **Нужен ли отдельный event type для provider usage updates?** —
   да, уже в §8.2 (`usage_update`). Что ДА не решено — приоритет
   между `usage_update` и `message_stop` в edge-case, где они идут
   в одном frame.
5. **Где граница между `buffered_fallback` и `hard deny unsupported`?**
   — Stage 1 default: fallback. `hard deny unsupported` = policy
   knob для high-compliance deploy'ев, вводится в Stage 2.

---

## 18. Test Plan

### 18.1 Unit

- **chunk parser**: SSE decoder (уже есть `stream_usage_sse_test.go`),
  NDJSON decoder (добавить для Ollama), per-provider adapter
  (`delta_text` vs `usage_update` vs `message_stop` mapping).
- **state machine**: допустимые переходы (allow→allow, allow→block,
  allow→flag→allow), недопустимые переходы.
- **inspector decisions**: incremental inspect возвращает стабильные
  решения при повторной подаче того же sliding window'а.

### 18.2 Integration

- **provider mock streams**: live SSE / NDJSON mock servers для
  OpenAI, Anthropic, Gemini, Ollama с scenarios:
  - clean stream → `stream_completed`;
  - injected harmful chunk → `stream_blocked_midflight` +
    downstream abort observable;
  - upstream abort mid-stream → `stream_upstream_error`;
  - client abort mid-stream → audit finalized с partial body.

### 18.3 Regression (invariants из §6)

- budget accounting: для `stream_completed` новое поведение даёт
  **те же** tokens / cost как старое, byte-by-byte сравнение на
  canonical fixtures;
- audit schema: все seven outcome'ов эмитят валидные `audit_logs`
  records;
- firewall decisions на canonical harmful fixture: buffered и
  incremental path дают одинаковый verdict.

### 18.4 Load

- latency envelope: TTFB должен быть < `X ms + network(upstream)` на
  canonical corpus (target в Stage 1 — ≤ первый chunk + 1
  inspection cycle);
- memory envelope: peak memory per-stream должен быть O(inspection
  window), НЕ O(response size);
- shadow mode divergence rate < 0.1% под production-shaped load.

---

## 19. Implementation Follow-Up PRs

Разбивка (может пересматриваться в implementation):

| PR       | Содержание                                                                  |
|----------|-----------------------------------------------------------------------------|
| PR-F7.1  | normalized stream event model + **paired decoder/emitter** provider adapters (per-provider PR-ы возможны) + round-trip fixtures |
| PR-F7.2  | incremental response inspection engine + inspector flags + fail modes + **CM+judge fallback policy wiring** (§12.6) |
| PR-F7.3  | streaming audit & accounting finalization (outcome classifier, metadata)    |
| PR-F7.4  | fallback visibility + metrics + **`docs/firewall.md` §11 "Streaming mode"** + changelog |
| PR-F7.5+ | (Stage 2) broader sanitize, tier-1 zero-fallback, legacy buffered removal   |

---

## 20. Acceptance Criteria for This RFC (PR-F7-RFC)

RFC готов к merge и последующему implementation-kickoff если:

1. согласованы target semantics для `allow` / `flag` / `block` /
   `sanitize` — см. §7 ✔;
2. зафиксирован Stage 1 scope — см. §13.2 ✔;
3. зафиксирован provider coverage matrix — см. §9.1 ✔;
4. зафиксирован budget / accounting contract — см. §10 ✔;
5. зафиксирован audit contract — см. §11 ✔;
6. зафиксирован rollout path с commit criterion для legacy removal
   — см. §13.4 ✔;
7. после approval можно открывать PR-F7.1 без повторной
   архитектурной дискуссии ✔.

---

## 21. Decisions fixed by this RFC (quick reference)

Для авторов implementation-PR'ов — явный список решений, которые уже
приняты и не переоткрываются без новой RFC:

- **Stage 1 не пытается "идеально" sanitize**: только deterministic
  chunk-local transforms.
- **Mid-stream block рвёт upstream и downstream**, не ждёт конца
  потока.
- **Streaming cache не трогаем**.
- **Legacy buffered path остаётся как fallback** per-provider и
  per-inspector, видимый через метрики и audit outcome.
- **Legacy удаляется только по commit criterion §13.4**, не по
  ощущению готовности.
- **Bytes-identity preservation для allow path** (§8.6): provider
  adapter re-encode на allow не делает — пересылает исходные
  bytes frame'а. Re-encoding допускается только на sanitize path.
- **CM+judge-enabled config → `buffered_fallback`** (§12.6), не
  heuristic-only downgrade. Judge mid-stream не активируется в
  Stage 1.
- **Decoder + emitter — парный интерфейс** (§8.6): каждый provider
  adapter обязан поставлять обе стороны и иметь round-trip тест
  `decode(X) → emit = X` на canonical fixtures.

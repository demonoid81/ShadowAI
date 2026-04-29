# OPS4 — Operations last-success timestamps

## Тема / вопрос

Расписать следующую задачу после OPS3 в формате рабочей постановки.

## Контекст

MCP beads показывает пустую очередь:

- `ready`: пусто.
- `in_progress`: пусто.

OPS3 добавил Prometheus-backed source для `/api/operations/status`: backend
может выполнить configurable PromQL и превратить numeric result в
`ok/warn/error/unknown`.

Оставшийся операционный gap из OPS2/OPS3: оператор видит факт текущей
ошибки/нарушения, но не видит, когда в последний раз успешно прошли
evidence export и evidence audit report. Для production UI это важно:
`0 failed jobs` не равно `job действительно недавно успешно выполнялся`.

## Текущее состояние

- `/api/operations/status` существует и admin-only.
- `evidence_export_cronjob`, `evidence_audit_report_cronjob`,
  `prometheus_alerts` могут обогащаться через Prometheus.
- Prometheus query contract сейчас numeric violation count:
  `0 = ok`, `>0 = violation`.
- UI показывает backend status, source, message и details.

## Задача

Добавить last-success telemetry для evidence export и evidence audit report в
Operations status API и UI.

Рабочее имя: **OPS4 — Operations last-success timestamps**.

## Требования

- Не обращаться к Prometheus из браузера.
- Не добавлять Kubernetes client в v1.
- Не раскрывать Prometheus URL, raw query или credentials в response.
- Не считать отсутствие failed jobs успешным выполнением.
- Поддержать clusters без kube-state-metrics: если timestamp query не настроен
  или вернул empty result, статус timestamp должен быть `unknown`, а не `ok`.
- Staleness threshold должен считаться на backend, чтобы UI не дублировал
  production semantics.
- Existing OPS3 count-query behavior не ломать.

## Предлагаемый API/config

Новые env/config поля:

- `OPERATIONS_EVIDENCE_EXPORT_LAST_SUCCESS_QUERY`
- `OPERATIONS_EVIDENCE_AUDIT_REPORT_LAST_SUCCESS_QUERY`
- `OPERATIONS_EVIDENCE_EXPORT_STALE_AFTER`
- `OPERATIONS_EVIDENCE_AUDIT_REPORT_STALE_AFTER`

Contract для `*_LAST_SUCCESS_QUERY`:

- query возвращает Unix timestamp в секундах;
- vector/scalar parsing переиспользует текущий Prometheus client;
- если returned value `<= 0` или empty result — `unknown`;
- если `now - timestamp > stale_after` — `warn`;
- если timestamp parse/query error — `error`;
- если timestamp свежий — `ok`.

Response details для соответствующих signals:

```json
{
  "query_configured": true,
  "value": 0,
  "last_success_configured": true,
  "last_success_at": "2026-04-29T03:00:00Z",
  "age_seconds": 7200,
  "stale_after_seconds": 93600
}
```

## Scope In

1. `config.Config` + `Load()` для новых env.
2. `RuntimeConfig` расширяется last-success query/stale fields.
3. `operations` package:
   - helper для Unix timestamp parsing;
   - enrichment existing CronJob signals with `last_success_at`;
   - staleness mapping.
4. Tests:
   - fresh timestamp → `ok`;
   - stale timestamp → `warn`;
   - empty timestamp query → `unknown`;
   - query error → `error`;
   - OPS3 count-query behavior unchanged.
5. Frontend:
   - показывать last success и age, если пришли в `details`;
   - unknown state не рисовать как success.
6. Helm values comments для новых env.

## Scope Out

- Kubernetes API.
- Alertmanager API.
- Job history storage в ShadowAI DB.
- Retry/re-run controls из UI.
- Prometheus authentication/token support, если его нет в текущем client-е.

## Definition of Done

- Без новых env поведение OPS3 полностью сохраняется.
- При fresh `*_LAST_SUCCESS_QUERY` UI показывает last-success timestamp.
- При stale timestamp signal получает `warn`, даже если count-query возвращает
  `0`.
- При failed count-query signal остаётся `error`, timestamp не маскирует
  failure.
- Нет raw PromQL/URL/secrets в JSON response.
- Backend tests:
  - `go test ./internal/operations ./internal/config ./cmd/shadowai -count=1`
  - `go test -tags enterprise ./internal/operations ./internal/config ./cmd/shadowai -count=1`
- Frontend tests/build:
  - targeted operations UI test или existing component test;
  - `npm run build`.
- `make helm-validate`.
- `ast-index update`.
- `git diff --check`.

## Дополнительно

### Анти-фантазия

Запрещено делать вывод “CronJob healthy” только из Helm config или наличия
CronJob template. Источник должен быть runtime metric/query.

### Edge cases

- `last_success_at` свежее, но count-query показывает failed jobs:
  итоговый status должен остаться `error`.
- count-query `0`, но last success старше threshold:
  итоговый status должен быть минимум `warn`.
- timestamp query не настроен:
  count-query status остаётся, но details честно показывают
  `last_success_configured=false`.
- Prometheus возвращает millisecond timestamp вместо seconds:
  v1 не должен угадывать; лучше считать это invalid/stale через тестируемую
  нормализацию или явно документировать seconds-only.

## Размышления

Рассмотрены варианты:

1. Использовать Prometheus timestamp query.
2. Читать Kubernetes Job/CronJob API.
3. Писать last-success в ShadowAI DB при запуске CronJob.

Принято решение для v1 использовать Prometheus timestamp query. Это продолжает
OPS3 без нового credential surface и не требует Kubernetes RBAC внутри
приложения.

Kubernetes client отклонён для OPS4: он увеличивает blast radius и требует
отдельной RBAC/tenant/security модели.

DB-backed last-success отклонён для OPS4: evidence export/audit report
CronJobs могут выполняться как отдельные containers/CLI, и запись статуса в
app DB требует отдельного producer contract.

## Возможные следующие шаги

По команде пользователя `реализуй`:

1. Создать bd issue `OPS4 Operations last-success timestamps`.
2. Начать с red tests в `internal/operations`.
3. Реализовать backend enrichment.
4. Обновить Operations UI.
5. Прогнать проверки и сделать commit.

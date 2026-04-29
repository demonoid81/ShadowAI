# Следующая задача через MCP beads

## Тема / вопрос

Определить следующую задачу после OPS3, используя MCP beads как источник
текущей очереди.

## Контекст

MCP beads установлен на workspace `/home/developer/Projects/ShadowAI`.

Результат проверки:

- `ready`: пусто.
- `in_progress`: пусто.
- `stats`: 35 задач всего, 35 закрыто, 0 open, 0 in_progress, 0 blocked,
  0 ready.

CASS-поиск по `next task roadmap ShadowAI after OPS3 Prometheus operations
signals` не нашёл результатов.

Локальный roadmap `docs/2026-04-17-enterprise-readiness-roadmap.md` фиксирует
следующий recommended work item: v2+ BYOK DEK epochs или formal external
validation / pen-test execution, если customer требует independent assessment.

OPS2 history фиксирует v2+ остаток: last-success timestamps, Alertmanager state
aggregation и explicit retry controls. OPS3 закрыл Prometheus-backed query
source, но не закрыл last-success timestamps и Alertmanager API.

## Размышления

Рассмотрены варианты:

1. Продолжить OPS-трек: добавить last-success timestamps для evidence export и
   evidence audit report.
2. Перейти к BYOK v2+: DEK epochs / broader key lifecycle.
3. Перейти к external validation / pen-test execution package.

Принято решение рекомендовать OPS4 как следующий ближайший task, потому что он
логически продолжает OPS2/OPS3 и закрывает оставшийся операционный gap без
крупного криптографического redesign.

BYOK DEK epochs остаётся следующей крупной roadmap-задачей после закрытия
операционного хвоста или при наличии customer requirement.

## Варианты

### OPS4 — Operations last-success timestamps

Добавить в `/api/operations/status` timestamp/source для последнего успешного
evidence export и evidence audit report. Источник v1: Prometheus/kube-state
metrics query, возвращающий Unix timestamp или age seconds. UI показывает не
только `ok/error`, но и `last_success_at` / `age`.

Плюсы: прямое продолжение OPS3, делает Operations UI полезнее для оператора.

Минусы: нужны аккуратные PromQL contracts и fallback для clusters без
kube-state-metrics.

### BYOK3 — DEK epochs / key lifecycle

Расширить BYOK модель до tenant/key epoch lifecycle.

Плюсы: сильный enterprise security story.

Минусы: больше scope, требует аккуратного crypto design и миграционного плана.

### SEC3 — formal external validation execution

Собрать runnable pen-test / assessor execution workflow.

Плюсы: полезно для business/security review.

Минусы: часть результата зависит от внешнего процесса.

## Рекомендация

Следующая задача: **OPS4 — Operations last-success timestamps**.

## Открытые вопросы

- Prometheus query должен возвращать Unix timestamp, age seconds или violation
  count + timestamp отдельным query?
- Нужна ли поддержка двух expression types: `*_QUERY` для violation count и
  `*_LAST_SUCCESS_QUERY` для timestamp?
- Должен ли UI считать stale threshold на frontend или backend?

## Следующие шаги

По команде пользователя перейти в IMPLEMENTATION:

1. Создать bd-задачу `OPS4 Operations last-success timestamps`.
2. Добавить config fields для last-success PromQL.
3. Расширить operations signal details полями `last_success_at` и `age_seconds`.
4. Обновить Operations UI.
5. Добавить тесты и commit.

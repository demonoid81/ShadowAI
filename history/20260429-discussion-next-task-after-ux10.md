# Следующая задача после UX10

## Тема / вопрос

Определить следующий work item после закрытия frontend epic `ShadowAI-9zi` и `ShadowAI-ux10`.

## Контекст

Локальная проверка `.beads/issues.jsonl` показала, что все текущие bead-задачи закрыты. Отдельного open/in_progress work item нет.

`history/20260429-bd-ShadowAI-ux10-operations-dashboard.md` фиксирует v2+ остаток: backend-backed CronJob/Prometheus summary endpoint, explicit retry controls, last-success timestamps.

`docs/2026-04-17-enterprise-readiness-roadmap.md` фиксирует, что до enterprise pilot / signed production / broader GA фундаментальные blockers закрыты; остатки классифицированы как v2+ BYOK DEK epochs и customer-specific identity/compliance deltas.

## Размышления

Рассмотрены два направления: продолжить сразу с BYOK v2+ DEK epochs или закрыть операционный gap, оставшийся после UX10. Принято решение рекомендовать операционный gap как следующий шаг, потому что он напрямую продолжает только что завершённую frontend работу и делает Operations page более полезной без выдуманных статусов.

Альтернатива с BYOK DEK epochs не отклонена как ненужная; она остаётся крупной v2+ задачей. Но для ближайшего шага меньше риск scope creep у backend-backed production signals API: он чётко ограничен чтением существующих Kubernetes/Prometheus/CronJob signals через безопасный backend endpoint.

## Варианты

1. **OPS2 — Backend-backed production signals API**
   Плюсы: закрывает UX10 v2+ gap; даёт Operations UI реальные last-success/failure сигналы; снижает риск ручной проверки CronJob/alerts.
   Минусы: требует backend API contract и аккуратного разграничения Kubernetes/Prometheus availability.

2. **BYOK3 — DEK epochs / broader key lifecycle**
   Плюсы: продолжает customer-managed encryption roadmap.
   Минусы: требует отдельного KMS/key-policy design и может зависеть от customer/provider decisions.

3. **SEC2 — External validation / pen-test execution package**
   Плюсы: полезно для business/security review.
   Минусы: часть работы внешняя/процессная, не всегда подходит как immediate coding task.

## Рекомендованное направление

Брать **OPS2 — Backend-backed production signals API**.

## Открытые вопросы

- Доступен ли Prometheus из backend runtime в целевой deployment модели.
- Нужно ли поддерживать Kubernetes API напрямую или ограничиться Prometheus/kube-state-metrics.
- Должен ли endpoint быть admin-only или global_admin-only.

## Возможные следующие шаги

1. По команде пользователя перейти в IMPLEMENTATION.
2. Создать bd-задачу `OPS2 Backend-backed production signals API`.
3. Зафиксировать API contract для `/api/operations/status`.
4. Реализовать backend endpoint и подключить Operations UI к нему как v2 live signals.

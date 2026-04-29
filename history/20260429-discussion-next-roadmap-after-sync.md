# Тема

Следующая задача по roadmap после ROADMAP-SYNC.

# Контекст

Источник: `docs/2026-04-17-enterprise-readiness-roadmap.md`, актуализированный 2026-04-29 после OPS2-OPS4.

Текущий `Current Priority Order` завершает закрытые пункты OPS2, OPS3 и OPS4, после чего оставляет три следующих кандидата:

- BYOK3 — DEK epochs / broader key lifecycle.
- SEC3 — formal external validation / pen-test execution.
- OPS5 — Alertmanager aggregation / retry controls.

# Размышления

Рассмотрены варианты продолжения по трём направлениям: product/security, business/procurement и operations v2+.

Принято решение рекомендовать BYOK3 как следующую основную задачу, потому что roadmap прямо помечает её как `recommended product/security track`, а BYOK v2+ lifecycle остаётся в разделе production hardening как заметный остаточный gap.

SEC3 признан сильной альтернативой, если ближайшая цель — enterprise procurement, security review или независимая проверка.

OPS5 признан операционной v2+ задачей, но не основным blocker, потому что OPS2-OPS4 уже закрыли backend status API, Prometheus-backed signals и last-success timestamps.

# Варианты

## Вариант 1 — BYOK3

Плюсы:

- Закрывает следующий заметный product/security gap после BYOK2/BYOK2.1.
- Усиливает customer-managed encryption story.
- Логично продолжает уже утверждённый BYOK RFC.

Минусы:

- Требует аккуратного дизайна key epochs, миграций и compatibility с существующими encrypted payload.
- Может затронуть restore/evidence runbooks.

## Вариант 2 — SEC3

Плюсы:

- Быстро усиливает business/procurement readiness.
- Даёт независимый validation artifact для enterprise security review.

Минусы:

- Больше процессная задача, чем product capability.
- Может зависеть от внешнего assessor или тестового окна.

## Вариант 3 — OPS5

Плюсы:

- Улучшает operator workflow: Alertmanager aggregation и retry/re-run controls.
- Хорошо ложится на уже готовые OPS2-OPS4 foundations.

Минусы:

- Roadmap помечает это как optional operations v2+.
- Не закрывает главный BYOK lifecycle gap.

# Рекомендованное направление

Следующая задача: **BYOK3 — DEK epochs / broader key lifecycle**.

Если приоритет бизнеса — procurement или security questionnaire, можно переключиться на **SEC3**. Если приоритет эксплуатации — self-service remediation в Operations UI, можно взять **OPS5**.

# Открытые вопросы

- Нужен ли BYOK3 сначала как mini-RFC или сразу implementation plan.
- Какие payload classes входят в BYOK3 v1: только audit payload или также admin events / SIEM minimized metadata / export artifacts.
- Должна ли key epoch metadata быть per-tenant или global с tenant-scoped overrides.

# Возможные следующие шаги

1. Расписать задачу BYOK3 в формате `КОНТЕКСТ / ТЕКУЩЕЕ СОСТОЯНИЕ / ЗАДАЧА / ТРЕБОВАНИЯ / DoD / ДОПОЛНИТЕЛЬНО`.
2. После подтверждения пользователя перейти в IMPLEMENTATION и создать bd-задачу.
3. Если пользователь выберет business track, аналогично расписать SEC3.

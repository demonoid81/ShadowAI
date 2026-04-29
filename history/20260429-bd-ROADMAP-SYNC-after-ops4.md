# ShadowAI-de2 / ROADMAP-SYNC после OPS2-OPS4

## Контекст

После OPS2/OPS3/OPS4 Operations track получил:

- safe backend endpoint `/api/operations/status`;
- Prometheus-backed production signals;
- last-success telemetry для evidence export и evidence audit report.

Основной roadmap `docs/2026-04-17-enterprise-readiness-roadmap.md` отставал от
этих коммитов и всё ещё содержал stale priority order.

## Цель

Синхронизировать enterprise-readiness roadmap как source-of-truth для
следующих задач.

## План реализации

1. Зафиксировать источники: discussion после OPS4 и последние коммиты.
2. Обновить статус документа и закрытые треки.
3. Убрать stale “current” формулировки.
4. Зафиксировать актуальный список v2+ кандидатов: BYOK3, SEC3, OPS5.
5. Проверить markdown diff и `git diff --check`.

## Размышления

Рассмотрены варианты: сразу перейти к BYOK3/SEC3 или сначала обновить roadmap.
Принято решение синхронизировать roadmap первым, потому что текущий документ
является локальным source-of-truth для выбора следующего трека.

Альтернатива переписать весь roadmap отклонена: задача является sync, а не
новым strategy RFC. Исторические разделы сохраняются, обновляются только
устаревшие статусы и следующий порядок.

## Scope In

- OPS2-OPS4 в закрытых треках.
- Production ops semantics после OPS4.
- Updated “Requires work” section.
- Updated current priority order.
- Updated decision point.

## Scope Out

- Реализация BYOK3.
- Реализация SEC3.
- Реализация OPS5.
- Изменение кода.

## Definition of Done

- Roadmap отражает OPS2–OPS4.
- Следующие кандидаты указаны явно.
- History examples созданы.
- bd закрыт.
- Commit выполнен.

## Roadmap

v1: source-of-truth roadmap sync.

v2+: отдельные задачи BYOK3, SEC3, OPS5.

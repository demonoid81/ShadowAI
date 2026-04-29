# Roadmap после OPS4

## Тема / вопрос

Определить актуальное состояние roadmap после закрытия OPS2–OPS4.

## Контекст

MCP beads:

- total issues: 36
- closed: 36
- open: 0
- in_progress: 0
- ready: 0

Последние коммиты:

- `a23ae77` — OPS2 `/api/operations/status`.
- `cf067df` — OPS3 Prometheus-backed operations signals.
- `fa86bc7` — OPS4 last-success timestamps.

`docs/2026-04-17-enterprise-readiness-roadmap.md` фиксирует recommended next
work item: v2+ BYOK DEK epochs или formal external validation / pen-test
execution. Этот документ не отражает OPS2–OPS4 как отдельный закрытый
операционный хвост, поэтому roadmap sync стал отдельным технически нужным
шагом.

## Размышления

Рассмотрены варианты: сразу перейти к BYOK DEK epochs, начать external
validation package или сначала обновить roadmap/status docs. Принято решение
рекомендовать короткий `ROADMAP-SYNC` первым, потому что локальный основной
roadmap является источником для следующих решений и сейчас отстаёт от
последних коммитов OPS2–OPS4.

После sync логичный следующий крупный implementation-трек — BYOK DEK epochs,
если цель усиливать enterprise/customer-managed encryption. Если ближайшая
цель — sales/security review, то вместо BYOK стоит брать formal external
validation / pen-test execution.

## Актуальное состояние

### Закрыто

- Frontend enterprise console UX8–UX10.
- OPS2 safe backend operations status API.
- OPS3 Prometheus-backed production signals.
- OPS4 last-success telemetry для evidence export/audit report.
- Базовые enterprise/pilot/signed-production blockers по roadmap закрыты.

### Осталось как v2+

1. **ROADMAP-SYNC**
   Обновить `docs/2026-04-17-enterprise-readiness-roadmap.md`: добавить OPS2–OPS4
   в закрытые треки, убрать stale текущие пункты, уточнить следующий priority
   order.

2. **BYOK3 — DEK epochs / broader key lifecycle**
   Расширить BYOK после BYOK2/BYOK2.1: tenant/key epochs, metadata, verify/export
   compatibility, rotation semantics.

3. **SEC3 — formal external validation / pen-test execution**
   Превратить SEC1 package в исполняемый external validation workflow:
   scope, scripts, expected artifacts, remediation tracking.

4. **OPS5 — Alertmanager aggregation / retry controls**
   OPS2–OPS4 закрыли status + Prometheus + last-success. Остались Alertmanager
   state aggregation и explicit retry/re-run controls.

5. **Customer-specific deltas**
   SAML adapter, IdP quirks, compliance evidence fields, vendor-specific
   requirements — только при customer demand.

## Рекомендация

Следующий immediate task: **ROADMAP-SYNC**.

Причина: это короткая задача, которая убирает stale source-of-truth перед
следующим большим треком.

После неё выбрать:

- **BYOK3**, если приоритет — product/security глубина.
- **SEC3**, если приоритет — бизнес-продажи, external assessment и enterprise
  procurement.

## Открытые вопросы

- Есть ли customer requirement на BYOK DEK epochs прямо сейчас?
- Нужен ли formal external validation до следующего business milestone?
- Требуются ли OPS5 retry controls в UI или достаточно Alertmanager/Prometheus
  visibility?

## Возможные следующие шаги

1. Реализовать ROADMAP-SYNC.
2. Затем расписать BYOK3 или SEC3 как отдельную bd-задачу.

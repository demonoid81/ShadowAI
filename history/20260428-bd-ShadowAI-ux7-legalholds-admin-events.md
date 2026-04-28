# bd ShadowAI-ux7 — Legal Holds and Admin Events UI

## Контекст

Backend уже содержит legal hold lifecycle, four-eyes approval/release, bulk approve/reject, pending SLA и privileged admin events. Frontend до этой задачи не давал оператору UI для этих workflows, поэтому legal/compliance операции требовали прямого API или CLI-доступа.

CASS был проверен перед реализацией, но локальная CASS-база недоступна/не инициализирована. Контекст восстановлен по bd-задаче и фактическому коду через ast-index/локальное чтение файлов.

## Цель

Добавить рабочие экраны:

- `/legal-holds` для создания, preview, lifecycle actions, bulk approve/reject и SLA visibility.
- `/admin-events` для просмотра privileged trail с actor/resource/action/status/org context фильтрами.

## План реализации

1. Проверить backend-контракт legalhold/adminaudit handlers и реальные маршруты.
2. Добавить недостающие route bindings для legal hold bulk/SLA/release approval.
3. Добавить frontend API client для legal holds и admin events.
4. Реализовать composables и UI-компоненты для legal hold create/table/SLA/bulk result.
5. Реализовать admin events table с backend-фильтрами и client-side status/org-context фильтрами.
6. Добавить ru/en i18n и router/nav entries.
7. Добавить utility-тесты для state/action matrix и выполнить build/backend checks.

## Размышления

Рассмотрены варианты размещения UI: встроить legal holds в Evidence/Compliance или сделать отдельные admin-only маршруты. Принято решение сделать отдельные маршруты `/legal-holds` и `/admin-events`, потому что операции являются интерактивными privileged workflows, а не только evidence overview.

Рассмотрены варианты optimistic update после lifecycle action и reload из backend. Принято решение reload после transition, потому что backend state machine является canonical и отдельные endpoints могут возвращать разные response shapes для edge cases.

Рассмотрены варианты org-фильтра admin events: backend query поддерживает actor/resource/action, но не прямой org/status filter. Принято решение использовать backend-фильтры там, где они есть, а status/org/source/target фильтровать на текущей странице результата с явным пояснением в UI. Альтернатива добавлять backend API расширение отклонена как отдельный scope.

Рассмотрены варианты bulk operation UX: скрыть detail и показывать только summary либо выводить per-item results. Принято решение показывать per-item status/error, так как four-eyes legal workflows требуют явной видимости partial failures.

## Реализация

- Добавлены route bindings для `/legal-holds/bulk-approve`, `/bulk-reject`, `/pending-sla`, `/{id}/approve-release`, `/{id}/reject-release`.
- Добавлен frontend API слой `src/api/legal.ts`.
- Добавлены `LegalHoldsPage`, `AdminEventsPage`, components и composables.
- Добавлен `legalHoldUi` utility module с action matrix, status counts и safe metadata preview.
- Добавлены i18n keys в `ru.json` и `en.json`.
- Добавлены nav routes в dashboard layout.

## Roadmap

### v1

- Legal hold lifecycle UI.
- Bulk approve/reject with per-item result.
- Pending SLA visibility.
- Admin events privileged trail with org/source/target context.

### v2+

- DSAR-specific dashboard поверх legal hold state.
- Exportable legal reports.
- Backend org/status filters для admin events, если операторам понадобится server-side pagination-aware filtering.

## Проверка

- `node` JSON parse + duplicate top-level locale check.
- `npm run test:legal-hold-ui`.
- `npm run build`.
- `go test -tags enterprise ./internal/legalhold ./cmd/shadowai`.
- `git diff --check`.

# Обсуждение — production-readiness стадия проекта

## Тема / вопрос

Определить текущее состояние ShadowAI по отношению к готовности к production.

## Контекст

Фактические источники:

- `docs/production-hardening.md` фиксирует GA1 production-hardening guide,
  supported operating envelope, mandatory secrets, mandatory alerts и known
  limits before GA.
- `history/20260427-discussion-current-project-status.md` фиксирует текущую
  стадию как `signed production candidate / enterprise pilot ready+`.
- Последние локальные коммиты закрыли L8.1d selector manifest и зафиксировали
  current project status.
- CASS-поиск вернул старый session summary по enterprise readiness, но
  актуальнее локальные git/docs/history.

## Размышления

Рассмотрены три возможные оценки:

1. `Enterprise pilot ready`.
2. `Signed production candidate`.
3. `Full GA / production ready без caveats`.

Принято решение использовать формулировку **signed production candidate**:
внутренние engineering-контуры production-grade в основном закрыты, но
внешние assurance-активности ещё не выполнены.

Альтернатива `full GA` отклонена: production-hardening документ прямо
фиксирует known limits — BYOK implementation отсутствует, formal pen test не
проведён, restore drill требует операционного выполнения, streaming incremental
для части providers не является безопасным default.

Альтернатива `MVP / not production ready` отклонена: tenant isolation, WORM,
evidence export, SIEM, auth/MFA/OIDC/SCIM, legal hold, governance, Helm/ops и
SOC evidence tooling уже реализованы и покрыты тестами.

## Варианты

### A. Controlled production / enterprise pilot

Подходит для self-hosted или dedicated tenant deploy с известным оператором,
включёнными secrets/alerts/evidence CronJobs и консервативными defaults.

### B. Signed production candidate

Подходит как внутренний release-candidate статус перед customer-facing GA:
кодовая база близка к production, но нужно пройти deployment drill, security
review и pen test.

### C. Broad GA

Пока преждевременно: нужны внешние проверки и решение по BYOK2/customer KMS,
если целевые клиенты этого требуют.

## Рекомендация

Текущая стадия: **production candidate / enterprise pilot ready+**.

Практический смысл:

- для controlled enterprise pilot — можно готовить deployment;
- для публичного GA — ещё рано;
- для signed production — нужен финальный non-code readiness пакет.

## Открытые вопросы

- Нужно ли сейчас сделать отдельный `GA readiness checklist`.
- Нужно ли обновить roadmap-документ, который частично отстаёт от фактических
  коммитов.
- Есть ли customer requirement на BYOK2 до первого production пилота.

## Возможные следующие шаги

1. Обновить roadmap/status document.
2. Создать GA readiness checklist.
3. Провести deployment drill на staging/prod-like namespace.
4. Подготовить security-review package и pen-test scope.
5. Оставить streaming incremental в conservative mode, пока provider-specific
   sanitize caveats не закрыты.

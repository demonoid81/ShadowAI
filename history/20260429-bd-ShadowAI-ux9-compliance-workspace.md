# ShadowAI-ux9 — Compliance report workspace

## Контекст

CompliancePage показывала только обзор compliance capabilities. Backend/CLI уже генерируют auditor-facing JSON artifacts: access review, evidence collection manifest, retention audit report и not_collected.json. Пользователь не мог открыть эти результаты во фронтенде и быстро понять, где есть findings, violations или incomplete controls.

## Цель

Добавить frontend workspace для локального просмотра compliance JSON reports без загрузки файлов на backend и без утверждения о наличии SOC2/ISO сертификации.

## План реализации

1. Зафиксировать tolerated JSON shapes для `audit-access-review`, `audit-evidence-report`, `audit-collect-evidence` manifest и `not_collected.json`.
2. Реализовать parser/summarizer слой в `frontend/src/utils/complianceReports.ts`.
3. Добавить browser-only upload workspace на Compliance page.
4. Показать summary cards: status, total, passed, failed, not_collected, findings.
5. Показать findings/violations и rows preview для проверки содержимого.
6. Добавить ru/en i18n и safe error для invalid JSON.
7. Проверить unit parser test и frontend production build.

## Размышления

Рассмотрены два варианта: отправлять отчёты на backend для нормализации или парсить их локально в браузере. Принято решение использовать локальный browser parse, потому что compliance artifacts могут содержать операционные идентификаторы, а scope UX9 не включает server-side storage или auditor portal.

Рассмотрены варианты строгой схемной валидации и tolerant summarizer. Принято решение использовать tolerant summarizer: CLI schemas могут расширяться, а UI должен сохранять просмотр unknown fields и безопасно показывать `unknown report` вместо падения.

Альтернатива с PDF/rendered certification report отклонена: это создало бы риск переобещания compliance статуса. UI явно оставляет disclaimer, что это workspace для evidence review, а не certification.

## Scope In

- Local JSON upload без network upload.
- Viewer для access review, retention report, evidence manifest и not_collected.
- Summary cards и findings/violations list.
- Rows preview для forensic review.
- i18n ru/en.

## Scope Out

- Серверное хранение загруженных отчётов.
- Генерация compliance reports из UI.
- PDF export.
- Cryptographic verification replacement для `audit-verify`.

## Definition of Done

- Access review JSON показывает findings.
- Retention report JSON показывает violations.
- Evidence collection manifest и not_collected показывают completeness gaps.
- Invalid JSON даёт безопасную ошибку без сохранения данных.
- `npm run build` проходит.

## Roadmap

v1: локальный report viewer на Compliance page.

v2+: server-side evidence inventory, auditor portal, report history, controlled export sharing.

# Обсуждение: BYOK2 KMS-backed payload encryption

## Тема / вопрос

Расписать следующую задачу roadmap: `ShadowAI-rhl.4` — BYOK2 KMS-backed
payload encryption implementation.

## Контекст

Локальные источники:

- `bd show ShadowAI-rhl.4 --json`: задача открыта, но содержит dependency:
  explicit KMS provider decision and field selection.
- `docs/rfcs/2026-04-pr-byok1-kms-byok-design.md`: BYOK1 имеет статус
  design-only, BYOK не реализован.
- `docs/production-hardening.md`: BYOK указан как not implemented; payload
  fields are plaintext.

Ключевые факты из BYOK1:

- provider-specific SDK integration — BYOK2 scope;
- primary encryptable fields: `audit_logs.request_body` и
  `audit_logs.response_body`;
- recommended model: encrypt-after-canonical;
- WORM verification must work without KMS;
- open questions: KMS provider, DEK cache TTL, payload audit depth, legal hold
  notes, DSAR cryptographic erasure, searchable encryption.

## Размышления

Рассмотрены варианты:

- Реализовать все KMS backend сразу. Альтернатива отклонена: это увеличит
  поверхность ошибок и смешает SDK-specific failure modes в первом PR.
- Начать с fake/in-memory KMS only. Альтернатива отклонена как product gap:
  она даст тестовую криптографию, но не customer-managed key story.
- Начать с одного production backend и общей KMS abstraction. Принято как
  рациональный v1: минимальная рабочая capability, расширяемая в v2.

Принятое рекомендуемое направление для задачи:

- KMS v1: HashiCorp Vault Transit как self-hosted enterprise-friendly backend.
- Fields v1: только `audit_logs.request_body` и `audit_logs.response_body`.
- Migration v1: new writes only + dual-read. Background sweep старых строк — v2.
- WORM invariant: canonical и row_hash считаются до encryption; verifier не
  требует KMS.

## Варианты

### Вариант A — Vault Transit first

Плюсы:

- Self-hosted compatible.
- Не привязан к AWS/GCP/Azure.
- Хорошо ложится на dedicated tenant deployments.
- Можно покрыть integration тестом через testcontainers или httptest
  Vault-compatible mock.

Минусы:

- Некоторым cloud-first customer всё равно потребуется AWS/GCP/Azure adapter.

### Вариант B — AWS KMS first

Плюсы:

- Частый enterprise default.
- Хорошо для AWS-hosted deployments.

Минусы:

- Cloud-specific dependency.
- Нужно решать IAM, region, key policy, local integration story.

### Вариант C — abstraction + no real backend

Плюсы:

- Быстро.
- Много unit-тестов.

Минусы:

- Не закрывает бизнес gap “customer-managed keys”.
- Нельзя честно назвать BYOK implemented.

## Рекомендация

Начать BYOK2 с Vault Transit first.

Задачу разделить так:

1. `BYOK2.1` — crypto/envelope + KMS abstraction + Vault Transit adapter.
2. `BYOK2.2` — audit repository integration для new writes only.
3. `BYOK2.3` — evidence/bundle metadata + verify compatibility.
4. `BYOK2.4` — runbook, Helm/env config, startup validation.
5. `BYOK2.5` — optional background sweep старых plaintext rows.

Для ближайшей реализации брать `BYOK2.1 + BYOK2.2` в одном PR только если scope
остаётся ограниченным двумя полями audit payload.

## Открытые вопросы

1. Подтверждён ли KMS backend v1: Vault Transit?
2. Подтверждены ли поля v1: `request_body`, `response_body`?
3. Разрешён ли v1 без background sweep старых plaintext rows?
4. Какой DEK cache TTL допустим: 5 минут, 15 минут, 1 час?
5. Нужен ли fail-closed write path при KMS outage, или временный plaintext
   fallback запрещён полностью?

## Возможные следующие шаги

Если решения подтверждены:

- перевести `ShadowAI-rhl.4` в `in_progress`;
- уточнить bd description под выбранный backend/scope;
- начать TDD с envelope encode/decode и KMS client contract;
- затем внедрять в `audit.Repository.Insert` без изменения WORM canonical.

Если решения не подтверждены:

- создать отдельную decision task `BYOK2-decision-gate`;
- оставить `ShadowAI-rhl.4` open до выбора KMS provider и field scope.

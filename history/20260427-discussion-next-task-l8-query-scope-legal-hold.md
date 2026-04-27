# Обсуждение следующей задачи — L8 query_scope legal hold RFC

## Тема / вопрос

Определить следующую задачу после PR-L7 legal hold SLA / DPO signals и
расписать её в рабочем формате.

## Контекст

CASS был проверен перед обсуждением, но недоступен как актуальный
источник: `cass health` вернул `index stale`. Поэтому источником истины
стали локальные документы и свежие history-файлы.

Найденные источники:

- `docs/production-hardening.md` фиксирует known limit:
  legal hold `query_scope` не реализован; сейчас enforced только
  `whole_user` и `date_range`.
- `docs/compliance/soc2-iso-control-mapping.md` фиксирует residual gap:
  legal hold query-scope beyond date-range remains roadmap.
- `docs/privacy-ops-runbook.md` после L7 фиксирует:
  SLA/DPO signals реализованы, но hold-scope шире date-range остаётся
  v2+ roadmap.
- `history/20260427-bd-ShadowAI-215-l7-legal-hold-sla.md` фиксирует
  v2+ roadmap: webhook/email/PagerDuty transport, dedicated SLA state
  table, `query_scope` legal hold selector language.

## Размышления

Рассмотрены варианты:

- **L7.1 external SLA routing** — email/webhook/PagerDuty/ticket creation
  поверх L7 signals.
- **L8 query_scope legal hold** — selector language для per-query /
  per-conversation legal hold scope beyond date-range.
- **BYOK2** — KMS/envelope encryption implementation после BYOK1 RFC.
- **F7.x non-OpenAI incremental sanitize** — закрытие streaming sanitize
  для Anthropic/Gemini/Ollama.

Принято рекомендованное направление: **PR-L8 RFC — legal hold
query_scope selector language**.

Альтернатива L7.1 отклонена как следующая immediate задача: L7 уже
создаёт durable admin/SIEM/Prometheus signals, а конкретная доставка в
email/ticketing зависит от customer stack.

Альтернатива BYOK2 отклонена до явного customer/KMS requirement: RFC
уже есть, но реализация затрагивает payload encryption, bundle format и
key lifecycle.

Альтернатива сразу реализовать `query_scope` без RFC отклонена:
selector DSL является security-sensitive поверх audit/tenant/legal
boundary, поэтому сначала нужно зафиксировать threat model, допустимые
поля, SQL-safe compilation и доказуемую auditability.

## Рекомендованное направление

Следующая задача:

**PR-L8 RFC: Legal Hold `query_scope` Selector Language**

Цель: зафиксировать безопасную и проверяемую модель `query_scope`
legal hold до реализации.

## Черновой scope задачи

### In

- RFC в `docs/rfcs/`.
- Threat model:
  - tenant boundary bypass;
  - over-broad selector;
  - SQL injection / unsafe dynamic query;
  - ambiguous audit explanation;
  - purge mismatch between preview and execution.
- Selector model:
  - allowlist полей;
  - поддерживаемые operators;
  - forbidden constructs;
  - normalized canonical form.
- Mapping selector → purge exclusion SQL.
- Preview/explain API shape для operator-а.
- Interaction с `whole_user`, `date_range`, DSAR и audit evidence.
- Migration plan, если нужны новые columns/table для compiled selector.
- Test plan и acceptance criteria для L8 implementation PR.

### Out

- Реализация parser/compiler в этом PR.
- UI для selector builder.
- External legal CMS integration.
- Email/webhook routing.
- BYOK/KMS.

## Открытые вопросы

1. Какие поля разрешить в v1 selector:
   `provider`, `model`, `created_at`, `conversation_id`,
   `request_metadata`, `policy_action`, `org_id`?
2. Нужен ли JSON DSL вместо текстового DSL для снижения parser-risk?
3. Должен ли `query_scope` применяться только к `audit_logs` или также
   к `admin_event_logs` / evidence bundles?
4. Нужен ли mandatory preview count перед activation?
5. Как фиксировать selector в WORM canonical/evidence chain:
   normalized JSON hash, full selector JSON или оба?

## Возможные следующие шаги

1. По команде пользователя создать bd-задачу `PR-L8 RFC: legal hold
   query_scope selector language`.
2. Начать с code/doc discovery:
   `legalhold` scope fields, purge SQL, audit export/bundle paths,
   WORM canonical, tenant org filters.
3. Написать RFC и вынести blocking decisions до implementation kickoff.

# Обсуждение — готовность к production и бизнес-использованию

## Тема / вопрос

Оценить, насколько ShadowAI готов к работе в production и к бизнес-использованию.

## Контекст

Фактические источники:

- `docs/production-hardening.md` фиксирует GA1 production-hardening guide,
  supported operating envelope, mandatory secrets, mandatory alerts, pre-launch
  checklist и known limits before GA.
- `docs/2026-04-17-enterprise-readiness-roadmap.md` фиксирует закрытые
  enterprise треки: SIEM, governance, identity, SCIM, tenant isolation, WORM,
  evidence ops, production ops, CI/release gates.
- `docs/compliance/soc2-iso-control-mapping.md` фиксирует control evidence
  inventory, но явно указывает, что это не SOC 2 / ISO certification.
- `history/20260427-discussion-production-readiness-stage.md` фиксирует
  текущую стадию как `production candidate / enterprise pilot ready+`.

CASS health сообщил stale index. CASS search не дал актуального результата,
поэтому source of truth — локальные docs/history/git.

## Размышления

Рассмотрены три шкалы готовности:

1. Controlled production pilot.
2. Public / broad GA.
3. Business readiness: продажи, security review, enterprise pilot, compliance
   questionnaires.

Принято решение не называть проект `full production ready`: техническая база
сильная, но formal pen test, external audit/certification и BYOK2 ещё не
закрыты.

Альтернатива `не готов к production` отклонена: в проекте уже есть Helm/ops,
secrets validation, readiness/health, WORM/evidence, SIEM, tenant isolation,
SCIM/OIDC/MFA, legal hold, evidence export, audit reports и control mapping.

## Оценка

### Controlled production / enterprise pilot

Оценка: **80–85% готовности**.

Подходит для:

- self-hosted или dedicated tenant deployment;
- ограниченного enterprise pilot;
- запуска с ручным operator control;
- conservative settings: buffered/shadow streaming, mandatory alerts,
  evidence CronJobs, S3 Object Lock, readiness probes.

Что ещё нужно перед запуском:

- deployment drill;
- restore drill;
- финальная проверка secrets/alerts/Helm values;
- staging/prod-like smoke run.

### Public GA / broad production

Оценка: **60–70% готовности**.

Что мешает назвать full GA:

- нет formal pen test;
- SOC2/ISO mapping есть, но это не certification;
- BYOK implementation отсутствует, есть только RFC/design;
- streaming incremental для части providers имеет caveats;
- roadmap/status документ частично отстаёт от фактических коммитов;
- restore drill автоматизирован CLI-командой, но операционно ещё должен быть
  выполнен и зафиксирован.

### Business readiness

Оценка: **75–80% готовности для enterprise conversations / pilots**.

Сильные стороны для бизнеса:

- ясная compliance story: WORM, evidence bundles, S3 Object Lock, audit reports;
- identity story: OIDC, SCIM, MFA, break-glass;
- governance story: provider/model rules, department/sensitivity routing,
  org budgets;
- tenant story: org isolation, tenant evidence proofs, per-org SCIM tokens;
- SOC/security questionnaire support через control evidence inventory;
- production hardening guide и runbooks.

Ограничения для бизнеса:

- нельзя обещать SOC2/ISO certification;
- нельзя обещать customer-managed keys как реализованную функцию;
- нельзя обещать broad GA без pen test/security review;
- performance numbers в production-hardening — targets/recommendations, не
  результат полноценного load test.

## Рекомендация

Текущий статус формулировать так:

> ShadowAI is ready for controlled enterprise production pilot, and is a signed
> production candidate. It is not yet broad-GA certified software.

Для русского pitch:

> Проект готов к контролируемому enterprise-пилоту и близок к production
> readiness. Для публичного GA нужны deployment drill, pen test/security review,
> актуализация roadmap и решение по BYOK/customer keys.

## Открытые вопросы

- Какой первый целевой сценарий: self-hosted pilot или SaaS/dedicated tenant.
- Требуется ли BYOK2 до первого клиента.
- Кто владелец pen test / external security review.
- Нужно ли formal SOC2 Type I/Type II как ближайшая бизнес-цель.

## Возможные следующие шаги

1. Обновить enterprise readiness roadmap.
2. Создать GA readiness checklist.
3. Провести staging deployment drill.
4. Сформировать security-review package.
5. Подготовить business-facing one-pager с честными claims и limitations.

# Licensing Decision (2026-04-21)

## Контекст
Закрытие стратегического вопроса до merge PR-G1 (см.
`20260421-direction-enterprise-self-host.md`,
`20260421-discussion-licensing.md`).

## Решение
**Вариант E** из discussion-licensing:

1. **ShadowAI Core** — репозиторий `demonoid81/ShadowAI` (этот repo).
   Лицензия: **Apache License 2.0**. Файлы `LICENSE`, `NOTICE`.
2. **ShadowAI Enterprise** — отдельный приватный репозиторий
   `shadowai-enterprise` (создаётся оператором).
   Лицензия: **proprietary commercial self-host license**
   (не ELv2, не BSL, не AGPL):
   - All Rights Reserved;
   - право использования даётся через MSA + Order Form +
     Self-Hosted EULA;
   - source access, если нужен, оформляется контрактом, а не публичной
     source-available лицензией.
3. **Contributor agreement** для Core — **DCO** (sign-off),
   не CLA. Reasoning: минимум friction, достаточно для чистого Apache;
   CLA вводится позже только если потребуется менять лицензию Core
   или переносить community code в Enterprise.
4. **Trademark policy** — `TRADEMARK.md` в Core. Ключевой механизм
   защиты от hostile re-host при permissive core:
   - форки разрешены, но нельзя называть форк/hosted-service
     "ShadowAI";
   - использование логотипа — только по письменному разрешению.

## Core/Enterprise boundary

### ShadowAI Core (Apache 2.0)
- proxy + routing + stream usage parsing;
- firewall engine + все 10 инспекторов + semantic_v2;
- benchmark harness + corpus-gen;
- basic policy engine (CRUD + enforcement);
- Prometheus metrics;
- basic auth/JWT + user CRUD;
- basic audit (минимальный уровень без payload modes);
- basic dashboard (stats без privacy masking);
- inspector modes (disabled/shadow/enforce).

### ShadowAI Enterprise (commercial)
- AUDIT_PAYLOAD_MODE=metadata|redacted (PR-A);
- retention + purge для audit_logs (PR-A / PR-D.1);
- DSAR / erasure (PR-B);
- `admin_event_logs` + retention (PR-D / PR-D.1);
- user-read access audit (PR-G0) и расширения (PR-G0.1 / G0.2);
- dashboard masking / privacy UX (PR-D.1);
- Provider/Model Governance (PR-G1) — allowlist, role-based,
  compliance inventory;
- SIEM integration (mirror в Splunk/Elastic/CloudTrail);
- SSO/SCIM;
- legal hold automation;
- backup post-restore scrub;
- tenant isolation (PR-F);
- compliance control mappings / enterprise runbooks
  (`privacy-ops-runbook.md` — enterprise-level).

## Состояние репозитория (на момент решения)
- master содержит только Core-код (PR-2..PR-6.1.1). Privacy/audit/
  governance feature branches существуют, но **ни одна не merged в
  master**. Миграционных конфликтов нет.
- Feature branches `pr-a-audit-privacy`, `pr-b-erasure`,
  `pr-d-admin-audit`, `pr-d1-retention-masking`, `pr-e-privacy-runbook`,
  `pr-g0-user-read-audit` переносятся в `shadowai-enterprise` repo как
  основа начального коммита.
- PR-G1 с самого начала идёт в `shadowai-enterprise`, не в Core.

## Почему не остальные варианты
- **A (Apache везде)** — слишком слабая защита монетизации.
- **B (AGPL)** — procurement-friction для банков/страхования/
  госсектора; конфликт с regulated-enterprise позицией.
- **C (BSL)** — лучше AGPL для anti-hosting, но всё ещё лишний legal
  friction для целевого сегмента.
- **D (ELv2)** — source-available без OSS upside; хуже для community
  trust, чем Apache core + commercial enterprise.

## Критичное правило (merge discipline)
Публичный Apache core **не должен** принимать PR enterprise-scope.
Список текущих feature branches (PR-A / PR-B / PR-D / PR-D.1 / PR-E /
PR-G0) — enterprise, не Core. Merge любой из них в master = подрыв
commercial boundary.

## Следующие шаги
1. ✅ Создать `LICENSE` (Apache 2.0), `NOTICE`, `CONTRIBUTING.md` (DCO),
   `TRADEMARK.md`. Коммит в branch `licensing-core`, PR в master.
2. Оператору: создать приватный repo `shadowai-enterprise`,
   перенести feature branches PR-A/B/D/D.1/E/G0 туда как initial
   import.
3. Оператору: разработать и зафиксировать proprietary
   commercial self-host EULA (внешний юридический review обязателен).
4. PR-G1 запускается уже в `shadowai-enterprise`, не в Core.
5. README Core обновить с упоминанием dual-project структуры
   ("ShadowAI Core is Apache 2.0; Enterprise features available
   under commercial license").

## Источники
- Apache 2.0 application guidance:
  <https://www.apache.org/legal/apply-license>
- Apache contributor agreements overview:
  <https://www.apache.org/licenses/contributor-agreements.html>
- DCO 1.1: <https://developercertificate.org/>
- BSL 1.1 (отклонено): <https://mariadb.com/de/bsl11/>
- ELv2 (отклонено): <https://www.elastic.co/pricing/faq/licensing/>

## Disclaimer
Это решение — product/licensing architecture decision. Не юридическое
заключение. Перед публичным выпуском и customer-facing commercial
terms требуется юрист.

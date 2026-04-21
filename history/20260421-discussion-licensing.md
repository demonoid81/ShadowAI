# Discussion: Licensing ShadowAI (2026-04-21)

## Тема
Выбор модели лицензирования ShadowAI до merge PR-G1. Решение влияет на:
- что публикуется в публичный repo;
- модель монетизации;
- защиту от hostile re-host (AWS/Azure managed copy).

## Контекст
- Direction-decision (2026-04-21): regulated enterprise, self-host/
  single-tenant, open-core (см. `20260421-direction-enterprise-self-host.md`).
- Продукт: LLM firewall (10 инспекторов) + audit/governance/DSAR.
- Конкуренты: AWS Bedrock Guardrails, Azure AI Content Safety, Lakera,
  Prompt Security (commercial), NVIDIA NeMo Guardrails (Apache 2.0).
- Целевые клиенты — финансы, здравоохранение, госсектор. Enterprise
  legal-команды консервативно относятся к AGPL/SSPL.

## Допущения (B — понятна частично)
- Open-core уже выбран как общее направление. Обсуждение конкретизирует
  границу split и выбор open-лицензии для core.
- Нет VC-ограничений по лицензии.
- Основная монетизация — commercial enterprise build + support SLA,
  не managed SaaS.
- Hostile re-host — средний риск, не нулевой.

## Размышления
Ключевое противоречие: copyleft (AGPL/SSPL/BSL) защищает от
cloud-копирования, но отпугивает enterprise legal — а именно это
целевой сегмент. Permissive (Apache/MIT) привлекательны для legal,
но не дают защиты от re-host.

Компромиссы:
- split: core + enterprise с разными лицензиями;
- delayed-OSS: BSL → Apache через N лет.

Для regulated enterprise значимее убрать legal-friction, чем
защититься от AWS. AWS-Guardrails-клиент и self-host-compliance-клиент
— разные рынки; re-host почти не каннибализирует наш сегмент. Значит
copyleft на core избыточен. Rational split: core под permissive,
enterprise-фичи под commercial license.

Альтернатива (AGPL) отклонена: legal-friction в regulated-сегменте
превышает выгоду от защиты от re-host.

## Варианты

### A. Pure Apache 2.0
- **+** maximum adoption, zero legal-friction, OSI-approved.
- **+** прямая модель: весь код open, монетизация через services.
- **−** полная уязвимость к re-host.
- **−** enterprise-feature differentiation размывается.

### B. Pure AGPLv3 + commercial dual
- **+** copyleft + network provision → форк раскрывается.
- **+** классический dual-licensing (MongoDB до 2018, MinIO).
- **−** regulated enterprise legal часто блокирует AGPL.
- **−** self-host клиент боится distribution trigger.
- **−** конфликт с «regulated enterprise, low-friction sales».

### C. BSL 1.1 с change date → Apache 2.0
- **+** защита от re-host в commercially-valuable период (3–4 года),
  затем автоматически Apache.
- **+** use-limitation формулируется точечно («нельзя as-a-service»).
- **+** прецеденты: Sentry, CockroachDB, MariaDB MaxScale.
- **−** non-OSI — часть дистрибутивов не распространяет.
- **−** legal-чтение дольше, чем Apache, но короче, чем AGPL.

### D. Elastic License v2 (ELv2)
- **+** простая формулировка, три ограничения.
- **+** прецеденты: Elastic, Redis с 2024.
- **−** non-OSI, «proprietary с чтением кода».
- **−** нет delayed-OSS — вечно source-available.

### E. Open-core split: Apache 2.0 core + Commercial enterprise module
- **+** core в Apache 2.0 → широкий adoption + prod-deployments.
- **+** enterprise-модули (PR-G1, PR-F, SIEM, 4-eyes, SSO/SCIM)
  в отдельном repo под commercial license.
- **+** ровно закрывает regulated-enterprise сегмент.
- **+** прецеденты: GitLab CE (MIT) + EE (proprietary),
  Grafana OSS + Grafana Enterprise.
- **−** требует технической дисциплины: feature-boundary должна быть
  чёткой; нельзя постепенно переносить фичи — это подорвёт community
  trust.
- **−** не защищает core от re-host. Смягчается тем, что
  enterprise-модули — ключевой value для целевого сегмента.

## Рекомендация
**Вариант E** (split: Apache 2.0 core + commercial enterprise),
с опциональной страховкой через BSL при появлении реального
re-host signal.

Обоснование:
1. Целевой сегмент (regulated enterprise) требует low-friction
   procurement — Apache снимает проблему полностью.
2. Монетизация уже сидит в enterprise-фичах (PR-G1, PR-F, SIEM,
   4-eyes, DSAR automation) — естественный split без искусственного
   crippling core.
3. Re-host риск — средний, не первый: AWS Guardrails и наш
   enterprise-build обслуживают разных клиентов.
4. BSL можно включить позже при сигналах о cloud-копировании.
   Обратный переход тоже возможен, но реже.

## Конкретика split (для E)

### Core (Apache 2.0)
Текущий main-код ShadowAI:
- firewall: все 10 инспекторов + semantic_v2;
- audit_logs baseline (retention + purge);
- DSAR erasure;
- user CRUD, JWT auth;
- policy engine (CRUD + enforcement);
- admin_event_logs baseline;
- dashboard (basic stats, top users, usage).

### Enterprise (commercial license, repo `shadowai-enterprise`)
- Provider/Model Governance (PR-G1): allowlist, role-based,
  compliance inventory.
- Tenant isolation (PR-F).
- SIEM integration (mirror admin_event_logs в Splunk/Elastic/
  CloudTrail).
- 4-eyes policy для destructive ops (pending_erasures + approver).
- SCIM / SSO (SAML, OIDC с enterprise IdP).
- Advanced retention policies (per-tenant, per-role).
- Legal hold automation.
- Premium support SLA + priority security patches.
- Compliance mapping: SOC 2, ISO 27001, ISO 42001, EU AI Act.

## Открытые вопросы
1. **Commercial licence template** для enterprise-репо —
   LicenseZero, adapted ELv2 с «commercial seats», либо
   full custom EULA?
2. **CLA vs DCO** для core — DCO (Linux-style sign-off) достаточно
   для чистого Apache; для dual-licensing в будущем нужен full CLA
   (Apache ICLA-style).
3. **Trademark policy** — «ShadowAI» как имя требует trademark-
   политики. Отдельный документ.
4. **Pricing для enterprise build** — не блокирует merge PR-G1,
   но до GA нужно зафиксировать.

## Следующие шаги
1. Решение по одному из пяти вариантов.
2. Если E: решение по sub-вопросам (template, CLA/DCO, trademark).
3. Создать `LICENSE` в core repo, `LICENSE-enterprise.md` в
   enterprise repo, `CONTRIBUTING.md` с CLA/DCO инструкцией.
4. Public messaging в README: «ShadowAI Core is Apache 2.0 licensed;
   enterprise features available under commercial license».
5. После закрытия licensing — unblock PR-G1 merge.

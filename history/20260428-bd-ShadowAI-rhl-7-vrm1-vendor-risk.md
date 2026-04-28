# bd ShadowAI-rhl.7 — VRM1 LLM provider vendor-risk process

## Тема

Закрыть gap по формальному vendor-risk process для LLM providers.

## Контекст

`bd ready` показал `ShadowAI-rhl.7` как следующий открытый gap. `cass health`
вернул stale index, поэтому CASS не использовался как источник прошлого
контекста. Локальные источники:

- `docs/compliance/soc2-iso-control-mapping.md` указывал, что governance policy
  controls usage, но formal TPRM process отсутствует.
- `backend/internal/governance/` реализует provider/model governance.
- `docs/security/llm-red-team-validation-package.md` явно отделял vendor-risk
  review как отдельный process.

## Размышления

Рассмотрены варианты:

- Встроить vendor-risk как runtime feature. Альтернатива отклонена: legal,
  procurement, DPA, subprocessors и provider SOC reports не являются runtime
  enforcement и остаются operator-owned.
- Оставить только governance allowlist. Альтернатива отклонена: allowlist
  отвечает "что разрешено технически", но не отвечает "почему vendor approved".
- Создать process package + templates + governance mapping. Принято решение:
  это закрывает questionnaire/evidence gap без ложного утверждения, что
  ShadowAI выполняет юридическую due diligence за оператора.

## Scope

### In

- Vendor-risk process для LLM providers.
- Assessment template.
- Approved provider register template.
- Governance integration guidance.
- SOC/control mapping update.

### Out

- Выполнение vendor due diligence.
- Автоматическая проверка SOC reports/subprocessors.
- SSPM/TPRM SaaS integration.

## План реализации

1. Добавить `docs/compliance/llm-provider-vendor-risk.md`.
2. Добавить assessment template.
3. Добавить approved provider register CSV.
4. Обновить SOC2/ISO mapping и evidence quick reference.
5. Обновить enterprise roadmap.
6. Добавить examples history.
7. Проверить acceptance и diff hygiene.

## Definition of Done

- Business может честно ответить на vendor-risk questionnaire.
- Есть template для assessment.
- Есть template для approved provider register.
- Документирована связь approval → governance policy.
- Residual gaps честно описаны.
- Roadmap и SOC mapping обновлены.

## Проверка

- `rg` по ключевым acceptance терминам.
- `git diff --check`.
- `git diff --cached --check`.

## Риски / зависимости

- Provider-side retention/training/deletion зависит от договора и технических
  возможностей провайдера.
- Governance allowlist не заменяет legal/privacy approval.
- SSPM/TPRM automation остаётся v2+.

## Roadmap

### v1

Process package + templates + governance integration.

### v2+

- Автоматический diff approved-provider register vs live governance policy.
- Scheduled vendor review evidence collection.
- Optional integration with external TPRM/SSPM systems.

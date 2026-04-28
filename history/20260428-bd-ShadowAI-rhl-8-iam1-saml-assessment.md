# bd ShadowAI-rhl.8 — IAM1 SAML assessment

## Тема

Закрыть ambiguity gap по SAML: в продукте есть OIDC/SCIM/MFA, но SAML не
реализован, а часть enterprise buyers может требовать SAML.

## Контекст

`bd ready` показал задачу `ShadowAI-rhl.8` как следующий открытый gap в epic
`ShadowAI-rhl`. `cass health` вернул stale index, поэтому CASS не использовался
как источник прошлого контекста. Источники истины для решения: локальный код,
документы и bd.

Локальный поиск показал:

- OIDC реализован в `backend/internal/oidcauth/`.
- SCIM реализован в `backend/internal/scim/`.
- MFA / break-glass реализованы в auth layer.
- `docs/compliance/soc2-iso-control-mapping.md` и
  `docs/production-hardening.md` явно фиксируют SAML как unsupported.

## Размышления

Рассмотрены варианты:

- Реализовать SAML сразу. Альтернатива отклонена: для безопасной SAML
  реализации нужны customer IdP metadata, attribute mapping, MFA assertion
  semantics и tenant binding model. Без этих входных данных получится
  абстрактный adapter с высоким риском небезопасных defaults.
- Оставить gap как "нет SAML". Альтернатива отклонена: для business/security
  review нужен defendable ответ, почему OIDC/SCIM покрывают текущий enterprise
  path и когда SAML станет implementation item.
- Закрыть IAM1 assessment package. Принято решение: явно зафиксировать, что SAML
  не реализован, классифицировать его как customer-dependent, описать
  requirements matrix и минимальный будущий adapter scope.

## План реализации

1. Добавить security assessment document по SAML/OIDC/SCIM.
2. Обновить SOC2/ISO mapping: residual gap должен ссылаться на IAM1, а не
   звучать как неразобранный blocker.
3. Обновить production-hardening known limits.
4. Обновить enterprise roadmap: добавить IAM1 как закрытый assessment, оставить
   SAML implementation в deferred/customer-dependent.
5. Добавить examples/history artifact.
6. Проверить acceptance через grep и markdown diff checks.

## Definition of Done

- Есть документ, который внешний buyer/security reviewer может использовать для
  ответа на SAML-вопрос.
- SAML нигде не заявлен как реализованный capability.
- Текущий supported path OIDC + SCIM описан явно.
- Future SAML implementation имеет requirements и security invariants.
- Roadmap и compliance docs обновлены.

## Проверка

- Поиск acceptance-строк через `rg`.
- `git diff --check`.
- `git diff --cached --check`.

## Риски / зависимости

- Реальная SAML реализация зависит от customer/IdP contract.
- Нельзя auto-provision `global_admin` через SAML без отдельного dangerous opt-in.
- Tenant binding не должен доверять headers; нужен утверждённый IdP mapping.

## Roadmap

### v1

IAM1 assessment package: закрывает ambiguity и questionnaire gap.

### v2+

SAML adapter только после customer requirement:

- SP metadata endpoint.
- ACS callback.
- Signed assertion validation.
- Replay protection.
- Role/department/org mapping.
- MFA assertion enforcement.
- Audit/SIEM integration.

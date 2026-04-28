# Обсуждение: что осталось по задачам

## Тема / вопрос

Какие задачи остаются после закрытия текущих roadmap и control-gap cleanup работ.

## Контекст

Источник истины: локальные документы `docs/2026-04-17-enterprise-readiness-roadmap.md`,
`docs/production-hardening.md`, `docs/compliance/soc2-iso-control-mapping.md`.

CASS недоступен: `cass health` вернул `index stale`, поэтому использован локальный
поиск и чтение документов.

## Размышления

Рассмотрены варианты:

- трактовать roadmap как полностью закрытый;
- считать все `Current Gaps / Not Covered` блокерами;
- разделить остатки на product blockers, production validation и audit/formal gaps.

Принято решение: фундаментальные product/security blockers считать закрытыми,
а оставшиеся пункты вести как production/customer-specific hardening и formal
compliance work. Это точнее отражает текущее состояние: продукт готов к пилоту
и близок к production при корректном deployment, но формальная аудитная зрелость
требует внешних процедур и операторских доказательств.

Альтернатива “всё закрыто” отклонена: formal pen test, SOC 2/ISO attestation,
SAML, SAST/SCA и BYOK v2+ явно остаются gap-ами в документах.

## Варианты решений

1. Deployment-specific production validation.
   Плюс: самый прямой путь к реальному production confidence.
   Минус: зависит от конкретного окружения, секретов, IdP, SIEM, S3/Vault.

2. BYOK v2+ key lifecycle.
   Плюс: закрывает customer-managed encryption глубже текущего audit payload scope.
   Минус: требует аккуратного дизайна DEK epochs и новых payload classes.

3. Formal security/compliance readiness.
   Плюс: нужен для бизнеса и regulated customers.
   Минус: часть работы вне кода: third-party pen test, SOC 2/ISO engagement,
   branch protection, policy docs.

## Рекомендованное направление

Следующая техническая задача: deployment-specific production validation pack.
Она должна проверить реальный Helm deploy с OIDC/SCIM/SIEM/S3 Object Lock/Vault
и выдать go/no-go report.

Если приоритет бизнеса — customer-managed encryption, следующей задачей может
быть BYOK v2+ DEK epochs и расширение encryption scope за пределы `audit_logs`.

## Открытые вопросы

- Есть ли целевое окружение для production validation: cluster, namespace,
  домен, IdP, S3 bucket, Vault policy.
- Нужен ли SAML как обязательный customer requirement или OIDC+SCIM остаётся
  supported enterprise path.
- Требует ли текущий customer full BYOK beyond audit payloads.

## Возможные следующие шаги

1. PR-PROD1: deployment-specific production validation pack.
2. PR-BYOK3: DEK epochs + расширение BYOK scope.
3. PR-SEC2: external pen-test execution package + remediation tracker.
4. PR-CI2: SAST/SCA and branch-protection evidence hardening.

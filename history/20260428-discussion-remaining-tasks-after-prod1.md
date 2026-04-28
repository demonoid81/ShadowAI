# Обсуждение: остаток задач после PROD1

## Тема / вопрос

Что осталось по задачам после добавления `shadowai-prod-validate`.

## Контекст

Источник истины: локальные документы:

- `docs/2026-04-17-enterprise-readiness-roadmap.md`
- `docs/production-hardening.md`
- `docs/compliance/soc2-iso-control-mapping.md`

CASS недоступен: база не инициализирована в текущем data-dir. Использован
локальный поиск и чтение файлов.

## Размышления

Рассмотрены варианты:

- считать проект полностью закрытым по roadmap;
- считать все compliance gaps blocking задачами;
- разделить остаток на product v2+ work, external validation и operator-owned controls.

Принято решение: фундаментальные product/security blockers закрыты. Оставшиеся
задачи не блокируют controlled enterprise pilot при корректном deployment, но
важны для regulated customers и formal audit.

Альтернатива “всё blocking” отклонена: многие пункты являются внешними процессами
или operator-owned controls, а не недостающим runtime-кодом.

## Варианты

1. BYOK v2+ DEK epochs.
   Плюс: закрывает самый конкретный product gap в customer-managed encryption.
   Минус: затрагивает key lifecycle, field classification и миграции.

2. External validation / pen-test execution.
   Плюс: закрывает наиболее важный бизнес gap для security review.
   Минус: часть работы вне кода и требует внешнего ассессора.

3. CI/Sec hardening.
   Плюс: SAST/SCA и branch protection evidence усиливают change management.
   Минус: меньше product differentiation, больше operational maturity.

4. Policy docs.
   Плюс: SOC2/ISO readiness.
   Минус: mostly documentation/process, не runtime feature.

## Рекомендация

Следующая техническая задача: `BYOK3 — DEK epochs and expanded encryption scope`.
Это самый конкретный remaining product gap из текущих документов.

Если ближайшая цель — customer security review, следующей лучше брать `SEC2 —
formal external validation / pen-test execution pack`, потому что no formal pen
test остаётся первым gap в SOC2/ISO mapping.

## Открытые вопросы

- Есть ли customer requirement на full BYOK beyond audit payloads.
- Нужен ли формальный pen-test артефакт до следующего business milestone.
- Нужен ли SAML как обязательный customer blocker или OIDC+SCIM достаточно.

## Возможные следующие шаги

1. `BYOK3`: DEK epochs + расширение BYOK scope.
2. `SEC2`: external validation execution package и remediation tracker.
3. `CI2`: SAST/SCA + branch protection evidence.
4. `POL1`: formal Security Policy и BCP/DR policy docs.
5. `L8.2`: hash-only/BYOK-encrypted legal-hold selector bundles.

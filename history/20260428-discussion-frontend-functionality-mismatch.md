# Обсуждение: frontend не соответствует реализованному функционалу

## Тема / вопрос

Пользователь уточнил, что проблема не в запущенности frontend-процесса, а во
внешнем виде и product-level восприятии UI: текущий frontend не соответствует
уровню реализованного enterprise/security функционала.

## Контекст

Фактическая проверка:

- `frontend/src` содержит небольшой Vue/Vite UI: dashboard, audit, policies,
  budget, users, providers, firewall, internal-db.
- Общий объём основных Vue/TS файлов около 1.4k строк.
- `DashboardLayout.vue` использует простой dark sidebar, emoji icons и базовую
  навигацию.
- `DashboardPage.vue` показывает базовые request/cost/user stats, но не отражает
  WORM/evidence, tenant isolation, BYOK, SCIM/OIDC/MFA, production validation,
  SIEM posture и compliance readiness.

Roadmap при этом фиксирует реализованные enterprise capabilities: WORM evidence
chain, tenant isolation, SCIM/OIDC/MFA, org budgets, evidence bundles, Object
Lock, BYOK audit payload encryption, production validation и compliance mapping.

CASS недоступен: база не инициализирована в текущем data-dir. Использованы
локальные файлы и фактический frontend-код.

## Размышления

Рассмотрены варианты:

- делать точечный visual polish текущих страниц;
- переписать весь frontend сразу;
- выделить отдельный PR на enterprise security console shell и постепенно
  переносить функциональные страницы.

Принято решение: следующая задача должна быть не “подкрасить CSS”, а
`UX1 — Enterprise Security Console`. Нужно изменить информационную архитектуру:
UI должен показывать продукт как security/compliance control plane, а не как
простую админ-панель.

Альтернатива “только CSS polish” отклонена: она не решит mismatch между
функциональностью и восприятием. Альтернатива “полный rewrite всех страниц”
слишком рискованна для одного PR.

## Варианты решений

1. UX1 Shell + dashboard redesign.
   Плюс: быстро меняет первое впечатление и навигацию.
   Минус: часть глубоких страниц останется старой до UX2.

2. Full frontend rewrite.
   Плюс: максимальная консистентность.
   Минус: высокий риск regression и большой scope.

3. Только CSS polish.
   Плюс: быстро.
   Минус: не отражает enterprise capabilities.

## Рекомендованное направление

Начать с UX1:

- новый layout как Security Console;
- navigation groups: Observe, Govern, Protect, Evidence, Operate;
- dashboard hero/status strip: policy enforcement, WORM evidence, SIEM delivery,
  tenant isolation, BYOK, production readiness;
- заменить emoji/icon случайность на консистентную систему;
- добавить пустые/summary cards для capabilities, даже если часть глубоких
  workflows остаётся на существующих страницах;
- сохранить существующие API calls и routing где возможно.

## Открытые вопросы

- Нужно ли делать только shell/dashboard или сразу затронуть все страницы.
- Есть ли брендовые ограничения по цветам/типографике.
- Нужен ли light mode или достаточно production dark console.

## Возможные следующие шаги

1. `UX1`: Enterprise Security Console shell + dashboard redesign.
2. `UX2`: Evidence/WORM dedicated UI.
3. `UX3`: Tenant/org control plane UI.
4. `UX4`: Compliance/auditor workspace UI.

# bd-ShadowAI-8xd — примеры UX1

## Happy path 1: security buyer открывает dashboard

Ожидание: первый экран говорит не “админка”, а “Enterprise Security Console”.
Видны LLM Firewall, WORM evidence, tenant isolation, BYOK и production readiness.

## Happy path 2: operator ищет нужный раздел

Ожидание: навигация сгруппирована по задачам:

- Observe: dashboard/audit
- Govern: policies/budget/providers
- Protect: firewall/internal DB
- Operate: users

## Edge case 1: обычный пользователь без admin роли

Ожидание: admin-only пункты остаются скрытыми, как раньше. Новый layout не
обходит `authStore.isAdmin`.

## Edge case 2: нет dashboard stats

Ожидание: posture и hero sections всё равно отображаются, а metric cards ждут
`store.stats`, как раньше.

## Failure case 1: UI обещает live posture без backend signal

Запрещено: показывать выдуманные live health values. UX1 labels формулируются
как capability/posture summaries, не как runtime telemetry.

## Failure case 2: ломается сборка

Ожидание: `npm run build` обязан проходить. Это главный regression gate для UX1.

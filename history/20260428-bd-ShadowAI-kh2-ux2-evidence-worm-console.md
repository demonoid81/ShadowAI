# bd-ShadowAI-kh2 — UX2 evidence WORM console page

## Контекст

После UX1 frontend получил enterprise shell и posture dashboard, но evidence /
WORM возможности оставались только в документах и CLI. Backend уже реализует
HMAC chain, Merkle anchors, Ed25519 manifests, Object Lock export, tenant
Merkle proofs, additional sinks и production validation.

CASS недоступен: база не инициализирована в текущем data-dir. Источники истины:
history UX1, roadmap и фактический frontend-код.

## Цель

Добавить отдельную страницу `/evidence`, которая показывает chain-of-custody
модель и операторские команды верификации без нового backend API.

## Scope In

- Route `/evidence`.
- Evidence group в navigation.
- `EvidencePage.vue` с contract cards, pipeline, commands, caveats.
- i18n ru/en.

## Scope Out

- Live evidence monitoring.
- Backend API.
- Download bundle from UI.
- Full auditor workspace.

## Размышления

Рассмотрены варианты:

- добавить только ссылку на runbook;
- сделать live status UI с fake/static статусами;
- сделать capability page с явными operator commands и caveats.

Принято решение: capability page. Это улучшает product perception и объясняет
WORM/evidence story, не создавая ложного ощущения live monitoring.

Альтернатива fake live status отклонена: без backend endpoint это было бы
переобещанием. Runbook-only вариант отклонён: он не решает визуальный mismatch.

## План реализации

1. Добавить route `/evidence`.
2. Добавить Evidence nav group.
3. Реализовать `EvidencePage.vue`.
4. Добавить ru/en translations.
5. Проверить `npm run build`.
6. Закрыть bd и commit.

## Roadmap

### v1

- Evidence/WORM capability UI.

### v2+

- Live evidence health API.
- Bundle inventory browser.
- Auditor workspace.
- Signed validation report viewer.

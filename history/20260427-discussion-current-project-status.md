# Обсуждение — текущее состояние проекта

## Тема / вопрос

Оценить текущее состояние ShadowAI и стадию проекта.

## Контекст

Фактические источники:

- `git log --oneline -80` показывает, что после `origin/master` локальный
  `master` ушёл вперёд на 21 коммит и закрыл review fixes + L6/L7/L8/L8.1a-d.
- Последний коммит: `305aef5 bd-ShadowAI-9co: add selector manifest to evidence bundles`.
- `docs/production-hardening.md` фиксирует GA1 production-hardening guide и
  known limits.
- `docs/2026-04-17-enterprise-readiness-roadmap.md` содержит общий roadmap, но
  частично устарел: в нём `SOC2.1` ещё помечен как current, хотя в истории уже
  есть `SOC2.3`, `Scale2`, `W8.1` и свежий L8.1d.
- `history/20260427-bd-ShadowAI-9co-l8-1d-selector-manifest.md` фиксирует
  закрытие selector manifest gap для query-scope evidence bundles.
- CASS-поиск по текущему состоянию не нашёл релевантных записей; локальный
  git/docs/history использованы как source of truth.

## Размышления

Рассмотрены два источника статуса: roadmap-документ и фактическая история
коммитов.

Принято решение считать фактический `git log` более авторитетным, потому что
roadmap-документ частично отстаёт от выполненных задач.

Альтернатива отвечать только по roadmap-документу отклонена: это занизило бы
стадию проекта и проигнорировало бы уже реализованные треки после `SOC2.1`.

## Варианты формулировки стадии

### Вариант A — Enterprise pilot ready

Плюсы:

- Консервативная формулировка.
- Соответствует production-hardening caveats: нет formal pen test, BYOK
  implementation отсутствует, часть streaming providers остаётся buffered.

Минусы:

- Недооценивает уже реализованные WORM/evidence, tenant, SOC2 automation,
  access review, performance gates и legal hold query-scope.

### Вариант B — Signed production candidate

Плюсы:

- Лучше отражает фактическое состояние: GA1 hardening, WORM chain, evidence
  bundles, S3 Object Lock, retention report, SOC2 evidence collection, access
  review, tenant isolation и L8 query-scope закрыты.

Минусы:

- Нужны внешние активности перед customer-facing GA: deployment drill,
  pen test, security review, выбранный BYOK path.

### Вариант C — Broader GA

Плюсы:

- Большая часть engineering foundation уже закрыта.

Минусы:

- Слишком агрессивно: roadmap/production-hardening всё ещё фиксируют known
  limits и внешние readiness gaps.

## Рекомендация

Текущая стадия: **signed production candidate / enterprise pilot ready+**.

Проект уже не в MVP и не в design-only фазе. Основные enterprise/compliance
контуры реализованы: identity, tenant isolation, governance, SIEM, WORM,
evidence bundles, evidence export automation, access review, legal hold
query-scope.

До настоящего GA остаются не столько core feature gaps, сколько
операционные/assurance задачи:

- актуализировать roadmap-документ под фактический `git log`;
- выполнить production deployment drill;
- пройти external security review / pen test;
- принять решение по BYOK2;
- закрыть remaining streaming provider sanitize caveats или оставить buffered
  как supported default.

## Открытые вопросы

- Нужно ли немедленно обновить `docs/2026-04-17-enterprise-readiness-roadmap.md`,
  чтобы он не противоречил фактической истории коммитов.
- Является ли следующий milestone `BYOK2`, `roadmap refresh`, `pen-test prep`
  или `deployment drill`.

## Возможные следующие шаги

1. Обновить roadmap-документ до актуального состояния.
2. Сформировать `GA readiness checklist` с внешними non-code items.
3. Начать BYOK2 implementation только если есть customer requirement.
4. Подготовить security-review package: architecture, threat model, evidence
   artifacts, known limits.

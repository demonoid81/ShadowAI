# bd ShadowAI-rhl.5 — F8.1 semantic_v2 production promotion package

## Контекст

`semantic_v2` уже реализован как request-side embedding inspector с режимом
`shadow_only`, метрикой `shadowai_semantic_v2_inspect_total` и prod validation
для endpoint/provider/corpus. Gap: оператору не хватало enforce-ready package —
corpus gate, alert templates, promotion criteria и rollback procedure.

CASS был проверен перед началом: `cass health` вернул stale index. Поэтому
использованы фактический код, docs и bd-задача.

## Цель

Сделать переход `FIREWALL_SA_V2_SHADOW_ONLY=true` → `false` управляемым:
оператор должен видеть corpus validity, behavior baseline, fail-open health,
would-block review queue и rollback commands.

## Scope

In:
- CLI `firewall-corpus-verify` для offline validation manifest'а.
- Build gates для CLI в Makefile/CI/Docker image.
- Helm PrometheusRule alerts для `fail_open` и `would_block`.
- Runbook для staged rollout.
- Docs updates для production-hardening, corpus README и production runbook.

Out:
- Новая embedding model или внешний benchmark vendor.
- Автоматическое снятие `shadow_only`.
- Автоматическая генерация production corpus в CI.

## План реализации

1. Через `ast-index` восстановить `SemanticV2Config`, metrics и текущий corpus loader.
2. Добавить red-тесты для CLI verifier-а.
3. Реализовать `cmd/firewall-corpus-verify`.
4. Добавить CLI в build gates и runtime image.
5. Добавить Helm/static Prometheus alerts.
6. Написать runbook с rollout stages и rollback.
7. Прогнать tests, helm validation, закрыть bd и сделать commit.

## Размышления

Рассмотрены варианты:
- Только docs/runbook без нового tooling.
- Расширить `firewall-bench` и использовать его как единственный gate.
- Добавить отдельный `firewall-corpus-verify` как быстрый structural gate, а
  `firewall-bench --with-embeddings` оставить behavior gate.

Принято решение: отдельный corpus verifier + existing bench. Причина:
`firewall-bench` проверяет качество/behavior и требует datasets/baseline, а
оператору нужен быстрый preflight для mounted corpus: provider/model/dimension,
normalization, categories и минимальный размер.

Альтернатива “docs-only” отклонена: она не закрывает enforce-ready gap, потому
что promotion остаётся ручным утверждением без машинного preflight.

## Roadmap

v1:
- Corpus structural validation.
- Behavior gate через existing `firewall-bench --with-embeddings`.
- Alert templates for `fail_open` and `would_block`.
- Staged runbook: disabled → shadow_only → limited enforce → full enforce.

v2+:
- Auto-regeneration job with embedding sidecar.
- Per-category corpus thresholds.
- Dashboards as Grafana JSON, если появится dashboard packaging track.

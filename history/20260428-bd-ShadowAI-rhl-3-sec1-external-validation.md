# bd ShadowAI-rhl.3 — SEC1 external LLM security validation package

## Контекст

SOC/compliance документы фиксировали остаточный gap: нет formal penetration
test / third-party security assessment. Кодовые controls уже существуют
(firewall, streaming inspection, governance, tenant isolation, WORM evidence),
но внешний assessor не имел единого scope package и воспроизводимого набора
case ID.

CASS был проверен перед реализацией: `cass health` вернул stale index. Поэтому
источником истины выступили bd, локальные docs, benchmark datasets и текущие
runbook/evidence commands.

## Цель

Подготовить package, с которым внешний red-team/assessor может выполнить
scoped LLM security validation без reverse-engineering продукта: scope,
rules of engagement, attack matrix, safe corpus, evidence collection и
remediation workflow.

## Scope

In:
- Документ для external assessor.
- Controlled attack matrix: prompt injection, jailbreak, data exfiltration,
  multi-turn, streaming, governance, tenant isolation, observability/evidence.
- JSONL test corpus с безопасными canary payloads.
- Evidence export and verification workflow.
- Updates в production/compliance/roadmap docs.

Out:
- Выполнение внешнего pen test.
- Утверждение security attestation.
- Реальные customer data / destructive tests.
- Автоматический finding tracker.

## План реализации

1. Найти существующие compliance/security gaps и benchmark datasets.
2. Создать `docs/security/llm-red-team-validation-package.md`.
3. Создать `docs/security/llm-red-team-test-cases.jsonl`.
4. Обновить production-hardening и SOC mapping: package exists, execution still absent.
5. Обновить enterprise roadmap.
6. Добавить history examples.
7. Проверить JSONL, markdown diff, закрыть bd и commit.

## Размышления

Рассмотрены варианты:
- Ограничиться короткой ссылкой в SOC mapping.
- Создать только high-level runbook без case corpus.
- Создать external validation package + JSONL test corpus.

Принято решение: package + corpus. Причина: внешний assessor должен видеть
границы тестирования, expected controls и evidence artifacts по каждому case ID,
иначе проверка снова превращается в ручной reverse-engineering.

Альтернатива “выполнить pen test самим” отклонена: это не external validation,
не независимая third-party assessment и противоречит Scope Out bd-задачи.

## Roadmap

v1:
- Readiness package and controlled safe test cases.
- Evidence workflow через existing audit/evidence CLIs.
- Remediation template.

v2+:
- External report ingestion into bd/issue tracker.
- Automated mapping from SEC1 case ID to audit rows.
- Customer-specific addendum for regulated deployments.

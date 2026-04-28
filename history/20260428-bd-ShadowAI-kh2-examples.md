# bd-ShadowAI-kh2 — примеры UX2 Evidence/WORM

## Happy path 1: security reviewer открывает Evidence

Ожидание: reviewer видит chain-of-custody story: audit rows → HMAC chain →
Merkle anchors → signed manifests → sinks → evidence bundle.

## Happy path 2: operator ищет команду проверки

Ожидание: operator видит команды `audit-verify --bundle`,
`audit-export-evidence`, `audit-evidence-report`, `shadowai-prod-validate`.

## Edge case 1: нет live evidence API

Ожидание: страница не показывает invented “green” health. Все cards описаны как
capability / evidence contract.

## Edge case 2: tenant bundle

Ожидание: текст явно говорит, что tenant bundles проверяются offline и не
раскрывают cross-tenant row hashes.

## Failure case 1: regulated deployment без second sink

Ожидание: caveat сообщает, что W8 supports additional sinks, но operator должен
настроить independent witness сам.

## Failure case 2: restore drill не архивируется

Ожидание: caveat сообщает, что `audit-verify --restore-drill` автоматизирован,
но execution и evidence retention остаются operator-owned.

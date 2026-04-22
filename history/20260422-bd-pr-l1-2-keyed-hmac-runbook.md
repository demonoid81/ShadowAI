# PR-L1.2: Keyed HMAC для case_ref + runbook consistency

## Контекст
Review PR-L1.1 дал два замечания:

1. **Medium — plain hash brute-force-weak**: PR-L1.1 заменил raw
   `case_ref` в admin_event_logs / SIEM на truncated SHA-256 (16
   hex = 64 bit). Но SHA-256 без secret deterministic и открытый;
   attacker со SIEM-mirror dump'ом и знанием формата case_ref
   (например `SEC-2026-NNN`) может оффлайн brute-force'ить
   кандидаты и восстановить оригинальный identifier. Для
   regulated threat model нужен keyed HMAC.

2. **Low — runbook inconsistency**: §5 Legal Hold говорит
   `[implemented]` (PR-L1); §8.2 продолжает перечислять те же
   пункты как `[gap]`/`[planned]`. Ауди читает оба — запутывается.

PR-L1.2 закрывает оба.

## Scope (In)

### 1. Keyed HMAC tokenizer
- `legalhold.tokenizer` struct с `secret []byte` field.
- `Tokenize(caseRef) string` → HMAC-SHA256(secret, caseRef)[:8] hex.
- Fallback: пустой secret → unkeyed SHA-256 (PR-L1.1 behavior) +
  one-shot warning в stderr (`LEGAL_HOLD_TOKEN_SECRET not set,
  using unkeyed SHA-256 ... — DEV ONLY, brute-force-weak`).
- Все три callsites в handler.go (`apply success`, `apply conflict`
  409, `release success`) используют `h.tokens.Tokenize(...)`
  вместо глобальной `caseRefHash(...)`.
- `NewHandlerWithSecret(svc, adminAudit, tokenSecret)` — новый
  конструктор для prod-wiring. Старый `NewHandler(svc, adminAudit)`
  остаётся (unkeyed fallback) для существующих тестов.

### 2. Config + startup-guard
- Новое поле `Config.LegalHoldTokenSecret` (env
  `LEGAL_HOLD_TOKEN_SECRET`).
- `ValidateStartupConfig` в prod требует:
  - непустой secret → иначе error
    `"LEGAL_HOLD_TOKEN_SECRET must be set (>=32 chars) in prod..."`;
  - длина >=32 chars → иначе error `"must be >=32 chars..."`.
- Dev env игнорирует (в dev допустим fallback).

### 3. Wire в enterprise_wire.go
- `legalhold.NewHandlerWithSecret(svc, adminAuditRecorder,
  deps.Cfg.LegalHoldTokenSecret)` — передаёт secret в Handler.
- Когда ValidateStartupConfig прошёл в prod, secret гарантированно
  present → Tokenizer keyed.

### 4. Runbook §8.2 consistency
- `[gap]` bullets удалены: legal_hold table / enforcement /
  endpoints — всё now `[implemented]`.
- Добавлен bullet `[implemented]` (PR-L1.2) про keyed HMAC для
  case_ref токена.
- Остаются только настоящие gaps: retention-aware purge, 4-eyes
  approver, hold-scope шире user-level.
- Changelog 1.8 добавлен.

## Tests (все зелёные)

### legalhold (6 новых)
- `TestTokenizer_UnkeyedDeterministic` — backward compat
  (PR-L1.1 SHA-256 path).
- `TestTokenizer_KeyedDeterministic` — HMAC deterministic для
  SIEM correlation.
- `TestTokenizer_KeyedDiffersFromUnkeyed` — secret реально
  примешивается (proof of work).
- `TestTokenizer_DifferentSecretsProduceDifferentTokens` —
  ротация ключа меняет все tokens (osознанное поведение).
- `TestTokenizer_TokenLength_16Hex` — формат стабилен (keyed
  и unkeyed оба возвращают 16 hex).
- `TestNewHandlerWithSecret_UsesKeyed` — integration: Handler
  через `NewHandlerWithSecret` пишет keyed token, отличный от
  unkeyed для того же caseRef.

Существующие 24 теста не сломаны (старый `TestCaseRefHash_Deterministic`
переименован в `TestTokenizer_UnkeyedDeterministic`).

### config (4 новых)
- `TestValidateStartupConfig_LegalHoldSecretMissing` — prod без
  secret → error.
- `TestValidateStartupConfig_LegalHoldSecretTooShort` — <32 chars
  → error.
- `TestValidateStartupConfig_LegalHoldSecretOK` — 32+ chars → OK.
- `TestValidateStartupConfig_LegalHoldSecret_DevIgnored` — dev
  env принимает empty.

Existing prod-config tests обновлены: `prodConfigBase()` и
`TestValidateStartupConfig_ProdAllowsExplicitAuditOverrides` /
`TestValidateStartupConfig_ProdRejectsLoopbackHosts` получают
non-empty LegalHoldTokenSecret.

## Scope (Out / future)
- Secret rotation workflow (apply-hold событие с одним secret,
  release — с другим → SIEM correlation сломается). Сейчас это
  manual: оператор при rotation готов к re-correlation.
- Per-tenant secrets (v2, если появится multi-tenant).

## Acceptance
- [x] Plain SHA-256 → HMAC-SHA256 в case_ref tokenizer.
- [x] `LEGAL_HOLD_TOKEN_SECRET` required в prod (startup fail-fast).
- [x] Dev fallback работает с warning логом.
- [x] Существующие PR-L1.1 privacy guards (no raw case_ref) не
      регрессируют.
- [x] Runbook §8.2 больше не противоречит §5.
- [x] `go build ./...` + `go build -tags enterprise ./...` green.
- [x] `go test ./... -count=1` + `go test -tags enterprise ./...`
      полностью зелёные.

## Проверка
```bash
cd backend
go test -tags enterprise ./internal/legalhold -run Tokenizer -v
go test ./internal/config -run LegalHold -v
go test ./... -count=1                     # core matrix green
go test -tags enterprise ./... -count=1    # enterprise green
```

Ручная (после deploy с enterprise tag + env set):
```bash
export LEGAL_HOLD_TOKEN_SECRET=$(openssl rand -hex 32)
# apply hold → admin event должен содержать keyed token:
curl -X POST -H "Authorization: Bearer $ADMIN" -H "Content-Type: application/json" \
  -d '{"target_user_id":"u-1","case_ref":"SEC-2026-042","reason":"r"}' \
  http://localhost:8080/api/legal-holds
# Проверить:
psql "$DATABASE_URL" -c "
  SELECT metadata->>'case_ref_hash' AS token
  FROM admin_event_logs
  WHERE action='apply_hold' ORDER BY created_at DESC LIMIT 1;"
# Token должен отличаться от SHA-256('SEC-2026-042')[:16]
# (можно verify через: python3 -c 'import hashlib; print(hashlib.sha256(b"SEC-2026-042").hexdigest()[:16])')
```

## Риски / допущения
- **Rotation breaks correlation**: если operator ротирует
  LEGAL_HOLD_TOKEN_SECRET, SIEM-rules по `case_ref_hash` ломаются —
  старые events и новые больше не correlate'ятся. Документируем
  в runbook: rotation = planned break-point SIEM-rule'ам.
- **Operational tax**: +1 required env var в prod deployment.
  Смягчается startup fail-fast: оператор видит ошибку сразу.

## History
- Plan: этот файл.
- Related: PR-L1 (legal hold groundwork), PR-L1.1 (privacy + error
  split).

## Next roadmap (без изменений)
1. SIEM v1.1 (syslog/OTel/batching).
2. Legal hold v2 (retention-aware purge, 4-eyes, hold-scope).
3. G2 role-based governance.
4. WORM primary.
5. Firewall/runtime track.

# PR-L1.3: Scope fix для PR-L1.2 validation + tokenizer race

## Контекст
Review PR-L1.2 выявил два finding'а:

1. **High — core build contract break.** PR-L1.2 сделал
   `LEGAL_HOLD_TOKEN_SECRET` required в `ValidateStartupConfig`
   безусловно. `ValidateStartupConfig` живёт в Apache core
   package (`internal/config`), поэтому pure Core build
   (`go build ./cmd/shadowai` без `-tags enterprise`) тоже
   валил startup с `unsafe production config:
   LEGAL_HOLD_TOKEN_SECRET must be set...` — несмотря на то, что
   legalhold package в этом бинарнике вообще не скомпилирован.
   Это ломает L-1 build contract: Core-only deploy не должен
   требовать enterprise env vars.

2. **Low — data race в tokenizer warning.** `tokenizer.warnedUnkeyed`
   — bool, пишется из `Tokenize()` без sync. В prod concurrent
   admin requests → data race (редко релевантно, так как это
   dev fallback, но всё равно несоответствие sync-правилам Go).

PR-L1.3 закрывает оба.

## Scope (In)

### 1. Config validation split (build-tag)
- `internal/config/validate_enterprise.go` (`//go:build enterprise`):
  реализует `appendEnterpriseValidations(c, errs) []string` с
  реальным check'ом `LEGAL_HOLD_TOKEN_SECRET`.
- `internal/config/validate_core.go` (`//go:build !enterprise`):
  no-op stub того же hook'а.
- `Config.ValidateStartupConfig` вызывает hook. Core: check
  пропускается; Enterprise: check применяется.
- Паттерн — consistent с `cmd/shadowai/enterprise_wire.go` +
  `enterprise_stubs.go`.

### 2. Tokenizer race fix
- `tokenizer.warnedUnkeyed bool` → `tokenizer.warnOnce sync.Once`.
- Warning emit'ится через `warnOnce.Do(func() {...})` — безопасно
  при concurrent `Tokenize()` calls, гарантирует ровно один log
  per process.

### 3. Test split
- `internal/config/config_test.go`: существующие `TestValidateStartupConfig_LegalHold*`
  тесты **удалены** (они core-scope, но проверяют enterprise
  behavior — больше не работает).
- `internal/config/validate_enterprise_test.go`
  (`//go:build enterprise`): копия тех же 4 тестов, теперь
  tag'нуты enterprise.
- `internal/config/validate_core_test.go` (`//go:build !enterprise`):
  новый regression guard:
  `TestValidateStartupConfig_Core_NoLegalHoldSecretRequired` —
  prod core config с пустым `LEGAL_HOLD_TOKEN_SECRET` должен
  проходить validation без error.
- `internal/legalhold/handler_test.go`:
  `TestTokenizer_ConcurrentUnkeyed_NoRace` — 32 goroutines
  одновременно вызывают unkeyed Tokenize(), `-race` detector
  должен молчать.

## Acceptance
- [x] `go build ./...` (core) — pass.
- [x] `go build -tags enterprise ./...` — pass.
- [x] `go test ./... -count=1` (core) — green. Core-build prod
      config без secret теперь разрешён.
- [x] `go test -tags enterprise ./... -count=1` — green. Enterprise
      prod config без secret по-прежнему rejected.
- [x] `go test -tags enterprise -race ./internal/legalhold/` —
      green. Data race устранён.

## Проверка
```bash
cd backend
# Full matrix:
go test ./... -count=1
go test -tags enterprise ./... -count=1
go test -tags enterprise -race ./internal/legalhold/ -count=1
```

## Риски / допущения
- **Symmetrical split**: validate_core.go и validate_enterprise.go
  живут в одном package — это стандартный Go pattern для build-
  tag dispatch. Легко расширить другим enterprise-specific
  config checks если появятся.
- **Test symmetry**: core test suite и enterprise test suite
  имеют разный набор assertions — тестируют то, что реально
  enforce'ится в каждом build. Совокупное покрытие — 100% обоих
  code paths.

## History
- Plan: этот файл.
- Related: PR-L1.2 (keyed HMAC), L-1 (core/enterprise build split).

## Next roadmap (без изменений)
1. SIEM v1.1 (syslog/OTel/batching).
2. Legal hold v2 (retention-aware purge, 4-eyes, hold-scope).
3. G2 role-based governance.
4. WORM primary.
5. Firewall/runtime track.

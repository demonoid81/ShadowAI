# PR-S1.1: SIEM prod startup-validation guards

## Контекст
PR-S1 добавил SIEM mirror (HTTP fail-open). В v1 отсутствовали
prod-side проверки конфига — operator мог случайно deploy'нуть:
- `SIEM_ENABLED=true` без `SIEM_ENDPOINT` (audit trail тихо
  пропадает, mirror stays silent);
- `http://` endpoint (evidence stream in clear over the wire);
- `SIEM_INSECURE_SKIP_VERIFY=true` в prod (TLS-verify bypass).

PR-S1.1 добавляет fail-fast проверки в `ValidateStartupConfig`.

## Цель
Запретить в prod все три misconfiguration, дать dev/staging
свободу экспериментировать.

## Scope (In)
- Новое поле в `Config`: `SIEMAllowInsecureInProd` (env
  `SIEM_ALLOW_INSECURE_IN_PROD`).
- Три проверки в `ValidateStartupConfig` (активны только при
  `IsProduction() && SIEMEnabled`):
  1. Empty `SIEM_ENDPOINT` → error.
  2. Non-`https://` prefix → error (case-insensitive check).
  3. `SIEMInsecureSkipVerify=true` без `SIEMAllowInsecureInProd=true`
     → error.
- 7 новых тестов в `config_test.go`:
  - empty endpoint,
  - 3 non-https вариантов (http, ftp, no scheme) — table-driven,
  - insecure skip без override,
  - insecure skip с override,
  - happy prod config,
  - SIEM off с "грязным" endpoint → no error,
  - dev env игнорирует все правила.
- Runbook §8.4: новый `[implemented]` bullet; changelog 1.5.

## Scope (Out)
- Ротация bearer-токена (v1.1 задача).
- Runtime health-check на достижимость endpoint (сейчас —
  startup-only config validation; runtime failures видны через
  metrics).

## Примеры

### Valid prod config
```bash
APP_ENV=production
SIEM_ENABLED=true
SIEM_ENDPOINT=https://siem.example.com/ingest
SIEM_BEARER_TOKEN=splunk-hec-xxx
# SIEM_INSECURE_SKIP_VERIFY не задано → false (default)
```
`ValidateStartupConfig()` → nil. Старт OK.

### Rejected: SIEM on, endpoint empty
```bash
APP_ENV=production
SIEM_ENABLED=true
# SIEM_ENDPOINT забыт в env
```
Startup fails: `unsafe production config: SIEM_ENABLED=true
requires SIEM_ENDPOINT in prod (empty endpoint hides mirror failure)`.

### Rejected: http:// endpoint
```bash
APP_ENV=production
SIEM_ENABLED=true
SIEM_ENDPOINT=http://siem.internal/ingest
```
Startup fails: `unsafe production config: SIEM_ENDPOINT must use
https:// in prod (evidence stream requires in-transit encryption)`.

### Rejected: insecure skip без override
```bash
APP_ENV=production
SIEM_ENABLED=true
SIEM_ENDPOINT=https://siem.internal/ingest
SIEM_INSECURE_SKIP_VERIFY=true
# SIEM_ALLOW_INSECURE_IN_PROD не задано → false
```
Startup fails: `SIEM_INSECURE_SKIP_VERIFY=true requires
SIEM_ALLOW_INSECURE_IN_PROD=true in prod (TLS verify bypass)`.

### Accepted: insecure skip с explicit override
```bash
APP_ENV=production
SIEM_ENABLED=true
SIEM_ENDPOINT=https://siem.internal/ingest
SIEM_INSECURE_SKIP_VERIFY=true
SIEM_ALLOW_INSECURE_IN_PROD=true  # явное признание риска
```
Startup OK. Use-case: internal CA, cert которой не в trust-store
контейнера. Операция осознанная и логгируется через env review.

### Dev env — все правила off
```bash
APP_ENV=development
SIEM_ENABLED=true
SIEM_ENDPOINT=http://localhost:8088/ingest
SIEM_INSECURE_SKIP_VERIFY=true
```
Startup OK. `IsProduction()=false` → все SIEM-guards игнорируются.

## Acceptance criteria
- [x] Валидация срабатывает только в prod (`IsProduction()==true`).
- [x] Каждая из трёх ошибок содержит читаемое описание +
      упоминание override env-переменной или правильной схемы.
- [x] Несколько SIEM-ошибок в одном конфиге аккумулируются
      (через общий `errs []string` + `strings.Join`).
- [x] SIEM off с "грязным" endpoint не вызывает ошибку (gate на
      `c.SIEMEnabled`).
- [x] 7 regression-тестов, все зелёные.
- [x] Core + enterprise builds чисты; full test matrix green.

## Проверка
```bash
cd backend
go test ./internal/config -run TestValidateStartupConfig_SIEM -v
# 8 PASS (включая table-subtests)
go test ./... -count=1                      # core matrix green
go test -tags enterprise ./... -count=1     # enterprise matrix green
```

## Риски / допущения
- В `ValidateStartupConfig` нет URL-парсера: проверка на `https://`
  через `strings.HasPrefix(..., "https://")` + lowercase. Этого
  достаточно — если строка невалидна как URL, HTTP client её позже
  отвергнёт (и event'ы пойдут в `shadowai_siem_fail_total`).
- `SIEM_ALLOW_INSECURE_IN_PROD=true` оставляет в логах явный
  audit trail (env review); это сознательная политика — есть
  legitimate случаи (internal CA, air-gapped deploy).

## History
- Plan: этот файл.
- Examples: в конфиг-блоках выше.

## Next
Roadmap пока не меняется — см. PR-S1 history для списка следующих
шагов (SIEM v1.1 syslog/OTel, tamper-evident WORM, legal hold,
G2 role-based, firewall/runtime track).

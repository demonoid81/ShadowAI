# ShadowAI-ux10 — Examples

## Happy path 1 — Operations liveness OK

Вход: `GET /api/health` возвращает `{"status":"ok"}`.

Ожидаемый результат: live card `Process liveness` получает статус `live ok`, detail сообщает что процесс отвечает на liveness probe.

## Happy path 2 — Operations readiness OK

Вход: `GET /api/ready` возвращает `{"ready":true,"checks":{"db":{"ok":true},"redis":{"ok":true}}}`.

Ожидаемый результат: readiness card получает статус `live ok`, оператор видит что DB и Redis доступны.

## Edge case 1 — Readiness degraded

Вход: `GET /api/ready` возвращает `{"ready":false,"checks":{"db":{"ok":true},"redis":{"ok":false}}}`.

Ожидаемый результат: readiness card получает статус `failed`, detail перечисляет `redis` как failed check. UI не показывает зелёный статус.

## Edge case 2 — Firewall disabled

Вход: `/proxy/firewall/status` доступен, но возвращает `enabled:false`.

Ожидаемый результат: firewall card получает статус `review`, не `live ok`; это runtime warning, а не network failure.

## Failure case — Signal endpoint unavailable

Вход: любой live endpoint падает по network/403/404.

Ожидаемый результат: соответствующая card получает статус `unknown`; статические capability cards не используются как fallback-green.

## Dashboard API failure

Вход: `/api/dashboard/stats`, `/usage` или `/top-users` возвращает ошибку.

Ожидаемый результат: соответствующий dashboard block показывает error state, а block rate отображается как `unknown`, не `0.0%`.

## Empty live data

Вход: `/api/dashboard/usage` или `/top-users` возвращает пустой массив.

Ожидаемый результат: UI показывает empty state, не пустую таблицу и не fake readiness.

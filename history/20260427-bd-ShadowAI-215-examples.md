# bd ShadowAI-215 — примеры L7 legal hold SLA / DPO signals

## Успешный сценарий 1 — pending hold превысил SLA

Hold со статусом `pending` создан 25 часов назад, threshold равен 24 часа.

Ожидаемое поведение:

- scheduler создаёт `admin_event_logs.action=legal_hold_sla_breached`;
- metadata содержит `event_code=legal_hold_pending_sla_breached`;
- SIEM получает событие через fanout recorder;
- metric `shadowai_legal_hold_sla_breaches_total{status="pending"}` увеличивается.

## Успешный сценарий 2 — release_pending hold превысил SLA

Hold перешёл в `release_pending` 49 часов назад, threshold равен 24 часа.

Ожидаемое поведение:

- scheduler создаёт SLA event;
- metadata содержит `event_code=legal_hold_release_pending_sla_breached`;
- age считается от `release_requested_at`, а не от `created_at`;
- alert `LegalHoldReleasePendingSLABreached` может сработать.

## Граничный сценарий 1 — pending hold ещё внутри SLA

Hold создан 2 часа назад, threshold равен 24 часа.

Ожидаемое поведение:

- event не создаётся;
- breach counter не увеличивается;
- gauge oldest age для статуса остаётся 0 или отражает только текущих breach candidates.

## Граничный сценарий 2 — повторный scan в том же day bucket

Первый scan уже создал event для `hold_id + status + YYYY-MM-DD`.

Ожидаемое поведение:

- второй scan находит candidate, но пропускает duplicate;
- SIEM не получает повтор;
- report увеличивает `DuplicatesSkipped`.

## Ошибка 1 — repo не поддерживает SLA monitor interface

Service сконфигурирован с repository, у которого нет `HoldsOlderThanStatus`/`SLASignalExists`.

Ожидаемое поведение:

- `EmitSLASignals` возвращает ошибку;
- scheduler пишет `legal_hold_sla_scan_failed`;
- приложение продолжает работать.

## Ошибка 2 — invalid prod config

`LEGAL_HOLD_SLA_SCAN_INTERVAL=0` или threshold равен 0.

Ожидаемое поведение:

- production startup validation возвращает config error;
- Helm values по умолчанию задают валидные значения.

## Сигнал DPO — DSAR заблокирован legal hold

Admin запускает DSAR erasure, но target user находится под `active` или `release_pending` hold.

Ожидаемое поведение:

- erasure endpoint возвращает `409 hold_active`;
- обычный `erase` admin event сохраняется;
- дополнительно создаётся `admin_event_logs.action=dsar_blocked_by_legal_hold`;
- metric `shadowai_dsar_dpo_signal_total{result="blocked_by_hold"}` увеличивается.

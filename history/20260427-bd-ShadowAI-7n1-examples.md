# bd ShadowAI-7n1 — примеры L6 scoped legal holds

## Успешный сценарий 1 — legacy whole-user hold

Запрос без `scope_type` создаёт hold со scope `whole_user`.

Ожидаемое поведение:

- create возвращает `201`.
- persisted hold имеет `scope_type=whole_user`.
- после approve retention purge не удаляет старые `audit_logs` этого user вне зависимости от `created_at`.

## Успешный сценарий 2 — date-range hold защищает строки внутри диапазона

Hold создаётся с:

```json
{
  "scope_type": "date_range",
  "scope_date_from": "2026-04-01T00:00:00Z",
  "scope_date_to": "2026-04-30T23:59:59Z"
}
```

Ожидаемое поведение:

- audit row target user с `created_at=2026-04-10T12:00:00Z` остаётся после purge.
- purge run записывается штатно.
- DSAR для user блокируется, потому что whole-user erasure затрагивает held data.

## Граничный сценарий 1 — date-range hold не защищает строки вне диапазона

Для того же hold audit row с `created_at=2026-03-20T12:00:00Z` остаётся eligible для retention purge.

Ожидаемое поведение:

- row вне диапазона удаляется при cutoff старше retention threshold.
- row внутри диапазона остаётся.
- deleted count отражает только реально удалённые rows.

## Граничный сценарий 2 — release_pending всё ещё защищает

Hold прошёл `active → release_pending`, но release ещё не approved вторым admin.

Ожидаемое поведение:

- retention purge не удаляет protected rows.
- защита снимается только после `ApproveRelease`.
- после terminal `released` purge снова может удалить eligible rows.

## Ошибка 1 — некорректный date range

Запрос:

```json
{
  "scope_type": "date_range",
  "scope_date_from": "2026-05-01T00:00:00Z",
  "scope_date_to": "2026-04-01T00:00:00Z"
}
```

Ожидаемое поведение:

- service возвращает `ErrInvalidScopeRange`.
- HTTP API возвращает `400`.
- hold не создаётся.
- admin event содержит `error_code=invalid_scope_range`.

## Ошибка 2 — query_scope не поддержан

Запрос:

```json
{
  "scope_type": "query_scope"
}
```

Ожидаемое поведение:

- HTTP API возвращает `400 unsupported scope_type`.
- hold не создаётся.
- admin event содержит `error_code=unsupported_scope_type`.

## Ошибка 3 — неизвестный scope_type

Запрос с `scope_type="conversation"` отклоняется так же, как unsupported scope.

Ожидаемое поведение:

- нет silent fallback к `whole_user`;
- нет чрезмерной или непредсказуемой блокировки purge;
- operator должен выбрать поддержанный scope.

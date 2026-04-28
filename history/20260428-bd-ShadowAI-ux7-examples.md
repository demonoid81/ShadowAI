# bd ShadowAI-ux7 — примеры

## Happy path 1 — создание hold

1. Admin открывает `/legal-holds`.
2. Заполняет `target_user_id`, `case_ref`, `reason`, scope `whole_user`.
3. Нажимает create.
4. UI добавляет hold в таблицу со status `pending`.

Ожидаемый результат: оператор видит pending hold и может передать его на approve другому admin.

## Happy path 2 — release approval

1. Hold находится в status `active`.
2. Admin нажимает `Request release`.
3. После reload hold получает status `release_pending`.
4. Другой admin нажимает `Approve release`.
5. UI reload-ит список и показывает финальный статус из backend.

Ожидаемый результат: UI не делает optimistic state mutation и доверяет backend state machine.

## Edge case 1 — bulk approve с partial failure

1. Admin выбирает несколько pending holds.
2. Backend возвращает часть results с `success=false` и `error`.
3. UI показывает summary `success/failures` и таблицу per-item results.

Ожидаемый результат: failure не скрывается, оператор видит конкретный hold ID и error.

## Edge case 2 — admin events org context filter

1. Admin открывает `/admin-events`.
2. Backend фильтрует actor/resource/action.
3. Пользователь вводит org/source/target ID в org filter.
4. UI фильтрует текущую страницу результата по `org_id`, `source_org_id`, `target_org_id`.

Ожидаемый результат: контекст org виден без ложного заявления, что backend выполняет этот фильтр глобально по всем страницам.

## Failure case — self-approval или forbidden transition

1. Admin пытается approve/reject/release action, которую backend запрещает.
2. Backend возвращает error, например self-approval или invalid state.
3. UI показывает error banner и не скрывает hold из таблицы.

Ожидаемый результат: sensitive legal state не меняется оптимистично; ошибка остаётся видимой оператору.

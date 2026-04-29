# Примеры для `ShadowAI-n7p`

## Happy path 1 — stage только подтверждённых файлов

Вход:

- `CLAUDE.md`
- `deploy/helm/shadowai/docs/deploy-checklist.md`
- `deploy/helm/shadowai/docs/secret-matrix.md`
- `history/20260419-discussion-llm-security-business-requirements.md`

Ожидаемый результат:

- Эти файлы попадают в commit.
- Неподтверждённые binaries и служебные каталоги остаются вне commit.

## Happy path 2 — push после commit

Вход:

- `master` содержит новый docs commit.

Ожидаемый результат:

- `git push origin master` обновляет remote.
- `origin/master...HEAD` даёт `0 0`.

## Edge case 1 — смешанное рабочее дерево

Ситуация:

- Есть modified `backend/cmd/shadowai/main.go`, который не подтверждён для этого push.

Ожидаемый результат:

- Файл остаётся локально dirty.
- В commit не попадает.

## Edge case 2 — untracked binaries

Ситуация:

- В `backend/` есть untracked CLI binaries.

Ожидаемый результат:

- Они не stage-ятся и не пушатся.

## Failure case — случайный `git add -A`

Ситуация:

- Агент использует `git add -A` в смешанном дереве.

Ожидаемый результат:

- Это считается нарушением scope.
- В этой задаче используется explicit path staging.

# Задача

`ShadowAI-n7p` — push approved docs files.

# Контекст

Пользователь явно подтвердил, что можно отправить в ветку четыре файла:

- `history/20260419-discussion-llm-security-business-requirements.md`
- `CLAUDE.md`
- `deploy/helm/shadowai/docs/deploy-checklist.md`
- `deploy/helm/shadowai/docs/secret-matrix.md`

Рабочее дерево смешанное: есть другие modified/untracked файлы, которые не входят в scope.

# План

1. Проверить diff/содержимое подтверждённых файлов.
2. Stage только подтверждённые файлы и history artifacts этой bd-задачи.
3. Проверить `git diff --cached --check`.
4. Commit.
5. Push `master`.
6. Проверить синхронизацию `origin/master...HEAD`.

# Размышления

Рассмотрены два варианта: запушить всё рабочее дерево или только явно подтверждённые файлы.

Принято решение stage-ить только подтверждённый набор, потому что рабочее дерево содержит unrelated binaries, служебные каталоги и отдельный dirty `backend/cmd/shadowai/main.go`.

Альтернатива `git add -A` отклонена как небезопасная: она включила бы неподтверждённые артефакты.

# Definition of Done

- Commit содержит только подтверждённые docs/history файлы, `.beads` metadata и history artifacts задачи.
- Остальные dirty/untracked файлы не попали в commit.
- Push выполнен.
- `origin/master` синхронизирован с `HEAD`.

# Проверка

Фиксируется в итоговом ответе после commit/push.

# Roadmap

v1: безопасно запушить подтверждённый docs-only набор.

v2+: отдельно решить судьбу оставшихся локальных dirty/untracked файлов.

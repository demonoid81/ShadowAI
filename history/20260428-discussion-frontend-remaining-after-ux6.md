Тема / вопрос
Что ещё осталось по frontend после закрытия UX4, UX5 и UX6.

Контекст
Источник истины — локальный `.beads/issues.jsonl` и последние git-коммиты.
CASS недоступен в текущем data dir, поэтому не использовался как источник прошлого контекста.

Размышления
Рассмотрены оставшиеся задачи frontend-эпика `ShadowAI-9zi`.
Зафиксировано, что закрыты:
- UX4 Settings & Admin Control Center read-only v1.
- UX5 Tenant Admin CRUD and SCIM token management.
- UX6 Auth UX hardening: MFA, OIDC, break-glass and profile.

Открыты:
- UX7 Legal Holds and Admin Events UI.
- UX8 Governance Policy v2 UI.
- UX9 Compliance report workspace.
- UX10 Operations live health and dashboard accuracy.

Варианты решений
Вариант A — продолжать строго по roadmap: UX7 → UX8 → UX9 → UX10.
Плюс: соответствует эпик-плану и закрывает compliance/legal workflows раньше визуальных polish-задач.
Минус: UX8 имеет priority 1 в bd, но стоит после UX7 в roadmap.

Вариант B — идти по priority из bd: UX8 → UX7 → UX9 → UX10.
Плюс: быстрее закрывается governance policy v2, ключевой business control.
Минус: нарушает уже зафиксированный порядок эпика.

Рекомендованное направление
Продолжать по roadmap: UX7 → UX8 → UX9 → UX10, потому что пользователь явно разрешил делать задачи по порядку.

Открытые вопросы
Нет блокирующих вопросов. При реализации каждой задачи backend contracts должны подтверждаться по фактическому коду.

Возможные следующие шаги
1. UX7 — Legal Holds and Admin Events UI.
2. UX8 — Governance Policy v2 UI.
3. UX9 — Compliance report workspace.
4. UX10 — Operations live health and dashboard accuracy.

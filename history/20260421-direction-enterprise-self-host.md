# Direction Decision: Enterprise / Self-Host / Open-Core

**Дата:** 2026-04-21
**Статус:** утверждено пользователем (decision-record).
**Горизонт:** 6 месяцев.
**Применяется к:** все последующие PR-решения должны проверяться
против этого контракта.

---

## Решение

| Ось | Выбор |
|---|---|
| Приоритетный сегмент | **Regulated enterprise** |
| Deployment model | **Self-host / single-tenant** (не SaaS, не multi-tenant) |
| Licensing | **Open-core** (OSS proxy+inspectors; commercial privacy/governance/enterprise features) |
| Product story | **LLM Firewall + LLM Security / Privacy control plane** |
| GTM messaging | privacy, audit, rollout safety, multi-provider governance |
| Benchmark publication | отложено — сначала привести к public datasets (Garak/PromptBench/JailbreakBench), убрать internal-only tuning, подготовить methodology note. До этого — только sales engineering |
| SOC 2 | с консультантом (не самостоятельно) |

---

## Почему

- Privacy/audit/retention/DSAR/rollout трек уже глубокий (PR-A/B/C/D/D.1/E).
  Это совпадает с приоритетами regulated enterprise.
- Не нужно немедленно выигрывать у Lakera/Prompt Armor по detection-бюджету.
- Self-host снимает много enterprise objections (data residency,
  vendor lock-in, "read the code") без инвестиций в SaaS
  control-plane.
- Open-core позволяет монетизировать именно то, что бизнесу нужно —
  governance, privacy, compliance tooling.

---

## Обновлённый roadmap

### Now (следующие 1-2 цикла)
1. **User-read access audit** — `GET /api/users/{id}` в `admin_event_logs`.
   Закрывает gap §8.5 runbook. Маленький PR, быстрый win.
   **Не блокируется licensing decision.**
2. **Licensing decision session** — отдельной стратегической сессией,
   до PR-G1. Зафиксировать:
   - license model (Apache-2.0 + proprietary enterprise / AGPL +
     commercial exception / BSL / другое).
   - OSS vs commercial boundary.
   - rule of thumb ("runtime core OSS, governance/privacy
     commercial" или альтернатива).
3. **PR-G1: Provider/Model Governance** — after licensing decision.
4. **EU AI Act / ISO 42001 / SOC 2 control mapping** — docs PR
   (параллельно, не блокирует остальное).

### Next
- **Backup post-restore scrub** (CLI).
- **Legal hold groundwork** (`legal_holds` table + enforce в
  `ScrubUserDataTx`).
- **SIEM integration** (append-only mirror `admin_event_logs`).

### Later / deferred
- **PR-7** (Stage 2 streaming passthrough) — только если phase shift
  в SaaS/general runtime.
- **PR-F** (tenant isolation) — только если SaaS/platform direction.

---

## Provider governance scope (утверждено)

### PR-G1: Provider/Model allowlist + policy visibility

**In:**
- config: `ALLOWED_PROVIDERS`, `ALLOWED_MODELS_<PROVIDER>` (или
  структурированный YAML/JSON policy file).
- deny-by-default option (`ALLOWED_PROVIDERS_DENY_UNLISTED=true`).
- Enforce: запрос на запрещённую комбинацию → 403 + audit event.
- Audit: policy violation в `admin_event_logs` с `action=policy_denied`,
  `resource=provider_governance`, metadata `{provider, model,
  reason}`.
- Status endpoint / расширение `/api/firewall/status`:
  effective policy visible (какие providers/models allowed).
- Docs: "как объяснить customer, куда могут уходить данные".

**Out (deferred to PR-G2/G3):**
- Role-based routing ("role X only to provider Y").
- Sensitivity-based routing (pii → stricter set).
- Provider inventory / DPA metadata / compliance report export.

### PR-G2: Sensitivity/Role-Based Routing (later)
role/endpoint/pii-class → allowed providers; fallback policy.

### PR-G3: Provider compliance inventory (later)
DPA/region/retention notes; customer-facing policy evidence export.

---

## Licensing decision timing

**Правило:** licensing decision **не позже чем перед merge PR-G1.**

Обоснование:
- PR-G1 "Provider/Model Governance" попадает в commercial boundary
  почти наверняка.
- Если сейчас всё идёт в OSS default, откат governance/admin
  audit/privacy controls в commercial tier будет болезненным
  (license migration нужен для existing forks).
- User-read access audit (этот PR) — маленький security fix,
  безопасно мержится в текущий default без привязки к commercial
  split.

---

## Как применять decision при PR-review

Каждый новый PR должен отвечать:
1. Какому сегменту он служит? (enterprise / SaaS / dev / platform)
2. Если не enterprise — **отложено**, если нет явного argument'а.
3. Затрагивает ли commercial boundary? Если да — упомянуть в
   licensing decision session.
4. Упоминается ли в `docs/privacy-ops-runbook.md §8 Known Gaps`?
   Если да — обновить статус.

---

## Открытые вопросы на licensing session

1. License model (Apache-2.0 core + proprietary / AGPL + exception /
   BSL /...).
2. Boundary: runtime vs governance? Inspector-depth vs audit-depth?
3. Enterprise tier pricing model (per-deploy / per-seat / usage).
4. Existing committed PRs: нужен ли re-licensing или cutoff commit.
5. Public repo structure: monorepo с commercial subdir / split repos.

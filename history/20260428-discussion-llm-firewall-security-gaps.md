# Обсуждение — остатки по LLM firewall и LLM security

## Тема / вопрос

Каких обещанных или подразумеваемых возможностей ещё нет в ShadowAI по направлению
LLM firewall и LLM security.

## Контекст

- CASS health вернул stale index, поэтому CASS не использовался как актуальный
  источник истины.
- Использованы локальные источники: `docs/firewall.md`,
  `docs/production-hardening.md`,
  `docs/runbooks/streaming-production-proof.md`,
  `docs/rfcs/2026-04-pr-f7-streaming-architecture.md`,
  `docs/rfcs/2026-04-pr-byok1-kms-byok-design.md`,
  `docs/compliance/soc2-iso-control-mapping.md`, а также фактический код
  streaming-adapter'ов и incremental engine.

## Что уже есть

- LLM Firewall описан как двусторонний pipeline для request/response inspection
  с 10 инспекторами: PII, DLP, policy, prompt injection, jailbreak, content
  moderation, output validation, content rate limiter, multi-turn и semantic.
- Request-side защита покрывает prompt injection, jailbreak, PII/DLP, policy и
  semantic checks.
- Response-side защита есть в buffered mode и в incremental mode для
  heuristic-based инспекторов через sliding window.
- Streaming track реализовал adapters, incremental inspection, shadow compare,
  structured audit outcomes и OpenAI-compatible incremental sanitize.
- semantic_v2 имеет shadow-only rollout, `would_block`/`fail_open` метрики и
  production validation для endpoint/provider/corpus.
- Security/compliance вокруг LLM usage усилены: tenant isolation, governance,
  org budgets, SIEM, WORM evidence, evidence bundles и access review.

## Чего ещё нет / что нельзя обещать как готовое

1. **Полный provider-agnostic incremental sanitize.**
   OpenAI-compatible SSE поддерживает `EmitSanitized`, но Anthropic, Gemini и
   Ollama пока используют identity-stub: sanitize verdict пишется в audit, но
   payload не переписывается. Production-hardening прямо запрещает включать
   incremental prod для этих providers до полной реализации или ограничения
   traffic только OpenAI-compatible.

2. **Cross-chunk PII sanitize.**
   Incremental engine sanitizes текущий delta, а не весь sliding window.
   PII, разрезанная между несколькими chunks, явно оставлена в F7.6 scope.

3. **Выполненная production proof window для streaming.**
   Есть runbook F7.6 с 30-дневным процессом, метриками и threshold'ами, но
   локальные документы фиксируют именно процесс proof window, а не факт его
   прохождения на реальном production traffic.

4. **Полная semantic_v2 enforcement maturity.**
   semantic_v2 есть, но recommended default остаётся disabled/shadow-only до
   накопления стабильного baseline. Это не доказанная production-модель
   обнаружения всех paraphrased jailbreak/prompt-injection сценариев.

5. **LLM-as-Judge как fail-closed security boundary.**
   Judge documented как latency-sensitive: parsing/http failures не должны
   превращать firewall в SPOF. В streaming CM+judge уходит в buffered fallback.
   Поэтому нельзя продавать judge как безусловный hard-block на каждую ошибку
   или как гарантию отсутствия jailbreak.

6. **BYOK / customer-managed encryption.**
   BYOK1 — только RFC/design. Payload fields остаются plaintext; KMS/BYOK2 не
   реализован. Это относится к LLM security/confidentiality, а не к runtime
   firewall verdict'ам.

7. **Формальная внешняя security validation.**
   Есть unit/smoke/perf/security controls, но локальные документы фиксируют
   отсутствие formal penetration test / third-party assessment и отсутствие
   SOC2/ISO certification.

8. **SAML и полноценный enterprise identity matrix.**
   Реализован OIDC/SCIM/MFA, но SAML отсутствует. Это не блокирует LLM firewall,
   но ограничивает enterprise security обещания для клиентов, где SAML обязателен.

9. **Vendor/LLM provider risk program.**
   Governance ограничивает provider/model usage, но SOC mapping фиксирует, что
   formal third-party risk/vendor assessment process для LLM providers отсутствует.

10. **Мгновенная multi-replica policy invalidation.**
    Governance cache снижает DB load, но production-hardening фиксирует lag до
    60 секунд. Для emergency-block политики это нужно учитывать операционно.

## Размышления

Рассмотрены два способа формулировки статуса:

- назвать всё закрытым, так как большинство engineering-фич реализовано;
- отделить реализованные controls от operational proof, external validation и
  provider-specific gaps.

Принято решение использовать вторую формулировку. Она точнее для продаж и
security review: продукт уже имеет сильный LLM firewall/control-plane baseline,
но некоторые claims требуют caveat или отдельного scope.

Альтернатива "LLM security полностью готова" отклонена: локальные документы
прямо фиксируют BYOK design-only, no formal pen test, streaming provider sanitize
stub и proof-window process вместо завершённого proof.

## Рекомендованное направление

Если цель — честный business/security claim, безопасная формулировка:

> ShadowAI provides a production-grade LLM firewall and governance control plane
> for controlled enterprise deployments, with request/response inspection,
> streaming safeguards, auditability and tenant governance. Provider-specific
> incremental sanitize, BYOK encryption, formal penetration testing and
> third-party compliance certification remain explicit roadmap/final-validation
> items.

## Открытые вопросы

- Нужен ли F7.7 как реализация non-OpenAI `EmitSanitized` для Anthropic,
  Gemini и Ollama?
- Должна ли semantic_v2 перейти из shadow-only в enforce для production по
  отдельному promotion документу?
- Есть ли customer requirement на BYOK2/KMS сейчас, или это остаётся
  roadmap-after-demand?
- Нужен ли независимый pen test до первого regulated customer deployment?

## Возможные следующие шаги

1. F7.7 — full incremental sanitize для Anthropic/Gemini/Ollama.
2. F8.1 — semantic_v2 promotion package: corpus validation, dashboards,
   enforce criteria.
3. SEC1 — external red-team / penetration-test readiness package.
4. BYOK2 — KMS/envelope encryption implementation, если есть customer/KMS
   requirement.
5. DOC1 — обновить публичные claims, чтобы отделить implemented controls от
   roadmap/validation items.

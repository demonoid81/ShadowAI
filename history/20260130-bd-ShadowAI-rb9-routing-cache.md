# Intelligent Routing + Fallback Chain & Semantic Cache

**bd:** ShadowAI-rb9
**Дата:** 2026-01-30
**Статус:** Завершено

## Контекст

Proxy-сервер поддерживает несколько AI-провайдеров, но требует явного указания провайдера в URL.
Необходимы единый endpoint с автовыбором провайдера и кэширование ответов.

## Решения

### Intelligent Routing
- Единый `POST /proxy/chat` без указания провайдера
- `ModelMapper` — автоопределение провайдера по модели (exact match + prefix heuristic)
- `Router` — три стратегии: `cheapest`, `fastest`, `round-robin`
- Fallback chain: при ошибке провайдера автопереход к следующему кандидату
- `HealthTracker` — запись success/failure/latency в Redis (TTL 10 мин)

### Semantic Cache
- Exact-match кэш в Redis по SHA256(provider + model + messages)
- TTL настраивается через `CACHE_TTL`
- Не кэшируется: streaming, non-2xx, X-No-Cache: true
- Hit/miss счётчики для метрик

## Новые файлы
- `backend/internal/proxy/router.go` — Router
- `backend/internal/proxy/router_test.go` — тесты
- `backend/internal/proxy/health.go` — HealthTracker
- `backend/internal/proxy/health_test.go` — тесты
- `backend/internal/proxy/model_map.go` — ModelMapper
- `backend/internal/proxy/model_map_test.go` — тесты
- `backend/internal/proxy/cache.go` — SemanticCache
- `backend/internal/proxy/cache_test.go` — тесты

## Изменённые файлы
- `backend/internal/config/config.go` — 4 env vars
- `backend/internal/proxy/registry.go` — FindByModel()
- `backend/internal/proxy/handler.go` — UnifiedChat, health recording
- `backend/cmd/shadowai/main.go` — инициализация, маршрут /proxy/chat

## Env vars
- `ROUTING_STRATEGY` — cheapest|fastest|round-robin (default: cheapest)
- `FALLBACK_ORDER` — comma-separated provider names (optional)
- `CACHE_ENABLED` — true|false (default: true)
- `CACHE_TTL` — duration (default: 1h)

## Тесты
Все тесты проходят: model_map, health, router, cache + все предыдущие.

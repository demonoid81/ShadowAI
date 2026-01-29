# ShadowAI — AI Control Plane: Реализация

## Контекст
Полная реализация ShadowAI — платформы контроля доступа к AI API.

## Стек
- **Backend**: Go (gorilla/mux + gorilla/websocket), PostgreSQL 16, Redis 7
- **Frontend**: Vue 3 (Composition API, TypeScript), Pinia, Tailwind CSS, Chart.js
- **Инфраструктура**: Docker Compose

## Реализованные модули

### Backend (36 файлов)
- **config** — загрузка конфигурации из env-переменных
- **domain** — 4 доменных типа (User, AuditLog, PolicyRule, Budget)
- **auth** — JWT + bcrypt + API-key, middleware, CRUD пользователей
- **proxy** — reverse proxy к OpenAI с pipeline (PII → Policy → Budget → Forward → Audit)
- **pii** — regex-детектор (email, phone, credit_card, ssn, ip_address) + 7 тестов
- **policy** — движок политик (pii_block, pii_warn, keyword_block, model_restrict)
- **audit** — асинхронная запись через буферизованный Go-канал
- **budget** — Redis-счётчики (INCRBY) + PG sync
- **dashboard** — агрегационные SQL-запросы
- **middleware** — CORS, logging, recovery, rate limiting (Redis sliding window)
- **platform** — PostgreSQL и Redis адаптеры
- **migrations** — 4 SQL-миграции

### Frontend (28 файлов)
- Vue 3 + Vite + Pinia + Vue Router + Tailwind CSS
- 6 страниц: Login, Dashboard, AuditLog, Policies, Budget, Users
- 5 компонентов: StatsCard, UsageChart, RequestTable, PolicyRuleForm, BudgetGauge
- Axios с JWT-интерсепторами, auth guard

### Инфраструктура
- docker-compose.yml (postgres, redis, backend, frontend)
- Dockerfiles для backend (multi-stage Go) и frontend (Vite build + nginx)
- nginx.conf с проксированием API и SPA fallback
- Makefile, seed.sql

## Ключевые решения
- gorilla/mux вместо chi (по требованию пользователя)
- Процедурный pipeline в proxy handler — body читается один раз
- Async audit через Go-канал на 1000 записей
- Redis sliding window для rate limiting
- Первый зарегистрированный пользователь автоматически становится admin

## Верификация
- `go build ./...` — успешно
- `go test ./...` — 7/7 PII-тестов пройдены
- npm install — 152 пакета установлены

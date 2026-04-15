# ShadowAI

Контрольная плоскость для работы с LLM API: единый прокси-сервис с политиками, аудитом и бюджетированием.

## Состав
- Backend: Go + Gorilla Mux, PostgreSQL, Redis
- Frontend: Vue 3 + Pinia + Vue Router
- Reverse proxy: OpenAI, Anthropic, Gemini, Mistral, Groq, OpenRouter, Ollama

## Быстрый запуск
1. Скопировать переменные окружения в `.env` (по желанию):
   - `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`
   - `REDIS_URL`, `DATABASE_URL`, `JWT_SECRET`
   - `ROUTING_STRATEGY`, `FALLBACK_ORDER`, `CACHE_ENABLED`, `CACHE_TTL`
   - `CORS_ALLOWED_HOSTS` (по умолчанию: `http://localhost:3000,http://localhost:5173`)
   - `ALLOWED_PROVIDER_HOSTS` (по умолчанию: `api.openai.com,api.anthropic.com,generativelanguage.googleapis.com,api.mistral.ai,api.groq.com,openrouter.ai,localhost`)
   - в `ALLOWED_PROVIDER_HOSTS` поддерживается wildcard-паттерн вида `*.subdomain.example.com`
   - `TRUSTED_PROXY_CIDRS` (CIDR-блоки доверенных reverse-proxy/load balancer, например `10.0.0.0/8,172.16.0.0/12`)
   - `SERVER_READ_TIMEOUT`, `SERVER_WRITE_TIMEOUT`, `SERVER_IDLE_TIMEOUT`, `SERVER_READ_HEADER_TIMEOUT` (формат Go `time.Duration`, например `15s`, `120s`)
   - `PROVIDER_CONNECTIVITY_INTERVAL` (расписание автопроверки сетевой доступности провайдеров, например `5m`, по умолчанию `5m`; `0` — отключает)
   - `DLP_MODE` (`audit`, `enforce`, `strict`, по умолчанию `enforce`)
   - `INTERNAL_DB_SOURCES` (например `crm=postgres://user:pass@10.0.0.5:5432/crm_db?sslmode=require,erp=postgres://user:pass@10.0.0.6:5432/erp_db?sslmode=require`)
   - `INTERNAL_DB_REFRESH_INTERVAL` (интервал фоновой синхронизации источников из БД, например `30s`, по умолчанию `30s`)
   - `INTERNAL_DB_QUERY_TIMEOUT` (таймаут на SQL-запросы во внутренних БД, например `8s`, по умолчанию `8s`)
   - `SERVER_MAX_HEADER_BYTES` (максимальный размер заголовков в байтах, по умолчанию `1048576`)
   - `MAX_COMPLETION_TOKENS` (ограничение ожидаемого лимита токенов ответа для stream/оценки бюджета; 0 — без cap, по умолчанию `0`)
   2. Запустить инфраструктуру:
   - `make up`
3. Применить миграции:
   - `make migrate`
4. (Опционально) загрузить seed:
   - `make seed`
5. Запустить сервисы:
   - `make up` (postgres, redis, backend, frontend)

## API
- `POST /api/auth/login`, `POST /api/auth/register`
- `POST /api/auth/revoke` — revoke all JWT tokens for current user
- `POST /api/auth/rotate-api-key` — rotate current user API key
- `POST /proxy/chat` — единый endpoint с маршрутизацией + fallback
- `POST /proxy/{provider}/...` — прямой маршрут конкретного провайдера
- `GET /proxy/providers`
- `POST /proxy/providers/{provider}/test` — проверка сетевой доступности/доступа к провайдеру по allowlist + TCP dial
- `POST /proxy/providers/test` — массовая проверка всех провайдеров (allowlist + TCP dial), полезно для сетевого hardening
- `GET /proxy/providers/connectivity` — история последней сетевой проверки по каждому провайдеру из Redis (админ, для аудита и мониторинга)
- `GET /proxy/providers/connectivity/alerts` — только проблемные провайдеры (`status=alerts|unreachable|egress|stale`, `stale_after_seconds`)
- `/api/dashboard/*`, `/api/audit/logs`, `/api/policies/*`, `/api/budgets/*`, `/api/users/*`
- `/api/internal-dbs` — список разрешенных внутренних SQL источников
- `POST /api/internal-dbs/query` — безопасный read-only запуск SELECT/WITH запросов по подключенным источникам
- `GET /api/internal-dbs` доступен для ролей `admin`, `analyst`, `auditor`
- `POST /api/internal-dbs/query` доступен для ролей `admin`, `analyst`
- `GET /api/internal-dbs/sources` — список записей внутренних источников (admin)
- `POST /api/internal-dbs/sources` — создать внутренний источник (admin)
- `GET /api/internal-dbs/sources/{id}` — получить запись источника (admin)
- `PUT /api/internal-dbs/sources/{id}` — обновить источник (admin)
- `DELETE /api/internal-dbs/sources/{id}` — удалить источник (admin)
- `POST /api/internal-dbs/sources/refresh` — форсированный ресинк источников из БД (admin)
- `POST /api/internal-dbs/sources/{id}/test` — проверить доступность источника по ID и выполнить `SELECT 1` (admin)

## Что закрыто в hardening

- API-ключи пользователей хранятся в БД как SHA-256 хеш, а не как открытый текст.
- Лимиты на `POST /api/auth/login` и `POST /api/auth/register` настроены на уровне роутера.
- Защита API и прокси-роутов: безопасные заголовки, таймауты сервера, CORS, ограничения размера тела.
- Прокси в `frontend/nginx.conf` закрыто дополнительным `server_tokens off`, таймаутами и ограничением проксируемых заголовков.
- Для proxy rate-limit теперь берётся IP только из `X-Real-IP`/`X-Forwarded-For`, когда запрос пришёл с доверенного прокси (`TRUSTED_PROXY_CIDRs`), иначе используется `RemoteAddr`.
- DLP на уровне прокси: контроль `request/response` по PII и секретным паттернам (`audit`/`enforce`/`strict`).
- Апстрим-запросы провайдерам идут через HTTP-транспорт с `TLS`-ограничениями (минимум TLS 1.2) и контролируемыми timeout-ами.
- Post-call аудит бюджета: non-stream путь после парсинга ответа проверяет фактический расход `tokens/cost`; при лимите отдаёт 402.
- Внутренние источники БД переведены в DB-backed управление: таблица `internal_db_sources` хранит DSN/статус/описание, менеджер периодически перезагружает активные источники из БД и применяет изменения к пулу коннектов.
- Источник BД обновляется в фоне по `INTERNAL_DB_REFRESH_INTERVAL`, что снижает зависимость от ручного перезапуска сервиса при смене DSN или включении/выключении источников.
- Проверки доступности провайдеров теперь сохраняются в Redis и доступны через `GET /proxy/providers/connectivity`, а `GET /proxy/providers/connectivity/alerts` даёт только проблемные статусы (egress/не доступен/stale) для операционного контроля.
- Также есть фоновый scheduler: `PROVIDER_CONNECTIVITY_INTERVAL` запускает периодические проверки всех провайдеров и пишет сводку в логи сервера (`ok` / `alert`).

## Нюансы
- По умолчанию входной пользователь может стать админом автоматически (если пользователей ещё нет).
- Бюджет может быть не задан — тогда лимиты не применяются.
- Кэширование ответов (cache) — только для non-streaming запросов.

## Полезные команды
- `make test` — backend тесты
- `make lint` — backend lint (если настроен)
- `make frontend-build` — сборка frontend

## Доступная версия
Сейчас реализована MVP-версия с возможностью расширения политик, аудитом и метриками.

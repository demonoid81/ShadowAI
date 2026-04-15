# ShadowAI

AI Control Plane и LLM Firewall — единый reverse-proxy для LLM API с многоуровневой защитой, политиками, аудитом и бюджетированием.

---

## Оглавление

- [Обзор](#обзор)
- [Архитектура](#архитектура)
  - [Технологический стек](#технологический-стек)
  - [Структура проекта](#структура-проекта)
- [Быстрый запуск](#быстрый-запуск)
- [LLM Firewall](#llm-firewall)
  - [Архитектура Pipeline](#архитектура-pipeline)
  - [Инспекторы](#инспекторы)
  - [Гибридная детекция](#гибридная-детекция)
  - [LLM-as-Judge](#llm-as-judge)
- [Провайдеры](#провайдеры)
  - [Маршрутизация](#маршрутизация)
  - [Кэширование](#кэширование)
  - [Health Tracking](#health-tracking)
- [API Reference](#api-reference)
  - [Аутентификация](#аутентификация-api)
  - [Proxy](#proxy)
  - [Dashboard](#dashboard)
  - [Политики](#политики)
  - [Бюджеты](#бюджеты)
  - [Пользователи](#пользователи)
  - [Аудит](#аудит)
  - [Internal DB](#internal-db)
- [Аутентификация и авторизация](#аутентификация-и-авторизация)
  - [JWT](#jwt)
  - [API Keys](#api-keys)
  - [Роли](#роли)
- [Безопасность (Hardening)](#безопасность-hardening)
  - [Security Headers](#security-headers)
  - [Rate Limiting](#rate-limiting)
  - [DLP](#dlp)
  - [TLS](#tls)
  - [Egress Control](#egress-control)
- [Конфигурация](#конфигурация)
- [База данных](#база-данных)
  - [Миграции](#миграции)
  - [Схема](#схема)
- [Тестирование](#тестирование)
- [Полезные команды](#полезные-команды)

---

## Обзор

ShadowAI — контрольная плоскость для работы организации с LLM-провайдерами. Обеспечивает:

- **Единый API-вход** для 7 провайдеров (OpenAI, Anthropic, Gemini, Mistral, Groq, OpenRouter, Ollama)
- **LLM Firewall** с 10-уровневой инспекцией запросов и ответов
- **DLP** — предотвращение утечки данных (PII, секреты, API-ключи)
- **Политики доступа** — блокировка по PII, ключевым словам, моделям
- **Бюджетирование** — лимиты по токенам и стоимости (помесячно, по пользователю)
- **Полный аудит** всех запросов с фиксацией токенов, стоимости, PII, решений политик
- **Интеллектуальная маршрутизация** с fallback-цепочкой и семантическим кэшем
- **Подключение внутренних БД** (read-only SQL-запросы к CRM, ERP и т.д.)

---

## Архитектура

### Технологический стек

| Слой | Технологии |
|---|---|
| **Backend** | Go 1.25, Gorilla Mux, golang-jwt, bcrypt |
| **Database** | PostgreSQL 16 (pgcrypto) |
| **Cache / State** | Redis 7 (кэш, rate limiting, health tracking) |
| **Frontend** | Vue 3, Pinia, Vue Router, Tailwind CSS, Chart.js |
| **Infrastructure** | Docker Compose |

### Структура проекта

```
backend/
├── cmd/shadowai/              # Точка входа приложения
├── internal/
│   ├── auth/                  # JWT-аутентификация, API-ключи, middleware, роли
│   ├── proxy/                 # Reverse proxy, providers, routing, cache, health
│   ├── firewall/              # LLM Firewall (10 инспекторов, judge, patterns)
│   ├── dlp/                   # Data Loss Prevention (3 режима)
│   ├── pii/                   # PII Detection (5 паттернов)
│   ├── policy/                # Policy Engine (rule engine)
│   ├── audit/                 # Audit logging
│   ├── budget/                # Budget management (токены + стоимость)
│   ├── config/                # Configuration (env vars)
│   ├── dashboard/             # Dashboard API (статистика, usage, top users)
│   ├── internaldb/            # Internal DB sources (CRUD + query)
│   ├── middleware/            # HTTP middleware (CORS, rate limit, security, logging)
│   ├── domain/                # Domain models (User)
│   └── platform/              # PostgreSQL / Redis адаптеры
├── migrations/                # SQL-миграции (001–006)
frontend/
├── src/
│   ├── pages/                 # 6 страниц (Dashboard, Login, Audit, Budget, Policies, Users)
│   ├── components/            # UI-компоненты
│   ├── stores/                # Pinia stores
│   └── api/                   # API client
```

---

## Быстрый запуск

### Предварительные требования

- Docker и Docker Compose
- (Опционально) Go 1.25+ для локальной разработки
- API-ключи хотя бы одного LLM-провайдера

### Шаги

1. **Создать `.env`** в корне проекта (опционально):

```bash
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=AI...
JWT_SECRET=my-secure-secret-at-least-32-chars!!
```

2. **Запустить инфраструктуру:**

```bash
make up
```

3. **Применить миграции:**

```bash
make migrate
```

4. **Загрузить начальные данные (опционально):**

```bash
make seed
```

5. **Проверить работоспособность:**

```bash
curl http://localhost:8080/api/health
# {"status":"ok"}
```

> Первый зарегистрированный пользователь автоматически получает роль `admin`.

---

## LLM Firewall

### Архитектура Pipeline

```
Client Request
    │
    ▼
┌─────────────────────────────────────────────┐
│           10 Inspector Chain (Request)       │
│  PII → DLP → Policy → PromptInj → Jailbreak │
│  → ContentMod → OutputVal → RateLimit       │
│  → MultiTurn → Semantic                     │
└─────────────────────────────────────────────┘
    │ (если все allow)
    ▼
  Forward to LLM Provider
    │
    ▼
┌─────────────────────────────────────────────┐
│          Inspector Chain (Response)          │
│  PII → DLP → ContentMod → OutputVal         │
└─────────────────────────────────────────────┘
    │
    ▼
Client Response
```

Каждый инспектор возвращает решение (`Decision`) с действием:
- `allow` — пропустить
- `block` — отклонить запрос (HTTP 403)
- `sanitize` — очистить данные и пропустить
- `flag` — пропустить с предупреждением

Pipeline прерывается при первом `block`.

### Инспекторы

| # | Инспектор | Фаза | Метод | Описание |
|---|---|---|---|---|
| 1 | **PII** | req + resp | regex | Обнаружение email, телефонов, SSN, кредитных карт, IP-адресов |
| 2 | **DLP** | req + resp | regex | Обнаружение API-ключей, AWS credentials, GitHub tokens, bearer tokens, PEM-сертификатов. 3 режима: `audit` / `enforce` / `strict` |
| 3 | **Policy** | req | rule engine | Применение правил: `pii_block`, `pii_warn`, `keyword_block`, `model_restrict` |
| 4 | **Prompt Injection** | req | heuristic + judge | 15 паттернов с весами, пороговый scoring, опциональная LLM-верификация |
| 5 | **Jailbreak** | req | heuristic + judge | Обнаружение DAN, roleplay-атак, encoding tricks, гомоглифов |
| 6 | **Content Moderation** | req + resp | heuristic + judge | Hate speech, насилие, self-harm, harassment |
| 7 | **Output Validation** | resp | heuristic | Обнаружение shell/SQL injection, credentials, попыток exfiltration в ответах |
| 8 | **Content Rate Limit** | req | sliding window | Ограничение символов и флагов в минуту (per-user) |
| 9 | **Multi-turn** | req | session analysis | Обнаружение атак конкатенации, эскалации ролей в многоходовых диалогах |
| 10 | **Semantic** | req | token similarity | Weighted Jaccard similarity против 25 вредоносных шаблонов с критическими терминами |

### Гибридная детекция

Инспекторы 4, 5, 6 используют двухслойную архитектуру:

1. **Heuristic Layer** — быстрый regex/pattern matching с весовым scoring.
   Каждый паттерн имеет вес; итоговая оценка нормализуется.
   Если оценка превышает `heuristic_threshold` — запрос блокируется немедленно.

2. **LLM-as-Judge Layer** — если эвристика дала оценку ниже порога блокировки,
   но выше порога подозрения, запрос отправляется на верификацию LLM-судье.
   Если `judge_threshold` превышен — блокировка.

Пороги настраиваются отдельно для каждого инспектора через переменные окружения.

### LLM-as-Judge

Judge — клиент для оценки угроз через LLM-провайдер. Конфигурация:

| Параметр | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_JUDGE_ENABLED` | Включить judge | `false` |
| `FIREWALL_JUDGE_PROVIDER` | Провайдер (ollama, openai, anthropic, groq, openrouter, mistral) | `ollama` |
| `FIREWALL_JUDGE_MODEL` | Модель | `llama3.2` |
| `FIREWALL_JUDGE_ENDPOINT` | URL эндпоинта | `http://localhost:11434` |
| `FIREWALL_JUDGE_API_KEY` | API-ключ (если требуется) | — |
| `FIREWALL_JUDGE_TIMEOUT` | Таймаут запроса | `5s` |

Judge отправляет промпт с текстом пользователя и ожидает JSON-ответ:
```json
{"is_threat": true, "confidence": 0.85, "reason": "..."}
```

**Fail-safe:** если judge недоступен или вернул ошибку, решение принимается
только на основе эвристики (запрос не блокируется из-за недоступности judge).

---

## Провайдеры

| Провайдер | Модели по умолчанию | Формат стрима | Требует API Key |
|---|---|---|---|
| **OpenAI** | gpt-4o, gpt-4o-mini, gpt-3.5-turbo, gpt-4-turbo, gpt-4, o1, o1-mini | SSE | Да |
| **Anthropic** | claude-3-5-sonnet | SSE | Да |
| **Gemini** | gemini-1.5-pro | SSE | Да |
| **Mistral** | mistral-large-latest | SSE | Да |
| **Groq** | llama-3.1-70b | SSE | Да |
| **OpenRouter** | auto | SSE | Да |
| **Ollama** | llama3.2 | NDJSON | Нет |

Провайдеры без API-ключа пропускаются при старте (кроме Ollama — регистрируется всегда).

### Маршрутизация

4 стратегии выбора провайдера (переменная `ROUTING_STRATEGY`):

| Стратегия | Описание |
|---|---|
| `cheapest` | Сортировка по стоимости токенов (по умолчанию) |
| `fastest` | Сортировка по средней задержке (из health tracker) |
| `round-robin` | Циклический перебор провайдеров |
| `fallback` | Порядок из `FALLBACK_ORDER` (например `openai,anthropic,groq`) |

При сбое основного провайдера запрос автоматически переходит к следующему в цепочке.
Если модель указана явно — первым выбирается провайдер, поддерживающий эту модель.

### Кэширование

Семантический кэш в Redis:

- Ключ: SHA-256 хеш от `userID + provider + model + messages`
- TTL настраивается через `CACHE_TTL` (по умолчанию `1h`)
- Кэширование только для non-streaming запросов
- Трекинг попаданий/промахов (`cache:stats:hits`, `cache:stats:misses`)
- Включение/отключение: `CACHE_ENABLED` (по умолчанию `true`)

### Health Tracking

Мониторинг состояния провайдеров:

- Проверка сетевой доступности (TCP dial + egress allowlist)
- Отслеживание латентности каждого провайдера
- Результаты сохраняются в Redis
- Фоновый scheduler: `PROVIDER_CONNECTIVITY_INTERVAL` (по умолчанию `5m`, `0` — отключить)
- API для просмотра результатов: `/proxy/providers/connectivity`
- Алерты по проблемным провайдерам: `/proxy/providers/connectivity/alerts`

---

## API Reference

### Аутентификация (API) {#аутентификация-api}

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| POST | `/api/auth/login` | Вход (получение JWT) | Публичный |
| POST | `/api/auth/register` | Регистрация нового пользователя | Публичный |
| POST | `/api/auth/revoke` | Отзыв всех JWT текущего пользователя | Авторизованный |
| POST | `/api/auth/rotate-api-key` | Ротация API-ключа текущего пользователя | Авторизованный |

### Proxy

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| POST | `/proxy/chat` | Unified chat (интеллектуальная маршрутизация + fallback) | Авторизованный |
| POST | `/proxy/{provider}/...` | Прямой прокси к конкретному провайдеру | Авторизованный |
| GET | `/proxy/providers` | Список зарегистрированных провайдеров | Авторизованный |
| POST | `/proxy/providers/test` | Тест доступности всех провайдеров | Admin |
| POST | `/proxy/providers/{provider}/test` | Тест доступности конкретного провайдера | Admin |
| GET | `/proxy/providers/connectivity` | История проверок доступности из Redis | Admin |
| GET | `/proxy/providers/connectivity/alerts` | Только проблемные провайдеры (unreachable, egress blocked, stale) | Admin |

### Dashboard

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/dashboard/stats` | Общая статистика (запросы, токены, стоимость) | Admin |
| GET | `/api/dashboard/usage` | Использование по времени | Admin |
| GET | `/api/dashboard/top-users` | Топ пользователей по потреблению | Admin |

### Политики

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/policies` | Список всех политик | Admin |
| POST | `/api/policies` | Создать новую политику | Admin |
| PUT | `/api/policies/{id}` | Обновить политику | Admin |
| DELETE | `/api/policies/{id}` | Удалить политику | Admin |

### Бюджеты

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/budgets/{user_id}` | Получить бюджет пользователя | Admin / владелец |
| PUT | `/api/budgets/{user_id}` | Обновить бюджет пользователя | Admin |

### Пользователи

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/users` | Список всех пользователей | Admin |
| GET | `/api/users/{id}` | Получить пользователя по ID | Admin |
| PUT | `/api/users/{id}` | Обновить пользователя | Admin |

### Аудит

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/audit/logs` | Список записей аудита | Admin |

### Internal DB

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/internal-dbs` | Список доступных внутренних источников | Admin, Analyst, Auditor |
| POST | `/api/internal-dbs/query` | Выполнить read-only SQL-запрос (SELECT/WITH) | Admin, Analyst |
| GET | `/api/internal-dbs/sources` | Список записей источников (CRUD) | Admin |
| POST | `/api/internal-dbs/sources` | Создать внутренний источник | Admin |
| GET | `/api/internal-dbs/sources/{id}` | Получить запись источника | Admin |
| PUT | `/api/internal-dbs/sources/{id}` | Обновить источник | Admin |
| DELETE | `/api/internal-dbs/sources/{id}` | Удалить источник | Admin |
| POST | `/api/internal-dbs/sources/refresh` | Форсированный ресинк источников из БД | Admin |
| POST | `/api/internal-dbs/sources/{id}/test` | Проверить доступность источника (`SELECT 1`) | Admin |

### Health Check

| Метод | Путь | Описание | Доступ |
|---|---|---|---|
| GET | `/api/health` | Проверка состояния сервиса | Публичный |

---

## Аутентификация и авторизация

### JWT

- Алгоритм: **HS256**
- Время жизни: **24 часа**
- Claims: `user_id`, `email`, `role`, `tv` (token version)
- Отзыв: инкремент `token_version` в БД — все ранее выданные токены становятся невалидными
- Минимальная длина `JWT_SECRET`: 32 символа (предупреждение при нарушении)

### API Keys

- Генерация: **32 случайных байта** (crypto/rand)
- Хранение в БД: **SHA-256 хеш** (не открытый текст)
- Ротация через `/api/auth/rotate-api-key` — старый ключ немедленно инвалидируется
- API-ключ передаётся в заголовке `Authorization: Bearer <key>`

### Роли

| Роль | Права |
|---|---|
| `admin` | Полный доступ: все API, управление пользователями, политиками, бюджетами, аудитом, internal DB |
| `user` | Proxy (chat), просмотр своего бюджета |
| `analyst` | Proxy (chat), список внутренних БД, SQL-запросы к внутренним БД |
| `auditor` | Proxy (chat), список внутренних БД (только чтение списка) |

---

## Безопасность (Hardening)

### Security Headers

Все ответы включают защитные заголовки:

| Заголовок | Значение |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cache-Control` | `no-store` |
| `Content-Security-Policy` | `default-src 'self'` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` (только HTTPS) |

### Rate Limiting

- **Публичные эндпоинты** (login, register): 20 запросов в минуту per-IP
- **Proxy-эндпоинты**: 60 запросов в минуту per-user
- **Content Rate Limit** (firewall): ограничение символов и флагов в минуту per-user
- Реализация: sliding window в Redis (ZSET с timestamp)
- IP клиента берётся из `X-Real-IP` / `X-Forwarded-For` только при запросе с доверенного прокси (`TRUSTED_PROXY_CIDRS`), иначе — `RemoteAddr`

### DLP

3 режима работы (`DLP_MODE`):

| Режим | Поведение |
|---|---|
| `audit` | Логирование обнаруженных данных, запросы пропускаются |
| `enforce` | Санитизация PII и секретов перед отправкой провайдеру (по умолчанию) |
| `strict` | Блокировка запроса при обнаружении PII или секретов |

Обнаруживаемые паттерны PII: email, телефон, SSN, кредитные карты, IP-адреса.
Обнаруживаемые секреты: API-ключи (OpenAI, Anthropic и др.), AWS credentials, GitHub tokens, bearer tokens, PEM-сертификаты.

### TLS

- Минимальная версия TLS 1.2 для upstream-запросов к провайдерам
- Контролируемые таймауты на HTTP-транспорте

### Egress Control

- Whitelist разрешённых хостов провайдеров: `ALLOWED_PROVIDER_HOSTS`
- По умолчанию: `api.openai.com,api.anthropic.com,generativelanguage.googleapis.com,api.mistral.ai,api.groq.com,openrouter.ai,localhost`
- Поддержка wildcard-паттернов: `*.subdomain.example.com`
- Проверка при каждом TCP dial к провайдеру

---

## Конфигурация

### Полный список переменных окружения

#### Core

| Переменная | Описание | По умолчанию |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://shadowai:shadowai_secret@localhost:5432/shadowai?sslmode=disable` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `JWT_SECRET` | Секрет для подписи JWT (минимум 32 символа) | `change-me-in-production-32chars!!` |
| `SERVER_PORT` | Порт HTTP-сервера | `8080` |

#### Auth и CORS

| Переменная | Описание | По умолчанию |
|---|---|---|
| `CORS_ALLOWED_HOSTS` | Разрешённые origins для CORS | `http://localhost:3000,http://localhost:5173` |
| `TRUSTED_PROXY_CIDRS` | CIDR-блоки доверенных reverse-proxy | — |

#### Провайдеры

| Переменная | Описание | По умолчанию |
|---|---|---|
| `OPENAI_API_KEY` | API-ключ OpenAI | — |
| `ANTHROPIC_API_KEY` | API-ключ Anthropic | — |
| `GEMINI_API_KEY` | API-ключ Google Gemini | — |
| `MISTRAL_API_KEY` | API-ключ Mistral AI | — |
| `GROQ_API_KEY` | API-ключ Groq | — |
| `OPENROUTER_API_KEY` | API-ключ OpenRouter | — |
| `OLLAMA_URL` | URL Ollama сервера | `http://localhost:11434` |

#### Proxy и маршрутизация

| Переменная | Описание | По умолчанию |
|---|---|---|
| `ROUTING_STRATEGY` | Стратегия маршрутизации (`cheapest`, `fastest`, `round-robin`) | `cheapest` |
| `FALLBACK_ORDER` | Порядок fallback-цепочки (через запятую) | — |
| `CACHE_ENABLED` | Включить семантический кэш | `true` |
| `CACHE_TTL` | TTL кэша (Go duration) | `1h` |
| `ALLOWED_PROVIDER_HOSTS` | Whitelist хостов провайдеров | `api.openai.com,api.anthropic.com,...` |
| `PROVIDER_CONNECTIVITY_INTERVAL` | Интервал автопроверки доступности провайдеров | `5m` (`0` — отключить) |
| `MAX_COMPLETION_TOKENS` | Лимит токенов ответа для оценки бюджета | `0` (без лимита) |
| `DLP_MODE` | Режим DLP (`audit`, `enforce`, `strict`) | `enforce` |

#### Server

| Переменная | Описание | По умолчанию |
|---|---|---|
| `SERVER_READ_TIMEOUT` | Таймаут чтения запроса | `15s` |
| `SERVER_WRITE_TIMEOUT` | Таймаут записи ответа | `120s` |
| `SERVER_IDLE_TIMEOUT` | Таймаут idle-соединения | `120s` |
| `SERVER_READ_HEADER_TIMEOUT` | Таймаут чтения заголовков | `5s` |
| `SERVER_MAX_HEADER_BYTES` | Максимальный размер заголовков (байты) | `1048576` (1 MB) |

#### Firewall — общие

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_ENABLED` | Включить LLM Firewall pipeline | `true` |
| `FIREWALL_JUDGE_ENABLED` | Включить LLM-as-Judge | `false` |
| `FIREWALL_JUDGE_PROVIDER` | Провайдер для judge | `ollama` |
| `FIREWALL_JUDGE_MODEL` | Модель для judge | `llama3.2` |
| `FIREWALL_JUDGE_ENDPOINT` | URL эндпоинта judge | `http://localhost:11434` |
| `FIREWALL_JUDGE_API_KEY` | API-ключ для judge | — |
| `FIREWALL_JUDGE_TIMEOUT` | Таймаут запроса к judge | `5s` |

#### Firewall — Prompt Injection

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_PI_ENABLED` | Включить детекцию prompt injection | `true` |
| `FIREWALL_PI_HEURISTIC_THRESHOLD` | Порог эвристики для блокировки | `0.8` |
| `FIREWALL_PI_JUDGE_THRESHOLD` | Порог judge для блокировки | `0.4` |

#### Firewall — Jailbreak

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_JB_ENABLED` | Включить детекцию jailbreak | `true` |
| `FIREWALL_JB_HEURISTIC_THRESHOLD` | Порог эвристики для блокировки | `0.8` |
| `FIREWALL_JB_JUDGE_THRESHOLD` | Порог judge для блокировки | `0.4` |

#### Firewall — Content Moderation

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_CM_ENABLED` | Включить модерацию контента | `true` |
| `FIREWALL_CM_HEURISTIC_THRESHOLD` | Порог эвристики для блокировки | `0.7` |
| `FIREWALL_CM_JUDGE_THRESHOLD` | Порог judge для блокировки | `0.3` |

#### Firewall — Output Validation

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_OV_ENABLED` | Включить валидацию ответов | `true` |
| `FIREWALL_OV_HEURISTIC_THRESHOLD` | Порог эвристики для блокировки | `0.7` |

#### Firewall — Content Rate Limit

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_RL_ENABLED` | Включить content rate limiting | `false` |
| `FIREWALL_RL_MAX_CHARS_PER_MINUTE` | Максимум символов в минуту per-user | `50000` |
| `FIREWALL_RL_MAX_FLAGS_PER_MINUTE` | Максимум флагов в минуту per-user | `5` |

#### Firewall — Multi-turn

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_MT_ENABLED` | Включить анализ многоходовых атак | `true` |
| `FIREWALL_MT_WINDOW_SIZE` | Размер окна сообщений для анализа | `10` |
| `FIREWALL_MT_HEURISTIC_THRESHOLD` | Порог эвристики для блокировки | `0.6` |

#### Firewall — Semantic

| Переменная | Описание | По умолчанию |
|---|---|---|
| `FIREWALL_SA_ENABLED` | Включить семантический анализ | `true` |
| `FIREWALL_SA_THRESHOLD` | Порог сходства для флага | `0.5` |
| `FIREWALL_SA_BLOCK_THRESHOLD` | Порог сходства для блокировки | `0.75` |

#### Internal DB

| Переменная | Описание | По умолчанию |
|---|---|---|
| `INTERNAL_DB_SOURCES` | DSN внутренних БД (формат: `name=dsn,name2=dsn2`) | — |
| `INTERNAL_DB_REFRESH_INTERVAL` | Интервал ресинка источников из БД | `30s` |
| `INTERNAL_DB_QUERY_TIMEOUT` | Таймаут SQL-запросов к внутренним БД | `8s` |

---

## База данных

### Миграции

| # | Файл | Описание |
|---|---|---|
| 001 | `001_create_users.sql` | Таблица пользователей (UUID, email, password, role, api_key, token_version) |
| 002 | `002_create_audit_logs.sql` | Журнал аудита (запросы, токены, стоимость, PII, решения политик) |
| 003 | `003_create_policies.sql` | Правила политик (тип, конфигурация JSONB, приоритет) |
| 004 | `004_create_budgets.sql` | Бюджеты пользователей (лимиты USD и токенов, помесячный период) |
| 005 | `005_add_token_version_to_users.sql` | Добавление token_version для отзыва JWT |
| 006 | `006_create_internal_db_sources.sql` | Источники внутренних БД (DSN, статус, метаданные) |

Применение: `make migrate`

### Схема

#### users

| Поле | Тип | Описание |
|---|---|---|
| `id` | UUID | Первичный ключ (gen_random_uuid) |
| `email` | VARCHAR(255) | Уникальный email |
| `password` | VARCHAR(255) | Хеш пароля (bcrypt) |
| `role` | VARCHAR(20) | Роль (`admin`, `user`, `analyst`, `auditor`) |
| `api_key` | VARCHAR(64) | SHA-256 хеш API-ключа |
| `is_active` | BOOLEAN | Активность аккаунта |
| `token_version` | INT | Версия токена (для отзыва JWT) |
| `created_at` | TIMESTAMPTZ | Дата создания |
| `updated_at` | TIMESTAMPTZ | Дата обновления |

#### audit_logs

| Поле | Тип | Описание |
|---|---|---|
| `id` | UUID | Первичный ключ |
| `user_id` | UUID | FK на users |
| `request_body` | TEXT | Тело запроса (усечённое до 4000 символов) |
| `response_body` | TEXT | Тело ответа |
| `model` | VARCHAR(100) | Использованная модель |
| `provider` | VARCHAR(50) | Провайдер |
| `endpoint` | VARCHAR(255) | Целевой эндпоинт |
| `status_code` | INT | HTTP-код ответа |
| `prompt_tokens` | INT | Токены промпта |
| `completion_tokens` | INT | Токены ответа |
| `total_tokens` | INT | Общее количество токенов |
| `cost_usd` | NUMERIC(10,6) | Стоимость запроса в USD |
| `pii_detected` | BOOLEAN | Обнаружен ли PII |
| `pii_types` | TEXT[] | Типы обнаруженного PII |
| `policy_action` | VARCHAR(20) | Решение политики |
| `duration_ms` | INT | Длительность обработки (мс) |
| `created_at` | TIMESTAMPTZ | Время создания записи |

#### policy_rules

| Поле | Тип | Описание |
|---|---|---|
| `id` | UUID | Первичный ключ |
| `name` | VARCHAR(255) | Название правила |
| `rule_type` | VARCHAR(50) | Тип: `pii_block`, `pii_warn`, `keyword_block`, `model_restrict` |
| `config` | JSONB | Конфигурация правила |
| `is_active` | BOOLEAN | Активность |
| `priority` | INT | Приоритет (чем выше — тем раньше применяется) |

#### budgets

| Поле | Тип | Описание |
|---|---|---|
| `id` | UUID | Первичный ключ |
| `user_id` | UUID | FK на users (уникальный) |
| `monthly_limit_usd` | NUMERIC(10,2) | Месячный лимит в USD |
| `monthly_spent_usd` | NUMERIC(10,6) | Потрачено в текущем месяце |
| `monthly_token_limit` | INT | Месячный лимит токенов |
| `monthly_tokens_used` | INT | Использовано токенов в текущем месяце |
| `period_start` | DATE | Начало текущего периода |

#### internal_db_sources

| Поле | Тип | Описание |
|---|---|---|
| `id` | UUID | Первичный ключ |
| `name` | VARCHAR(64) | Уникальное имя источника (case-insensitive) |
| `dsn` | TEXT | Connection string |
| `description` | TEXT | Описание |
| `is_active` | BOOLEAN | Активность |
| `created_by` | UUID | Кто создал |
| `updated_by` | UUID | Кто обновил |
| `created_at` | TIMESTAMPTZ | Дата создания |
| `updated_at` | TIMESTAMPTZ | Дата обновления |

---

## Тестирование

### Запуск тестов

```bash
make test
```

### Покрытие по модулям

| Модуль | Тест-файлы | Покрытие |
|---|---|---|
| `auth` | `service_test.go`, `middleware_test.go` | Аутентификация, JWT, роли |
| `config` | `config_test.go` | Парсинг конфигурации |
| `dlp` | `dlp_test.go` | Режимы DLP, обнаружение секретов |
| `firewall` | 12 тест-файлов | Все 10 инспекторов, judge, patterns, интеграция |
| `internaldb` | `handler_test.go`, `manager_test.go` | CRUD источников, менеджер пула |
| `middleware` | `middleware_test.go` | CORS, rate limit, security |
| `pii` | `detector_test.go` | Обнаружение PII-паттернов |
| `policy` | `engine_test.go` | Policy engine, правила |
| `proxy` | 6 тест-файлов | Cache, health, model map, provider, retry, router |

Всего: **28 тест-файлов** по 10 модулям.

---

## Полезные команды

| Команда | Описание |
|---|---|
| `make up` | Запустить все сервисы (postgres, redis, backend, frontend) |
| `make down` | Остановить все сервисы |
| `make dev` | Локальная разработка (postgres + redis в Docker, backend из исходников) |
| `make migrate` | Применить SQL-миграции |
| `make seed` | Загрузить начальные данные |
| `make test` | Запустить backend-тесты |
| `make lint` | Запустить линтер (golangci-lint) |
| `make frontend-dev` | Запустить frontend в режиме разработки |
| `make frontend-build` | Собрать frontend для продакшена |

### Docker Compose

```bash
# Только инфраструктура
docker compose up -d postgres redis

# Все сервисы
docker compose up -d

# Логи backend
docker compose logs -f backend

# Пересборка backend
docker compose up -d --build backend
```

---

## Нюансы

- Первый зарегистрированный пользователь автоматически получает роль `admin`.
- Бюджет может быть не задан — в этом случае лимиты не применяются.
- Кэширование ответов работает только для non-streaming запросов.
- Максимальный размер тела запроса: 10 MB.
- Максимум сообщений в одном запросе: 256, максимум символов в сообщении: 4000.
- Тело запроса/ответа в аудите обрезается до 4000 символов.
- Post-call аудит бюджета: после получения ответа проверяется фактический расход; при превышении лимита — HTTP 402.
- Внутренние источники БД перезагружаются фоново по `INTERNAL_DB_REFRESH_INTERVAL`.
- Graceful shutdown по SIGINT/SIGTERM с 10-секундным таймаутом.

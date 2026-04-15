# ShadowAI API Reference

## Аутентификация

ShadowAI поддерживает два метода аутентификации:

1. **JWT Bearer Token** -- передаётся в заголовке `Authorization: Bearer <token>`. Токен получается через endpoint `/api/auth/login`.
2. **API Key** -- передаётся в заголовке `X-API-Key: <key>`. Ключ генерируется при регистрации пользователя и может быть ротирован через `/api/auth/rotate-api-key`.

### Роли пользователей

| Роль       | Описание                                                      |
|------------|---------------------------------------------------------------|
| `admin`    | Полный доступ ко всем endpoints, управление пользователями    |
| `user`     | Доступ к proxy, бюджетам (свой), отзыв токенов               |
| `analyst`  | Доступ к proxy, просмотр internal-dbs, выполнение запросов    |
| `auditor`  | Доступ к proxy, просмотр internal-dbs                         |

---

## Публичные endpoints

Публичные endpoints защищены rate-limit: **20 запросов в минуту** на IP-адрес.

### GET /api/health

Проверка работоспособности сервиса.

**Аутентификация:** не требуется

**Ответ (200):**
```json
{"status": "ok"}
```

---

### POST /api/auth/login

Аутентификация пользователя и получение JWT-токена.

**Аутентификация:** не требуется

**Rate limit:** 20 запросов/мин на IP

**Тело запроса:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123"
}
```

**Успешный ответ (200):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Ошибки:**

| Код | Тело                                        | Описание                     |
|-----|---------------------------------------------|------------------------------|
| 400 | `{"error": "invalid request body"}`         | Невалидный JSON              |
| 400 | `{"error": "email and password are required"}` | Пустой email или пароль   |
| 401 | `{"error": "invalid credentials"}`          | Неверный email или пароль    |
| 429 | `{"error": "rate limit exceeded"}`          | Превышен лимит запросов      |

---

### POST /api/auth/register

Регистрация нового пользователя. Первый зарегистрированный пользователь автоматически получает роль `admin`. Все последующие регистрации требуют аутентификацию администратора.

**Аутентификация:** не требуется (первый пользователь) / `admin` (последующие)

**Rate limit:** 20 запросов/мин на IP

**Тело запроса:**
```json
{
  "email": "newuser@example.com",
  "password": "strongPassword12",
  "role": "user"
}
```

Допустимые роли: `admin`, `user`, `analyst`, `auditor`. Если роль не указана, по умолчанию -- `user`.

**Успешный ответ (201):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "newuser@example.com",
  "role": "user",
  "api_key": "sk-...",
  "is_active": true,
  "created_at": "2026-04-15T12:00:00Z",
  "updated_at": "2026-04-15T12:00:00Z"
}
```

**Ошибки:**

| Код | Тело                                                   | Описание                              |
|-----|--------------------------------------------------------|---------------------------------------|
| 400 | `{"error": "invalid request body"}`                    | Невалидный JSON                       |
| 400 | `{"error": "email and password are required"}`         | Пустой email или пароль               |
| 400 | `{"error": "invalid role"}`                            | Недопустимая роль                     |
| 400 | `{"error": "password must be at least 12 characters"}` | Слишком короткий пароль               |
| 403 | `{"error": "only admins can register new users"}`      | Нет прав администратора               |
| 409 | `{"error": "user already exists"}`                     | Пользователь с таким email уже есть   |

---

## Авторизованные endpoints

Все endpoints ниже требуют аутентификацию (JWT Bearer или API Key).

### POST /api/auth/revoke

Отзыв всех JWT-токенов текущего пользователя. После вызова все ранее выданные токены становятся недействительными.

**Роль:** любая авторизованная

**Тело запроса:** не требуется

**Успешный ответ (200):**
```json
{
  "message": "all tokens revoked"
}
```

**Ошибки:**

| Код | Тело                          | Описание              |
|-----|-------------------------------|-----------------------|
| 401 | `{"error": "unauthorized"}`   | Нет аутентификации    |
| 500 | `{"error": "internal server error"}` | Внутренняя ошибка |

---

### POST /api/auth/rotate-api-key

Ротация API-ключа. Пользователь может ротировать свой ключ; администратор может ротировать ключ любого пользователя, указав `user_id`.

**Роль:** любая авторизованная (свой ключ) / `admin` (чужой ключ)

**Тело запроса (опционально):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Если `user_id` не указан -- ротируется ключ текущего пользователя.

**Успешный ответ (200):**
```json
{
  "api_key": "sk-new-generated-key..."
}
```

**Ошибки:**

| Код | Тело                        | Описание                                    |
|-----|-----------------------------|---------------------------------------------|
| 401 | `{"error": "unauthorized"}` | Нет аутентификации                          |
| 403 | `{"error": "forbidden"}`    | Не-администратор пытается ротировать чужой ключ |
| 500 | `{"error": "internal"}`     | Внутренняя ошибка                           |

---

## Proxy endpoints

Proxy endpoints обеспечивают единый интерфейс для работы с AI-провайдерами. Защищены rate-limit: **60 запросов в минуту** на пользователя.

### POST /proxy/chat

Унифицированный чат с интеллектуальной маршрутизацией. Автоматически выбирает провайдера на основе модели, доступности и стратегии маршрутизации (latency/round-robin/fallback). Поддерживает семантическое кэширование, цепочку fallback-провайдеров, firewall-инспекцию, PII/DLP-проверку и бюджетный контроль.

**Роль:** любая авторизованная

**Rate limit:** 60 запросов/мин на пользователя

**Заголовки (опционально):**
- `X-No-Cache: true` -- отключить семантический кэш для данного запроса

**Тело запроса:**
```json
{
  "model": "gpt-4o",
  "stream": false,
  "max_tokens": 1024,
  "messages": [
    {"role": "system", "content": "Ты -- полезный ассистент."},
    {"role": "user", "content": "Привет, как дела?"}
  ]
}
```

| Поле                    | Тип      | Обязательно | Описание                                          |
|-------------------------|----------|-------------|---------------------------------------------------|
| `model`                 | string   | нет         | Модель (если пусто -- default модель провайдера)  |
| `stream`                | bool     | нет         | Потоковая передача ответа                         |
| `max_tokens`            | int      | нет         | Лимит токенов завершения                          |
| `max_completion_tokens` | int      | нет         | Альтернативное поле для лимита                    |
| `messages`              | array    | да          | Массив сообщений (макс. 256, макс. 4000 символов каждое) |
| `messages[].role`       | string   | да          | Роль: `system`, `user`, `assistant`, `developer`  |
| `messages[].content`    | string   | да          | Содержимое сообщения                              |

**Ограничения:**
- Максимальный размер тела запроса: 10 MB
- Максимум сообщений: 256
- Максимальная длина сообщения: 4000 символов

**Успешный ответ (200):**

Формат ответа зависит от провайдера (OpenAI-совместимый формат для большинства). Дополнительные заголовки:
- `X-Cache: HIT` -- ответ получен из кэша
- `X-Provider: openai` -- имя провайдера, обработавшего запрос

```json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "model": "gpt-4o",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Привет! У меня всё хорошо."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 25,
    "completion_tokens": 12,
    "total_tokens": 37
  }
}
```

**Ошибки:**

| Код | Тело                                                                       | Описание                                      |
|-----|----------------------------------------------------------------------------|-----------------------------------------------|
| 400 | `{"error": "invalid json"}`                                                | Невалидный JSON                               |
| 400 | `{"error": "invalid request"}`                                             | Не прошла валидация запроса                    |
| 400 | `{"error": "max completion tokens exceeds allowed limit"}`                 | Превышен лимит completion-токенов             |
| 401 | `{"error": "unauthorized"}`                                                | Нет аутентификации                            |
| 402 | `{"error": "budget exceeded"}`                                             | Превышен бюджет пользователя                  |
| 403 | `{"error": "blocked by firewall", "reason": "...", "inspector": "..."}`    | Заблокировано firewall (см. раздел Firewall)  |
| 403 | `{"error": "blocked by dlp", "reason": "..."}`                            | Заблокировано DLP-политикой                   |
| 403 | `{"error": "blocked by policy", "reason": "...", "rule": "..."}`          | Заблокировано политикой безопасности          |
| 413 | `{"error": "request body too large"}`                                      | Тело запроса превышает 10 MB                  |
| 429 | `{"error": "rate limit exceeded"}`                                         | Превышен rate limit                           |
| 500 | `{"error": "policy error"}`                                                | Внутренняя ошибка политик                     |
| 502 | `{"error": "upstream error"}`                                              | Ошибка провайдера                             |
| 503 | `{"error": "no providers available"}`                                      | Нет доступных провайдеров для модели          |

---

### POST /proxy/{provider}/{path}

Прямая маршрутизация к конкретному провайдеру. Проходит те же проверки firewall, DLP, политик и бюджета, что и `/proxy/chat`.

**Роль:** любая авторизованная

**Rate limit:** 60 запросов/мин на пользователя

**Параметры пути:**
- `{provider}` -- имя провайдера (`openai`, `anthropic`, `gemini`, `mistral`, `groq`, `openrouter`, `ollama`)
- `{path}` -- путь API провайдера (например, `v1/chat/completions`)

**Тело запроса:** аналогично `/proxy/chat`

**Ошибки (дополнительно к общим):**

| Код | Тело                                                         | Описание                        |
|-----|--------------------------------------------------------------|---------------------------------|
| 400 | `{"error": "unknown provider"}`                              | Неизвестный провайдер           |
| 400 | `{"error": "unsupported model", "model": "...", "supported_models": [...]}` | Модель не поддерживается |

---

### GET /proxy/providers

Список доступных провайдеров и их поддерживаемых моделей.

**Роль:** любая авторизованная

**Ответ (200):**
```json
{
  "providers": [
    {
      "name": "openai",
      "default_model": "gpt-4o",
      "supported_models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
    },
    {
      "name": "anthropic",
      "default_model": "claude-sonnet-4-20250514",
      "supported_models": ["claude-sonnet-4-20250514", "claude-3-5-haiku-20241022"]
    }
  ]
}
```

---

### POST /proxy/providers/test

Тестирование подключения ко всем провайдерам. Проверяет сетевую достижимость, egress-блокировки, измеряет задержку.

**Роль:** `admin`

**Query-параметры:**
- `timeout_ms` (int, 250-30000, по умолчанию 5000) -- таймаут подключения

**Ответ (200):**
```json
{
  "summary": {
    "total": 4,
    "reachable": 3,
    "egress_blocked": 1,
    "timeout_ms": 5000
  },
  "results": [
    {
      "provider": "openai",
      "host": "api.openai.com",
      "port": "443",
      "scheme": "https",
      "reachable": true,
      "latency_ms": 120,
      "checked_at": "2026-04-15T12:00:00Z",
      "age_ms": 0,
      "stale": false,
      "egress_blocked": false,
      "message": "ok"
    }
  ]
}
```

---

### POST /proxy/providers/{provider}/test

Тестирование подключения к конкретному провайдеру.

**Роль:** `admin`

**Параметры пути:**
- `{provider}` -- имя провайдера

**Query-параметры:**
- `timeout_ms` (int, 250-30000, по умолчанию 5000)

**Ответ (200):** один объект `providerTestResponse` (формат аналогичен элементу массива `results` из `/proxy/providers/test`).

**Ошибки:**

| Код | Тело                               | Описание                  |
|-----|------------------------------------|---------------------------|
| 400 | `{"error": "unknown provider"}`    | Неизвестный провайдер     |
| 502 | провайдер недоступен               | Ошибка подключения        |

---

### GET /proxy/providers/connectivity

Текущий снимок состояния подключений ко всем провайдерам (из последнего scheduled-check или ручного теста).

**Роль:** `admin`

**Query-параметры:**
- `status` (string) -- фильтр: `all`, `alerts`/`problem`/`issues`, `unreachable`, `egress`, `stale`
- `stale_after_seconds` (int, >= 1, по умолчанию 600) -- порог устаревания данных

**Ответ (200):** массив объектов `providerTestResponse` с доп. полями `stale`, `age_ms`.

---

### GET /proxy/providers/connectivity/alerts

Аналогичен `/proxy/providers/connectivity?status=alerts` -- возвращает только провайдеров с проблемами (недоступные, заблокированные egress, устаревшие данные).

**Роль:** `admin`

---

## Admin endpoints

Все admin endpoints требуют роль `admin`.

### Управление пользователями

#### GET /api/users

Список всех пользователей (API-ключи скрыты).

**Роль:** `admin`

**Ответ (200):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@example.com",
    "role": "admin",
    "is_active": true,
    "created_at": "2026-04-15T12:00:00Z",
    "updated_at": "2026-04-15T12:00:00Z"
  }
]
```

---

#### GET /api/users/{id}

Получение пользователя по ID.

**Роль:** `admin`

**Ответ (200):** объект пользователя (без `api_key`)

**Ошибки:**

| Код | Тело                           | Описание              |
|-----|--------------------------------|-----------------------|
| 404 | `{"error": "user not found"}`  | Пользователь не найден |

---

#### PUT /api/users/{id}

Обновление пользователя (email, роль, статус активности).

**Роль:** `admin`

**Тело запроса (все поля опциональны):**
```json
{
  "email": "newemail@example.com",
  "role": "analyst",
  "is_active": false
}
```

**Успешный ответ (200):** обновлённый объект пользователя

**Ошибки:**

| Код | Тело                               | Описание              |
|-----|------------------------------------|-----------------------|
| 400 | `{"error": "invalid request body"}` | Невалидный JSON      |
| 400 | `{"error": "invalid role"}`        | Недопустимая роль     |
| 404 | `{"error": "user not found"}`      | Пользователь не найден |

---

### Аудит-логи

#### GET /api/audit/logs

Получение журнала аудита с пагинацией и фильтрацией. Каждый proxy-запрос логируется с информацией о PII, DLP, политиках, стоимости и токенах.

**Роль:** `admin`

**Query-параметры:**
- `limit` (int, 1-100, по умолчанию 50) -- количество записей
- `offset` (int, по умолчанию 0) -- смещение
- `user_id` (string) -- фильтр по пользователю
- `model` (string) -- фильтр по модели
- `policy_action` (string) -- фильтр: `allowed`, `blocked`, `sanitized`

**Ответ (200):**
```json
{
  "data": [
    {
      "id": "log-uuid",
      "user_id": "user-uuid",
      "request_body": "...",
      "response_body": "...",
      "model": "gpt-4o",
      "provider": "openai",
      "endpoint": "/proxy/chat",
      "status_code": 200,
      "prompt_tokens": 100,
      "completion_tokens": 50,
      "total_tokens": 150,
      "cost_usd": 0.0045,
      "pii_detected": true,
      "pii_types": ["email", "phone"],
      "policy_action": "allowed",
      "duration_ms": 1200,
      "created_at": "2026-04-15T12:00:00Z"
    }
  ],
  "total": 1500,
  "limit": 50,
  "offset": 0
}
```

---

### Политики безопасности (CRUD)

#### GET /api/policies

Список всех политик.

**Роль:** `admin`

**Ответ (200):**
```json
[
  {
    "id": "policy-uuid",
    "name": "block-pii-sharing",
    "rule_type": "pii_block",
    "config": {"types": ["ssn", "credit_card"]},
    "is_active": true,
    "priority": 1
  }
]
```

---

#### POST /api/policies

Создание новой политики.

**Роль:** `admin`

**Тело запроса:**
```json
{
  "name": "block-model-access",
  "rule_type": "model_block",
  "config": {"models": ["gpt-4"]},
  "is_active": true,
  "priority": 10
}
```

**Успешный ответ (201):** созданный объект политики

**Ошибки:**

| Код | Тело                          | Описание       |
|-----|-------------------------------|----------------|
| 400 | `{"error": "invalid body"}`   | Невалидный JSON |

---

#### PUT /api/policies/{id}

Обновление политики.

**Роль:** `admin`

**Тело запроса:** объект `PolicyRule` (аналогично POST)

**Успешный ответ (200):** обновлённый объект политики

---

#### DELETE /api/policies/{id}

Удаление политики.

**Роль:** `admin`

**Успешный ответ:** 204 No Content

---

### Бюджеты

#### GET /api/budgets/{user_id}

Получение бюджета пользователя.

**Роль:** `admin` или владелец бюджета (собственный `user_id`)

**Ответ (200):**
```json
{
  "id": "budget-uuid",
  "user_id": "user-uuid",
  "monthly_limit_usd": 50.00,
  "monthly_spent_usd": 12.35,
  "monthly_token_limit": 1000000,
  "monthly_tokens_used": 250000,
  "period_start": "2026-04-01T00:00:00Z"
}
```

**Ошибки:**

| Код | Тело                       | Описание          |
|-----|----------------------------|-------------------|
| 404 | `{"error": "not found"}`   | Бюджет не найден  |

---

#### PUT /api/budgets/{user_id}

Создание или обновление бюджета пользователя.

**Роль:** `admin`

**Тело запроса:**
```json
{
  "monthly_limit_usd": 100.00,
  "monthly_token_limit": 2000000
}
```

**Успешный ответ (200):** обновлённый объект бюджета

---

### Дашборд

#### GET /api/dashboard/stats

Общая статистика платформы.

**Роль:** `admin`

**Ответ (200):**
```json
{
  "total_requests": 15420,
  "blocked_requests": 230,
  "total_cost": 456.78,
  "total_tokens": 12500000,
  "active_users": 42
}
```

---

#### GET /api/dashboard/usage

Статистика использования за последние 30 дней (по дням).

**Роль:** `admin`

**Ответ (200):**
```json
[
  {
    "date": "2026-04-14",
    "requests": 520,
    "cost": 15.30,
    "tokens": 450000
  }
]
```

---

#### GET /api/dashboard/top-users

Топ-10 пользователей по стоимости использования.

**Роль:** `admin`

**Ответ (200):**
```json
[
  {
    "user_id": "user-uuid",
    "email": "power-user@example.com",
    "requests": 1200,
    "cost": 89.50
  }
]
```

---

## Internal DB endpoints

Endpoints для работы с внутренними базами данных (read-only запросы к подключённым PostgreSQL-источникам).

### GET /api/internal-dbs

Список доступных источников данных (только имена).

**Роль:** `admin`, `analyst`, `auditor`

**Ответ (200):**
```json
{
  "sources": ["analytics", "warehouse", "crm"]
}
```

---

### POST /api/internal-dbs/query

Выполнение SQL-запроса к указанному источнику. Поддерживаются только SELECT-запросы.

**Роль:** `admin`, `analyst`

**Тело запроса:**
```json
{
  "source": "analytics",
  "query": "SELECT id, name FROM users LIMIT 10",
  "max_rows": 100
}
```

**Успешный ответ (200):**
```json
{
  "source": "analytics",
  "columns": ["id", "name"],
  "rows": [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"}
  ],
  "row_count": 2,
  "truncated": false,
  "duration_ms": 45
}
```

**Ошибки:**

| Код | Тело                                    | Описание                                  |
|-----|-----------------------------------------|-------------------------------------------|
| 400 | `{"error": "source is required"}`       | Не указан источник                        |
| 400 | `{"error": "query is required"}`        | Не указан запрос                          |
| 400 | `{"error": "query is too long"}`        | Запрос слишком длинный                    |
| 404 | `{"error": "source not found"}`         | Источник не найден                        |
| 422 | `{"error": "unsupported sql"}`          | Запрос не является SELECT                 |
| 502 | `{"error": "..."}`                      | Ошибка выполнения запроса к источнику     |
| 503 | `{"error": "no sources configured"}`    | Нет настроенных источников                |

---

### GET /api/internal-dbs/sources

Список управляемых источников с полной информацией (DSN замаскирован).

**Роль:** `admin`

**Ответ (200):**
```json
[
  {
    "id": "source-uuid",
    "name": "analytics",
    "description": "Аналитическая БД",
    "is_active": true,
    "dsn_masked": "postgres://***:***@db.example.com:5432/analytics",
    "created_at": "2026-04-01T00:00:00Z",
    "updated_at": "2026-04-10T15:30:00Z"
  }
]
```

---

### POST /api/internal-dbs/sources

Создание нового источника данных.

**Роль:** `admin`

**Тело запроса:**
```json
{
  "name": "warehouse",
  "dsn": "postgres://user:pass@db.example.com:5432/warehouse",
  "description": "Data warehouse",
  "is_active": true
}
```

**Успешный ответ (201):** объект `sourceAdminResponse`

**Ошибки:**

| Код | Тело                                   | Описание                     |
|-----|----------------------------------------|------------------------------|
| 400 | `{"error": "invalid request"}`         | Невалидный JSON              |
| 400 | `{"error": "dsn is required"}`         | DSN не указан                |
| 400 | `{"error": "invalid dsn"}`             | Невалидный DSN               |
| 409 | `{"error": "source already exists"}`   | Источник с таким именем есть |

---

### GET /api/internal-dbs/sources/{id}

Получение источника по ID.

**Роль:** `admin`

**Ответ (200):** объект `sourceAdminResponse`

**Ошибки:**

| Код | Тело                               | Описание             |
|-----|------------------------------------|-----------------------|
| 400 | `{"error": "invalid source id"}`   | Невалидный UUID      |
| 404 | `{"error": "source not found"}`    | Источник не найден   |

---

### PUT /api/internal-dbs/sources/{id}

Обновление источника. Хотя бы одно поле обязательно.

**Роль:** `admin`

**Тело запроса (все поля опциональны):**
```json
{
  "name": "new-name",
  "dsn": "postgres://...",
  "description": "Обновлённое описание",
  "is_active": false
}
```

**Успешный ответ (200):** обновлённый объект `sourceAdminResponse`

**Ошибки:**

| Код | Тело                                      | Описание                        |
|-----|-------------------------------------------|---------------------------------|
| 400 | `{"error": "at least one field required"}` | Ни одно поле не указано         |
| 400 | `{"error": "invalid source id"}`          | Невалидный UUID                 |
| 404 | `{"error": "source not found"}`           | Источник не найден              |
| 409 | `{"error": "source already exists"}`      | Конфликт имени                  |

---

### DELETE /api/internal-dbs/sources/{id}

Удаление источника.

**Роль:** `admin`

**Успешный ответ:** 204 No Content

**Ошибки:**

| Код | Тело                              | Описание             |
|-----|-----------------------------------|----------------------|
| 400 | `{"error": "invalid source id"}`  | Невалидный UUID      |
| 404 | `{"error": "source not found"}`   | Источник не найден   |

---

### POST /api/internal-dbs/sources/refresh

Принудительное обновление всех подключений к источникам.

**Роль:** `admin`

**Ответ (200):**
```json
{"status": "ok"}
```

---

### POST /api/internal-dbs/sources/{id}/test

Тестирование подключения к источнику (выполняет `SELECT 1`).

**Роль:** `admin`

**Ответ (200):**
```json
{
  "id": "source-uuid",
  "name": "analytics",
  "status": "ok",
  "latency_ms": 23,
  "message": "connection successful"
}
```

**Ошибки:**

| Код | Тело                                           | Описание                      |
|-----|-------------------------------------------------|-------------------------------|
| 400 | `{"error": "invalid source id"}`               | Невалидный UUID               |
| 400 | `{"error": "invalid dsn"}`                     | Невалидный DSN источника      |
| 404 | `{"error": "source not found"}`                | Источник не найден            |
| 502 | `{"error": "source connectivity test failed"}` | Не удалось подключиться       |

---

## Коды ошибок

Сводная таблица HTTP-кодов, используемых в API:

| Код | Значение                  | Когда возвращается                                                           |
|-----|---------------------------|------------------------------------------------------------------------------|
| 400 | Bad Request               | Невалидный JSON, недопустимые параметры, неизвестный провайдер, неподдерживаемая модель |
| 401 | Unauthorized              | Отсутствует или невалидный JWT/API Key, неверные учётные данные              |
| 402 | Payment Required          | Превышен бюджет пользователя (месячный лимит USD или токенов)               |
| 403 | Forbidden                 | Недостаточно прав (роль), блокировка firewall/DLP/policy, egress-блокировка |
| 404 | Not Found                 | Ресурс не найден (пользователь, источник, бюджет)                           |
| 409 | Conflict                  | Пользователь или источник уже существует                                    |
| 413 | Payload Too Large         | Тело запроса превышает 10 MB                                                |
| 422 | Unprocessable Entity      | SQL-запрос не является SELECT (internal-dbs)                                |
| 429 | Too Many Requests         | Превышен rate limit (20/мин для публичных, 60/мин для proxy)               |
| 500 | Internal Server Error     | Внутренняя ошибка сервера                                                   |
| 502 | Bad Gateway               | Ошибка подключения к провайдеру или внешнему источнику данных               |
| 503 | Service Unavailable       | Нет доступных провайдеров или источников данных                             |

---

## Ответы Firewall

ShadowAI включает многоуровневый firewall-конвейер, который инспектирует запросы и ответы. При блокировке возвращается код 403 с информацией об инспекторе.

**Формат ответа при блокировке (403):**
```json
{
  "error": "blocked by firewall",
  "reason": "Обнаружена попытка prompt injection",
  "inspector": "prompt_injection"
}
```

### Инспекторы firewall

| Инспектор                | Описание                                                     |
|--------------------------|--------------------------------------------------------------|
| `pii`                    | Обнаружение персональных данных (email, телефон, SSN и др.)  |
| `dlp`                    | Data Loss Prevention -- блокировка утечки конфиденциальных данных |
| `policy`                 | Проверка соответствия политикам безопасности                 |
| `prompt_injection`       | Обнаружение prompt injection атак (эвристика + LLM-судья)   |
| `jailbreak`              | Обнаружение jailbreak-попыток (эвристика + LLM-судья)       |
| `content_moderation`     | Модерация контента (эвристика + LLM-судья)                  |
| `output_validation`      | Валидация ответов модели                                     |
| `content_rate_limiter`   | Ограничение объёма контента в единицу времени               |
| `multi_turn`             | Анализ многоходовых атак через контекст переписки           |
| `semantic`               | Семантический анализ намерений                               |

Firewall работает в двух фазах:
- **Request** -- инспекция входящего запроса перед отправкой провайдеру
- **Response** -- инспекция ответа провайдера перед отдачей пользователю

При блокировке на фазе Response потоковая передача (streaming) полностью буферизуется для обеспечения DLP-проверки.

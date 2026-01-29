# Мульти-провайдерный Reverse Proxy

## Дата: 2026-01-29

## Контекст
ShadowAI имел единственный hardcoded провайдер — OpenAI. Необходимо расширить
proxy-модуль для поддержки 7 AI-провайдеров.

## Решения

### Архитектура
- Введён интерфейс `Provider` с методами `BuildRequest`, `ParseResponse`, `StreamFormat`, `DefaultModel`, `SupportedModels`
- Создан `Registry` для хранения и поиска провайдеров по имени
- OpenAI-совместимые провайдеры (OpenAI, Mistral, Groq, OpenRouter) используют общую базу `OpenAICompatProvider`
- Кастомные провайдеры (Anthropic, Gemini, Ollama) реализуют интерфейс напрямую

### Маршрутизация
- Было: `POST /proxy/openai/v1/chat/completions`
- Стало: `POST /proxy/{provider}/{path:.*}` — wildcard для всех провайдеров

### Streaming
- Добавлена поддержка NDJSON streaming для Ollama (`ForwardNDJSON`)
- SSE streaming остаётся для остальных провайдеров

### Рефакторинг
- `handler.go` — полная переработка: вместо hardcoded OpenAI используется Provider из Registry
- `transport.go` — удалён (логика перенесена в `Provider.BuildRequest`)
- `config.go` — добавлены API-ключи для всех провайдеров
- `main.go` — создание Registry, регистрация всех провайдеров, wildcard-маршрут

## Провайдеры

| Провайдер | Тип | Base URL | Auth |
|---|---|---|---|
| OpenAI | OpenAI-compat | api.openai.com/v1/chat/completions | Bearer token |
| Anthropic | Кастомный | api.anthropic.com/v1/messages | x-api-key + anthropic-version |
| Gemini | Кастомный | generativelanguage.googleapis.com/v1beta/models/{model}:generateContent | API key в query |
| Mistral | OpenAI-compat | api.mistral.ai/v1/chat/completions | Bearer token |
| Groq | OpenAI-compat | api.groq.com/openai/v1/chat/completions | Bearer token |
| OpenRouter | OpenAI-compat | openrouter.ai/api/v1/chat/completions | Bearer token |
| Ollama | Кастомный | localhost:11434/api/chat | Без auth, NDJSON streaming |

## Файлы

### Новые
- `provider.go` — интерфейс Provider + StreamFormat + вспомогательные функции
- `registry.go` — ProviderRegistry
- `provider_openai_compat.go` — базовый тип для OpenAI-совместимых
- `provider_openai.go` — OpenAI
- `provider_anthropic.go` — Anthropic
- `provider_gemini.go` — Google Gemini
- `provider_mistral.go` — Mistral
- `provider_groq.go` — Groq
- `provider_openrouter.go` — OpenRouter
- `provider_ollama.go` — Ollama
- `provider_test.go` — 27 unit-тестов

### Изменённые
- `handler.go` — полная переработка под Provider interface
- `stream.go` — добавлена ForwardNDJSON
- `config.go` — 6 новых API-ключей
- `main.go` — Registry + wildcard route
- `docker-compose.yml` — env-переменные для новых провайдеров

### Удалённые
- `transport.go` — логика перенесена в Provider.BuildRequest

## Тесты
27 тестов, все проходят:
- Registry: register, get, list, get unknown
- Каждый провайдер: BuildRequest (URL, headers), ParseResponse (tokens, cost)
- Ollama: custom URL, NDJSON streaming, zero cost
- Cross-cutting: interface compliance, invalid JSON handling
- calculateProviderCost: known model, fallback

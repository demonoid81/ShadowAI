# Анализ готовности проекта ShadowAI

**Дата**: 2026-04-15
**Режим**: DISCUSSION

## Контекст

Проведён полный аудит проекта ShadowAI для определения степени готовности к продакшену.

## Сводная оценка

| Компонент | Готовность | Блокеры |
|---|---|---|
| Backend: компиляция | ❌ НЕ КОМПИЛИРУЕТСЯ | 3 ошибки |
| Backend: тесты | ⚠️ 2 из 15 пакетов | Нет тестов для auth, dlp, internaldb |
| Backend: безопасность | ✅ Хорошая основа | Нет тестов для security-critical модулей |
| Backend: код | ⚠️ Монолит в handler | proxy/handler.go — 1510 строк |
| Frontend: сборка | ✅ Собирается | — |
| Frontend: страницы | ✅ 6/6 реализованы | — |
| Frontend: тесты | ❌ Нет | — |
| Frontend: новые фичи | ⚠️ Не покрыты | DLP и Internal DB не имеют UI |
| Docker/Infra | ⚠️ Неполный | Новые env-переменные не проброшены |

## Критические проблемы (блокеры)

1. **Backend НЕ компилируется** — 3 ошибки:
   - `proxy/handler.go:485` — неиспользуемая переменная `start`
   - `proxy/handler.go:1428` — несовпадение типов `dlp.Finding` vs `pii.Finding` в Sanitize()
   - `internaldb/manager.go:93` — некорректный формат в fmt.Errorf()

2. **Покрытие тестами ~20%** — протестированы только proxy (cache, health) и pii

## Положительные стороны

- JWT: валидация signing method, 24h expiry, issued-at check
- Пароли: bcrypt с DefaultCost
- API-ключи: 32 bytes random, SHA256 hash, ротация
- DLP: детекция секретов (AWS, GitHub, bearer tokens, private keys)
- SQL injection prevention в internaldb (keyword filtering, prepared statements)
- Frontend собирается без ошибок (97KB JS + 10.5KB CSS)
- Роутер с auth guard, axios interceptor для 401

## Рекомендованное направление

1. **Починить компиляцию** (блокер #1)
2. **Добавить тесты** для auth, dlp, internaldb
3. **Декомпозировать** proxy/handler.go (1510 строк → модули)
4. **Пробросить** новые env-переменные в docker-compose
5. **Реализовать** UI для DLP и Internal DB

## Открытые вопросы

- Какой уровень тестового покрытия считается приемлемым?
- Нужна ли декомпозиция proxy/handler.go до или после стабилизации тестов?
- Приоритет: UI для DLP/Internal DB или стабилизация бэкенда?

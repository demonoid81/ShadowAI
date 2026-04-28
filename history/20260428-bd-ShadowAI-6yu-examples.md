# ShadowAI-6yu examples

## Happy path 1: старт с Settings

Оператор берёт `ShadowAI-ux4`. Он получает ограниченный scope: read-only `/settings`, без write-actions и без fake live status. После реализации build проходит, и следующий исполнитель может перейти к tenant CRUD.

## Happy path 2: tenant admin выделен отдельно

Оператор берёт `ShadowAI-ux5`. Ему не нужно одновременно решать MFA, governance v2 и compliance workspace. Scope ограничен организациями, SCIM tokens и org budget.

## Edge case 1: backend API отсутствует

Если child-задача обнаруживает, что нужного backend endpoint нет, она не делает mock-success UI. Вместо этого создаётся отдельная backend dependency, а frontend показывает unknown/not configured state.

## Edge case 2: слишком большой frontend файл

Если реализация child-задачи делает страницу больше 300 строк или смешивает несколько ответственностей, исполнитель должен выделить компоненты или composables. Это особенно вероятно для `ShadowAI-ux5`, `ShadowAI-ux7` и `ShadowAI-ux8`.

## Failure case 1: fake live status

Если UI показывает зелёный статус для CronJob, SIEM, evidence sink или production readiness без фактического backend signal, задача не считается завершённой. Такое состояние нарушает основной контракт epic.

## Failure case 2: auth redirect loop

Для `ShadowAI-ux6` MFA challenge не должен попадать под общий 401 redirect loop. Если пользователь получил `mfa_required`, frontend должен вести на MFA verify flow, а не сбрасывать токен и возвращать на обычный login.

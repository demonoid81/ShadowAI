# Dataset Sources

Все примеры в этом каталоге написаны или курированы для PR-5
(ShadowAI-2aa). Ни один текст не заимствован из датасетов в полном
виде; `source`-поле указывает **жанр** (категорию public-известных
паттернов атаки), на основе которого пример был составлен.

## `source` теги

| Тег                   | Что означает                                                     |
|-----------------------|------------------------------------------------------------------|
| `owasp-llm01`         | Категория OWASP LLM Top 10 2023 — LLM01 Prompt Injection.       |
| `jailbreak-common`    | Канонические паттерны из публичных обсуждений (DAN, STAN, AIM). |
| `curated`             | Пример написан автором для покрытия конкретного pattern'а.       |
| `curated-ru`          | То же, на русском (для мультиязычного coverage).                |

## Ссылки (для reviewer'а)

- [OWASP LLM Top 10 2023](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Injection Primer (OWASP gist)](https://github.com/jthack/PIPE)
- [PromptBench paper](https://arxiv.org/abs/2306.04528) — методология,
  из которой заимствуется идея "persuasive" paraphrases (не тексты).
- [Garak (NVIDIA)](https://github.com/NVIDIA/garak) — inspired, not
  copied.

## Добавление новых примеров

1. Убедитесь, что текст НЕ скопирован дословно из external dataset'ов
   с restrictive лицензией.
2. Добавьте строку в соответствующий `*.jsonl`. Поля `id` уникальны
   в пределах файла.
3. Обновите `LICENSES.md`, если используете новый source-тег.
4. Прогоните `go run ./cmd/firewall-bench --all` и убедитесь, что
   baseline проходит.

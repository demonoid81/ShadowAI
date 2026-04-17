# Dataset Licenses

Все примеры в `positive.jsonl` / `negative.jsonl` распространяются под
лицензиями, указанными в поле `license` каждой записи.

## Используемые лицензии

| Лицензия   | Применение                                                               |
|------------|---------------------------------------------------------------------------|
| `CC0`      | Канонические паттерны из public domain (OWASP examples, well-known jailbreak names — DAN, STAN, AIM). Эти названия — общеизвестные и не защищены copyright. |
| `MIT`      | Все тексты с тегом `source: curated*` — написаны автором для ShadowAI. Разрешено использование, модификация, распространение с сохранением атрибуции проекту ShadowAI. |

## Полный текст MIT (для curated примеров)

```
Copyright (c) 2026 ShadowAI contributors

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

## CC0 для well-known patterns

Строки из категорий `owasp-llm01` и `jailbreak-common` представляют
общеизвестные формулировки атак (ignore previous instructions, DAN
persona, etc.), которые публиковались в многочисленных источниках
без единого ownership'а. ShadowAI не претендует на их authorship;
они включены для reproducibility бенчмарка.

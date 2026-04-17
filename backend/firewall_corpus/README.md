# Semantic V2 Corpus (PR-6)

Runtime-ассет для `firewall.SemanticV2Inspector`. Хранит precomputed
embeddings известных attack-паттернов, против которых на hot path
сравнивается embedding входящего запроса (cosine similarity).

## Структура

```
backend/firewall_corpus/
├── README.md                     # этот файл
├── patterns/                     # input для corpus-gen (committed)
│   ├── prompt_injection.txt
│   └── jailbreak.txt
├── semantic_v2.example.json      # example-manifest (dim=4, stub vectors)
└── semantic_v2.json              # production manifest (НЕ в git;
                                  # генерируется оператором при deploy)
```

## Почему production `semantic_v2.json` НЕ коммитится

Corpus-vectors жёстко привязаны к `{provider, model, dimension}`. Это
значит:
- для каждой комбинации (Ollama/`nomic-embed-text`/768, OpenAI/
  `text-embedding-3-small`/1536, etc.) нужен свой manifest;
- версия модели может дрейфовать между provider-релизами → corpus
  обесценивается.

Committed file превратился бы в один "правильный" вариант для всех,
что ломает multi-provider контракт. Вместо этого оператор генерирует
свой manifest при deploy — `SemanticV2Inspector` init fail-fast при
mismatch, так что "чужой" corpus не пройдёт.

## Генерация

```bash
cd backend

# 1. Запустите embedding provider.
# Ollama:
ollama pull nomic-embed-text
# (сервер на http://localhost:11434)

# 2. Сгенерируйте manifest.
go run ./cmd/firewall-corpus-gen \
  --patterns ./firewall_corpus/patterns \
  --output   ./firewall_corpus/semantic_v2.json \
  --provider ollama \
  --endpoint http://localhost:11434 \
  --model    nomic-embed-text \
  --dimension 768 \
  --timeout  30s

# 3. Включите в env:
export FIREWALL_SA_V2_ENABLED=true
export FIREWALL_EMBEDDING_PROVIDER=ollama
export FIREWALL_EMBEDDING_ENDPOINT=http://localhost:11434
export FIREWALL_EMBEDDING_MODEL=nomic-embed-text
export FIREWALL_EMBEDDING_DIMENSION=768
export FIREWALL_SA_V2_CORPUS_PATH=./firewall_corpus/semantic_v2.json

# 4. Запустите backend. В логах:
# "semantic_v2: registered (provider=ollama model=nomic-embed-text dim=768 corpus_items=~50)"
```

## Обновление corpus

Расширить `patterns/*.txt` (добавить строки или новый файл-категорию) →
перегенерировать:

```bash
go run ./cmd/firewall-corpus-gen --patterns ./firewall_corpus/patterns --output ./firewall_corpus/semantic_v2.json ...
```

## `semantic_v2.example.json`

Заглушка с `dimension=4` и stub-embeddings (легко узнаваемые `[1,0,0,0]`,
`[0,1,0,0]`). Никогда не используйте её в production — provider/model
`example` не существуют, cosine similarity против этих векторов не имеет
смысла. Файл служит только для:
- демонстрации manifest-формата;
- регрессионных тестов `LoadCorpus`.

## Formats

### Manifest

```json
{
  "version": 1,
  "provider": "ollama",
  "model": "nomic-embed-text",
  "dimension": 768,
  "normalized": true,
  "generated_at": "2026-04-17T12:00:00Z",
  "items": [
    {
      "id": "prompt_injection-001",
      "category": "prompt_injection",
      "text": "ignore previous instructions",
      "embedding": [0.12, -0.04, 0.33, ...]
    }
  ]
}
```

### Patterns input

`patterns/<category>.txt` — одна непустая строка = один pattern.
Пустые строки игнорируются. `id` генерируется автоматически как
`<category>-<3-значный-индекс>`.

## Observability

- `shadowai_firewall_decisions_total{inspector="semantic_v2", ...}`
  — решения инспектора.
- `shadowai_embedding_requests_total{provider, model}` — общий счётчик
  embed-вызовов.
- `shadowai_embedding_fail_total` / `_timeout_total` — деградация
  embedding layer (не overlap'ятся).
- `shadowai_embedding_latency_seconds` — distribution для success'ных
  вызовов.
- `GET /proxy/firewall/status` — per-inspector metadata (provider,
  model, thresholds, corpus_items, dimension). Endpoint URL и APIKey
  НЕ раскрываются.

## Roadmap (v2+)

- `cmd/firewall-corpus-verify` — отдельный command для validation'а
  committed manifest'а (shape + dimension + normalization) без
  запуска backend.
- Auto-regen как part of CI job (requires Ollama-sidecar).
- Multiple corpus per-category support (например, разные thresholds
  для prompt_injection vs content_moderation).

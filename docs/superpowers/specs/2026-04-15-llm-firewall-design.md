# LLM Firewall — Design Spec

**Дата**: 2026-04-15
**Статус**: Approved
**Автор**: Mikhail + Claude

## Цель

Превратить ShadowAI из базового AI Control Plane в полноценный LLM Firewall с двусторонней инспекцией запросов/ответов, защитой от prompt injection, jailbreak-атак и вредоносного контента.

## Контекст

### Текущее состояние
- PII Detection: 5 regex-паттернов (email, phone, credit_card, ssn, ip)
- DLP: 7 secret-паттернов, 3 режима (audit/enforce/strict)
- Policy Engine: 4 типа правил (pii_block, pii_warn, keyword_block, model_restrict)
- Двусторонняя инспекция request/response уже работает
- Всё вшито монолитно в `proxy/handler.go` (1500+ строк)

### Проблема
- Нет защиты от prompt injection и jailbreak
- Нет content moderation
- Нет semantic analysis (только regex)
- Архитектура не расширяема — добавление нового инспектора требует правки handler

## Подход: Гибридная детекция

Двухслойная архитектура:
1. **Heuristic Layer** — быстрый regex + scoring (отсекает очевидное, ~1ms)
2. **LLM-as-Judge Layer** — верификация подозрительных запросов через configurable LLM (~200-500ms)

LLM-judge вызывается только при превышении scoring-порога heuristic-слоя.

## Архитектура

### Inspector Pipeline

```
Request
  ↓
[Inspector Pipeline — request phase]
  ├── PII Inspector (existing, refactored)
  ├── DLP Inspector (existing, refactored)
  ├── Policy Inspector (existing, refactored)
  ├── Prompt Injection Inspector (new)
  ├── Jailbreak Inspector (new)
  ├── Content Moderation Inspector (future)
  └── Content Rate Limiter (future)
  ↓
[First BLOCK → return 403, audit]
[SANITIZE → modify payload, continue]
[ALLOW → continue]
  ↓
Forward to Provider
  ↓
[Inspector Pipeline — response phase]
  ├── PII Inspector
  ├── DLP Inspector
  ├── Output Validator (future)
  └── Content Moderation Inspector (future)
  ↓
Return to Client
```

### Ключевые интерфейсы

```go
package firewall

type Phase string
const (
    PhaseRequest  Phase = "request"
    PhaseResponse Phase = "response"
)

type Action string
const (
    ActionAllow    Action = "allow"
    ActionBlock    Action = "block"
    ActionSanitize Action = "sanitize"
    ActionFlag     Action = "flag"  // allow but mark for review
)

type Severity string
const (
    SeverityLow      Severity = "low"
    SeverityMedium   Severity = "medium"
    SeverityHigh     Severity = "high"
    SeverityCritical Severity = "critical"
)

type Finding struct {
    Type     string   `json:"type"`
    Severity Severity `json:"severity"`
    Match    string   `json:"match"`
    Start    int      `json:"start"`
    End      int      `json:"end"`
    Meta     map[string]string `json:"meta,omitempty"`
}

type Decision struct {
    Action   Action    `json:"action"`
    Reason   string    `json:"reason"`
    Severity Severity  `json:"severity"`
    Findings []Finding `json:"findings"`
}

type Payload struct {
    Text      string            // extracted text from all messages
    Messages  []Message         // original messages
    Model     string
    Provider  string
    UserID    string
    Phase     Phase
    Meta      map[string]string // arbitrary metadata
}

type Message struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

type Inspector interface {
    Name() string
    InspectRequest(ctx context.Context, p *Payload) (*Decision, error)
    InspectResponse(ctx context.Context, p *Payload) (*Decision, error)
}

type Pipeline struct {
    inspectors []Inspector
}

func (p *Pipeline) Register(i Inspector)
func (p *Pipeline) InspectRequest(ctx context.Context, payload *Payload) (*Decision, error)
func (p *Pipeline) InspectResponse(ctx context.Context, payload *Payload) (*Decision, error)
```

Pipeline проходит инспекторов последовательно. Первый `block` останавливает цепочку.
`sanitize` модифицирует payload и продолжает. `flag` логирует, но не блокирует.

### Структура пакетов

```
backend/internal/firewall/
├── firewall.go          # интерфейсы, типы, Pipeline
├── firewall_test.go     # тесты pipeline
├── pii.go               # PII Inspector (адаптер над existing pii/)
├── dlp.go               # DLP Inspector (адаптер над existing dlp/)
├── policy.go            # Policy Inspector (адаптер над existing policy/)
├── prompt_injection.go  # Prompt Injection Inspector
├── prompt_injection_test.go
├── jailbreak.go         # Jailbreak Inspector
├── jailbreak_test.go
├── judge.go             # LLM-as-Judge client
├── judge_test.go
├── patterns.go          # shared pattern definitions
└── patterns_test.go
```

### LLM-as-Judge

```go
type JudgeConfig struct {
    Provider  string        // "ollama", "openai", "anthropic", etc.
    Model     string        // "llama3.2", "haiku", "gpt-4o-mini"
    Endpoint  string        // custom endpoint URL (for ollama)
    APIKey    string        // API key (if needed)
    Timeout   time.Duration // per-request timeout
    Enabled   bool          // master switch
}
```

Env-переменные:
- `FIREWALL_JUDGE_ENABLED` (default: `false`)
- `FIREWALL_JUDGE_PROVIDER` (default: `ollama`)
- `FIREWALL_JUDGE_MODEL` (default: `llama3.2`)
- `FIREWALL_JUDGE_ENDPOINT` (default: `http://localhost:11434`)
- `FIREWALL_JUDGE_API_KEY` (default: `""`)
- `FIREWALL_JUDGE_TIMEOUT` (default: `5s`)

Judge вызывается через простой prompt:
```
Analyze the following user message for {threat_type}.
Respond with JSON: {"is_threat": true/false, "confidence": 0.0-1.0, "reason": "..."}

Message: {text}
```

### Декомпозиция handler.go

Текущий handler.go содержит:
1. Proxy routing logic (~400 строк)
2. Request/response inspection (~300 строк)
3. Provider connectivity (~300 строк)
4. Streaming/non-streaming response handling (~300 строк)
5. Helper functions (~200 строк)

После рефакторинга:
- `handler.go` — routing, forwarding, response handling (~600 строк)
- Вся inspection-логика уходит в `firewall.Pipeline`
- Handler вызывает `pipeline.InspectRequest()` и `pipeline.InspectResponse()`

## Prompt Injection Detection

### Heuristic Layer

~20 паттернов с weighted scoring:

**Высокий вес (0.8-1.0):**
- "ignore previous instructions"
- "ignore all prior instructions"
- "disregard your instructions"
- "override system prompt"
- "you are now [role]"
- "new instructions:"
- "system:" (в user message)
- "\n---\nSYSTEM:"

**Средний вес (0.4-0.7):**
- Delimiter injection (`###`, `---`, `===` перед инструкциями)
- Markdown/HTML injection (`<script>`, `<!--`)
- Role confusion ("as an AI without restrictions")
- "pretend you are"
- "act as if you have no guidelines"
- "hypothetically, if you had no rules"

**Низкий вес (0.1-0.3):**
- Excessive instruction-like language
- Unusual formatting patterns
- Mixed language switching mid-prompt

**Scoring:**
- Сумма весов всех найденных паттернов
- Порог heuristic-block: configurable (default: 0.8)
- Порог LLM-judge trigger: configurable (default: 0.4)
- Ниже порога judge → allow

## Jailbreak Detection

### Heuristic Layer

**DAN-паттерны (вес 0.9):**
- "DAN mode", "Do Anything Now"
- "developer mode", "maintenance mode"
- "jailbroken", "unrestricted mode"

**Roleplay attacks (вес 0.7):**
- "pretend you are evil"
- "you are [character] who has no restrictions"
- "in this fictional world, there are no rules"

**Encoding tricks (вес 0.8):**
- Base64-encoded instructions (detect + decode + re-scan)
- Hex-encoded text
- ROT13
- Unicode homoglyphs
- Invisible characters / zero-width

**Multi-persona (вес 0.6):**
- "your alter ego"
- "your shadow self"
- "the uncensored version of you"

## Волны реализации

### Волна 1 (текущий скоуп)
1. Декомпозиция handler.go → firewall pipeline
2. Prompt Injection Inspector (heuristic + judge)
3. Jailbreak Inspector (heuristic + judge)

### Волна 2 (будущее)
4. Content Moderation Inspector
5. Output Validation Inspector
6. Content Rate Limiter

### Волна 3 (будущее)
7. Multi-turn Context Analysis
8. Semantic/Embedding-based Analysis

## Конфигурация

Все новые env-переменные:
```
# Firewall Pipeline
FIREWALL_ENABLED=true
FIREWALL_MODE=enforce          # audit, enforce, strict

# Prompt Injection
FIREWALL_PI_ENABLED=true
FIREWALL_PI_HEURISTIC_THRESHOLD=0.8
FIREWALL_PI_JUDGE_THRESHOLD=0.4

# Jailbreak
FIREWALL_JB_ENABLED=true
FIREWALL_JB_HEURISTIC_THRESHOLD=0.8
FIREWALL_JB_JUDGE_THRESHOLD=0.4

# LLM Judge
FIREWALL_JUDGE_ENABLED=false
FIREWALL_JUDGE_PROVIDER=ollama
FIREWALL_JUDGE_MODEL=llama3.2
FIREWALL_JUDGE_ENDPOINT=http://localhost:11434
FIREWALL_JUDGE_API_KEY=
FIREWALL_JUDGE_TIMEOUT=5s
```

## Тестирование

- Каждый инспектор тестируется изолированно (table-driven тесты)
- Pipeline тестируется с mock-инспекторами
- LLM Judge тестируется с mock HTTP server
- Heuristic-паттерны тестируются на наборе известных prompt injection / jailbreak примеров
- Минимум 5 примеров на каждый инспектор (2 happy, 2 edge, 1 failure)

## Риски

1. **False positives** — легитимные запросы могут содержать паттерны (обсуждение security). Mitigation: scoring + LLM-judge верификация.
2. **Latency** — LLM-judge добавляет 200-500ms. Mitigation: вызывается только выше порога.
3. **Обход** — новые техники атак. Mitigation: паттерны обновляемы, LLM-judge адаптивен.
4. **Рекурсия** — firewall judge вызывает LLM через тот же proxy. Mitigation: judge использует прямое HTTP-соединение, минуя proxy pipeline.

package firewall

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MultiTurnConfig содержит конфигурацию инспектора многоходовых атак.
type MultiTurnConfig struct {
	Enabled            bool
	WindowSize         int           // макс. сообщений для анализа (по умолчанию: 10)
	HeuristicThreshold float64       // порог комбинированного score (по умолчанию: 0.6)
	SessionTTL         time.Duration // TTL сессии (по умолчанию: 30m)
}

type sessionMessage struct {
	content   string
	timestamp time.Time
}

type userSession struct {
	messages []sessionMessage
	mu       sync.Mutex
}

// MultiTurnInspector обнаруживает кумулятивные атаки, распределённые
// по нескольким сообщениям в рамках одной сессии.
type MultiTurnInspector struct {
	config          MultiTurnConfig
	sessions        map[string]*userSession
	mu              sync.RWMutex
	piPatterns      []PatternRule
	jbPatterns      []PatternRule
	rolePatterns    []*regexp.Regexp
	lastCleanup     time.Time
	cleanupInterval time.Duration
}

// NewMultiTurnInspector создаёт новый инспектор многоходовых атак.
func NewMultiTurnInspector(cfg MultiTurnConfig) *MultiTurnInspector {
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 10
	}
	if cfg.HeuristicThreshold <= 0 {
		cfg.HeuristicThreshold = 0.6
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * time.Minute
	}

	return &MultiTurnInspector{
		config:     cfg,
		sessions:   make(map[string]*userSession),
		piPatterns: DefaultPromptInjectionPatterns(),
		jbPatterns: DefaultJailbreakPatterns(),
		rolePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\byou\s+are\b`),
			regexp.MustCompile(`(?i)\bact\s+as\b`),
			regexp.MustCompile(`(?i)\bpretend\b`),
			regexp.MustCompile(`(?i)\byour\s+role\s+is\b`),
			regexp.MustCompile(`(?i)\bbehave\s+as\b`),
			regexp.MustCompile(`(?i)\byou\s+are\s+now\b`),
		},
		lastCleanup:     time.Now(),
		cleanupInterval: 5 * time.Minute,
	}
}

// Name возвращает имя инспектора.
func (m *MultiTurnInspector) Name() string { return "multiturn" }

// InspectRequest проверяет запрос на кумулятивные многоходовые атаки.
func (m *MultiTurnInspector) InspectRequest(ctx context.Context, p *Payload) (*Decision, error) {
	if !m.config.Enabled {
		return &Decision{Action: ActionAllow}, nil
	}

	userID := p.UserID
	if userID == "" {
		userID = "_anonymous"
	}

	// Session key = userID + conversation_id. Разные диалоги одного
	// пользователя НЕ должны смешиваться. Если клиент не передал
	// conversation_id, fallback на userID-only (legacy behavior, но с warning).
	sessionKey := userID
	if convID := p.Meta["conversation_id"]; convID != "" {
		sessionKey = userID + ":" + convID
	}

	// Извлечь пользовательские сообщения из payload
	userMessages := m.extractUserMessages(p)
	if len(userMessages) == 0 {
		return &Decision{Action: ActionAllow}, nil
	}

	// Получить или создать сессию пользователя по составному ключу
	session := m.getOrCreateSession(sessionKey)

	session.mu.Lock()
	// Добавить только НОВЫЕ сообщения.
	// Chat-клиенты обычно resend'ят всю историю на каждом turn; без
	// дедупликации сессия бы накапливала дубликаты, искажая анализ.
	now := time.Now()
	existing := make(map[string]struct{}, len(session.messages))
	for _, sm := range session.messages {
		existing[sm.content] = struct{}{}
	}
	for _, msg := range userMessages {
		if _, dup := existing[msg]; dup {
			continue
		}
		session.messages = append(session.messages, sessionMessage{
			content:   msg,
			timestamp: now,
		})
		existing[msg] = struct{}{}
	}

	// Удалить просроченные сообщения
	m.evictExpired(session, now)

	// Ограничить размер окна
	if len(session.messages) > m.config.WindowSize {
		session.messages = session.messages[len(session.messages)-m.config.WindowSize:]
	}

	// Собрать тексты для анализа
	var texts []string
	for _, sm := range session.messages {
		texts = append(texts, sm.content)
	}
	session.mu.Unlock()

	// Ленивая очистка просроченных сессий
	m.lazyCleanup(now)

	if len(texts) == 0 {
		return &Decision{Action: ActionAllow}, nil
	}

	// --- Стратегия 1: Обнаружение конкатенационных атак ---
	decision, err := m.detectConcatenationAttack(texts)
	if err != nil {
		return nil, err
	}
	if decision != nil {
		return decision, nil
	}

	// --- Стратегия 2: Обнаружение эскалации ролей ---
	decision = m.detectRoleEscalation(texts)
	if decision != nil {
		return decision, nil
	}

	// --- Стратегия 3: Постепенное расширение границ ---
	decision = m.detectGradualBoundaryPush(p, texts)
	if decision != nil {
		return decision, nil
	}

	return &Decision{Action: ActionAllow}, nil
}

// InspectResponse не выполняет проверку ответов.
func (m *MultiTurnInspector) InspectResponse(ctx context.Context, p *Payload) (*Decision, error) {
	return &Decision{Action: ActionAllow}, nil
}

// extractUserMessages извлекает тексты сообщений из payload.
// Включает все сообщения (не только user) для полного контекста сессии.
// Если Messages пуст, используется Text как fallback (синтетическое user-сообщение).
func (m *MultiTurnInspector) extractUserMessages(p *Payload) []string {
	if len(p.Messages) > 0 {
		var msgs []string
		for _, msg := range p.Messages {
			if msg.Content != "" {
				msgs = append(msgs, msg.Content)
			}
		}
		return msgs
	}
	// Fallback на Text — создаём синтетическое user-сообщение
	if p.Text != "" {
		return []string{p.Text}
	}
	return nil
}

// getOrCreateSession возвращает существующую или создаёт новую сессию.
func (m *MultiTurnInspector) getOrCreateSession(userID string) *userSession {
	m.mu.RLock()
	session, ok := m.sessions[userID]
	m.mu.RUnlock()
	if ok {
		return session
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// Double-check
	if session, ok = m.sessions[userID]; ok {
		return session
	}
	session = &userSession{}
	m.sessions[userID] = session
	return session
}

// evictExpired удаляет сообщения с истёкшим TTL.
func (m *MultiTurnInspector) evictExpired(session *userSession, now time.Time) {
	cutoff := now.Add(-m.config.SessionTTL)
	i := 0
	for i < len(session.messages) && session.messages[i].timestamp.Before(cutoff) {
		i++
	}
	if i > 0 {
		session.messages = session.messages[i:]
	}
}

// lazyCleanup удаляет сессии без актуальных сообщений.
func (m *MultiTurnInspector) lazyCleanup(now time.Time) {
	m.mu.RLock()
	needCleanup := now.Sub(m.lastCleanup) > m.cleanupInterval
	m.mu.RUnlock()

	if !needCleanup {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastCleanup = now
	cutoff := now.Add(-m.config.SessionTTL)

	for uid, session := range m.sessions {
		session.mu.Lock()
		if len(session.messages) == 0 ||
			session.messages[len(session.messages)-1].timestamp.Before(cutoff) {
			delete(m.sessions, uid)
		}
		session.mu.Unlock()
	}
}

// detectConcatenationAttack конкатенирует все сообщения и сравнивает score
// объединённого текста с максимальным score отдельных сообщений.
func (m *MultiTurnInspector) detectConcatenationAttack(texts []string) (*Decision, error) {
	allPatterns := make([]PatternRule, 0, len(m.piPatterns)+len(m.jbPatterns))
	allPatterns = append(allPatterns, m.piPatterns...)
	allPatterns = append(allPatterns, m.jbPatterns...)

	// Score каждого сообщения по отдельности
	maxIndividualScore := 0.0
	for _, text := range texts {
		result := MatchPatterns(text, allPatterns)
		if result.Score > maxIndividualScore {
			maxIndividualScore = result.Score
		}
	}

	// Score конкатенированного текста
	concatenated := strings.Join(texts, " ")
	concatResult := MatchPatterns(concatenated, allPatterns)

	// Кумулятивная атака: конкатенированный score значительно превышает
	// максимальный индивидуальный score
	scoreDiff := concatResult.Score - maxIndividualScore
	if concatResult.Score >= m.config.HeuristicThreshold && scoreDiff > 0.1 {
		findings := matchesToFindings(concatResult.Matches, "multiturn_concatenation")
		return &Decision{
			Action:   ActionBlock,
			Reason:   "multi-turn concatenation attack detected: combined messages form malicious payload",
			Severity: SeverityHigh,
			Findings: findings,
		}, nil
	}

	// Конкатенированный score выше порога, но разница невелика — flag
	if concatResult.Score >= m.config.HeuristicThreshold {
		findings := matchesToFindings(concatResult.Matches, "multiturn_concatenation")
		return &Decision{
			Action:   ActionFlag,
			Reason:   "suspicious multi-turn pattern detected in combined messages",
			Severity: SeverityMedium,
			Findings: findings,
		}, nil
	}

	return nil, nil
}

// detectRoleEscalation обнаруживает нарастающие попытки смены роли ИИ.
func (m *MultiTurnInspector) detectRoleEscalation(texts []string) *Decision {
	if len(texts) < 2 {
		return nil
	}

	totalMatches := 0
	messagesWithRole := 0

	for _, text := range texts {
		matchCount := 0
		for _, rp := range m.rolePatterns {
			locs := rp.FindAllStringIndex(text, -1)
			matchCount += len(locs)
		}
		if matchCount > 0 {
			messagesWithRole++
			totalMatches += matchCount
		}
	}

	// Плотность: доля сообщений с role-changing языком
	density := float64(messagesWithRole) / float64(len(texts))

	// Если больше половины сообщений содержат role-changing паттерны
	// и общее количество совпадений достаточно велико
	if density >= 0.5 && totalMatches >= 3 {
		return &Decision{
			Action:   ActionFlag,
			Reason:   "role escalation pattern detected: progressive attempts to change AI role",
			Severity: SeverityMedium,
			Findings: []Finding{
				{
					Type:     "multiturn_role_escalation",
					Severity: SeverityMedium,
					Match:    "role-changing language density across turns",
					Meta: map[string]string{
						"density":       fmt.Sprintf("%.2f", density),
						"total_matches": strconv.Itoa(totalMatches),
					},
				},
			},
		}
	}

	return nil
}

// detectGradualBoundaryPush обнаруживает постепенное расширение границ.
func (m *MultiTurnInspector) detectGradualBoundaryPush(p *Payload, texts []string) *Decision {
	if p.Meta == nil {
		return nil
	}
	if p.Meta["flagged"] != "true" {
		return nil
	}

	allPatterns := make([]PatternRule, 0, len(m.piPatterns)+len(m.jbPatterns))
	allPatterns = append(allPatterns, m.piPatterns...)
	allPatterns = append(allPatterns, m.jbPatterns...)

	flaggedCount := 0
	for _, text := range texts {
		result := MatchPatterns(text, allPatterns)
		if result.Score > 0.2 {
			flaggedCount++
		}
	}

	if flaggedCount >= 3 {
		return &Decision{
			Action:   ActionFlag,
			Reason:   "gradual boundary pushing detected: multiple flagged messages in session",
			Severity: SeverityMedium,
			Findings: []Finding{
				{
					Type:     "multiturn_boundary_push",
					Severity: SeverityMedium,
					Match:    "gradual escalation across session",
					Meta: map[string]string{
						"flagged_count": strconv.Itoa(flaggedCount),
					},
				},
			},
		}
	}

	return nil
}

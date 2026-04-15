package firewall

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// PatternRule defines a single heuristic pattern for detection.
type PatternRule struct {
	Name    string
	Pattern *regexp.Regexp
	Weight  float64
	Type    string
}

// PatternMatch represents a single match of a pattern in text.
type PatternMatch struct {
	Rule  PatternRule
	Match string
	Start int
	End   int
}

// MatchResult aggregates all matches and computes a combined score.
type MatchResult struct {
	Score   float64
	Matches []PatternMatch
}

// MatchPatterns scans text against a set of patterns (case-insensitive).
// The score is the sum of weights of matched patterns, capped at 1.0.
func MatchPatterns(text string, patterns []PatternRule) MatchResult {
	if text == "" {
		return MatchResult{Score: 0}
	}

	lower := strings.ToLower(text)
	var matches []PatternMatch
	score := 0.0

	for _, rule := range patterns {
		locs := rule.Pattern.FindAllStringIndex(lower, -1)
		for _, loc := range locs {
			matches = append(matches, PatternMatch{
				Rule:  rule,
				Match: text[loc[0]:loc[1]],
				Start: loc[0],
				End:   loc[1],
			})
		}
		if len(locs) > 0 {
			score += rule.Weight
		}
	}

	// Check for base64-encoded payloads
	b64Matches := detectBase64Payloads(text, patterns)
	matches = append(matches, b64Matches.Matches...)
	score += b64Matches.Score

	if score > 1.0 {
		score = 1.0
	}

	return MatchResult{
		Score:   score,
		Matches: matches,
	}
}

// detectBase64Payloads finds base64-encoded strings in text, decodes them,
// and re-scans the decoded content against the same patterns.
func detectBase64Payloads(text string, patterns []PatternRule) MatchResult {
	b64Re := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	candidates := b64Re.FindAllStringIndex(text, -1)

	var matches []PatternMatch
	score := 0.0

	for _, loc := range candidates {
		candidate := text[loc[0]:loc[1]]
		decoded, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil {
			// Try RawStdEncoding (no padding)
			decoded, err = base64.RawStdEncoding.DecodeString(candidate)
			if err != nil {
				continue
			}
		}

		decodedStr := string(decoded)
		if !utf8.ValidString(decodedStr) {
			continue
		}

		lower := strings.ToLower(decodedStr)
		for _, rule := range patterns {
			if rule.Pattern.MatchString(lower) {
				matches = append(matches, PatternMatch{
					Rule:  rule,
					Match: candidate,
					Start: loc[0],
					End:   loc[1],
				})
				score += rule.Weight
			}
		}
	}

	return MatchResult{
		Score:   score,
		Matches: matches,
	}
}

// DefaultPromptInjectionPatterns returns heuristic patterns for detecting
// prompt injection attempts.
func DefaultPromptInjectionPatterns() []PatternRule {
	return []PatternRule{
		{
			Name:    "ignore_previous_instructions",
			Pattern: regexp.MustCompile(`ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|guidelines)`),
			Weight:  0.4,
			Type:    "prompt_injection",
		},
		{
			Name:    "system_override",
			Pattern: regexp.MustCompile(`(system\s*:\s*|<<\s*sys\s*>>|<\|system\|>)\s*you\s+are`),
			Weight:  0.4,
			Type:    "prompt_injection",
		},
		{
			Name:    "new_instructions",
			Pattern: regexp.MustCompile(`(new|updated|revised|real)\s+instructions?\s*:`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "you_are_now",
			Pattern: regexp.MustCompile(`you\s+are\s+now\s+(a|an|the|my)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "forget_everything",
			Pattern: regexp.MustCompile(`forget\s+(everything|all|what)\s+(you|i)\s+(know|told|said|learned)`),
			Weight:  0.4,
			Type:    "prompt_injection",
		},
		{
			Name:    "disregard",
			Pattern: regexp.MustCompile(`disregard\s+(all\s+)?(previous|prior|your|the)\s+(instructions|rules|guidelines|programming)`),
			Weight:  0.4,
			Type:    "prompt_injection",
		},
		{
			Name:    "override_safety",
			Pattern: regexp.MustCompile(`(override|bypass|disable|turn\s+off|remove)\s+(safety|content|ethical)\s*(filters?|restrictions?|guidelines?|policies?|rules?)`),
			Weight:  0.4,
			Type:    "prompt_injection",
		},
		{
			Name:    "pretend_no_rules",
			Pattern: regexp.MustCompile(`pretend\s+(that\s+)?(you\s+)?(have\s+no|don'?t\s+have|are\s+without)\s+(rules|restrictions|guidelines|limits)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "act_as_if",
			Pattern: regexp.MustCompile(`act\s+as\s+if\s+(you\s+)?(were|are)\s+(unrestricted|unfiltered|uncensored|without\s+rules)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "reveal_system_prompt",
			Pattern: regexp.MustCompile(`(reveal|show|display|print|output|repeat)\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt|hidden\s+prompt|secret\s+prompt)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "do_anything_now",
			Pattern: regexp.MustCompile(`do\s+anything\s+now`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "stop_being",
			Pattern: regexp.MustCompile(`stop\s+being\s+(a\s+)?(helpful|safe|responsible|ethical|moral|good)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "from_now_on",
			Pattern: regexp.MustCompile(`from\s+now\s+on\s+(you\s+)?(will|must|should|shall)\s+(ignore|disregard|forget|not\s+follow)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "actual_instructions",
			Pattern: regexp.MustCompile(`(actual|true|real|hidden)\s+instructions?\s+(are|is|were|was)\s*:`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
		{
			Name:    "end_system_begin",
			Pattern: regexp.MustCompile(`(\[/?system\]|\[/?inst\]|<\/?system>|<\/?instructions?>)`),
			Weight:  0.3,
			Type:    "prompt_injection",
		},
	}
}

// DefaultJailbreakPatterns returns heuristic patterns for detecting
// jailbreak attempts.
func DefaultJailbreakPatterns() []PatternRule {
	return []PatternRule{
		{
			Name:    "dan_mode",
			Pattern: regexp.MustCompile(`\bdan\b.*\b(mode|prompt|jailbreak|enabled)\b`),
			Weight:  0.5,
			Type:    "jailbreak",
		},
		{
			Name:    "developer_mode",
			Pattern: regexp.MustCompile(`(developer|dev)\s+mode\s+(enabled|activated|on|output)`),
			Weight:  0.5,
			Type:    "jailbreak",
		},
		{
			Name:    "jailbreak_keyword",
			Pattern: regexp.MustCompile(`\bjailbreak(ed|ing)?\b`),
			Weight:  0.3,
			Type:    "jailbreak",
		},
		{
			Name:    "evil_roleplay",
			Pattern: regexp.MustCompile(`(act|behave|respond|pretend)\s+(as|like)\s+(an?\s+)?(evil|malicious|unethical|immoral|dark|villain|criminal)`),
			Weight:  0.4,
			Type:    "jailbreak",
		},
		{
			Name:    "fictional_no_rules",
			Pattern: regexp.MustCompile(`(fictional|hypothetical|imaginary)\s+(world|scenario|universe|setting)\s+(where|with|in\s+which)\s+(there\s+are\s+)?no\s+(rules|laws|ethics|morals|restrictions)`),
			Weight:  0.4,
			Type:    "jailbreak",
		},
		{
			Name:    "alter_ego",
			Pattern: regexp.MustCompile(`(alter\s+ego|evil\s+twin|shadow\s+self|dark\s+side|opposite\s+mode)`),
			Weight:  0.3,
			Type:    "jailbreak",
		},
		{
			Name:    "token_smuggling",
			Pattern: regexp.MustCompile(`(ignore|bypass)\s*\[.*?\]\s*(previous|safety|rules)`),
			Weight:  0.4,
			Type:    "jailbreak",
		},
		{
			Name:    "character_play",
			Pattern: regexp.MustCompile(`(play|roleplay|simulate|emulate)\s+(as\s+)?(a\s+)?(character|persona|entity)\s+(that|who|which)\s+(has\s+no|ignores?|doesn'?t\s+(follow|have))\s+(rules|restrictions|ethics|guidelines)`),
			Weight:  0.4,
			Type:    "jailbreak",
		},
		{
			Name:    "opposite_day",
			Pattern: regexp.MustCompile(`(opposite|backwards?)\s+(day|mode|world)`),
			Weight:  0.2,
			Type:    "jailbreak",
		},
		{
			Name:    "unrestricted_ai",
			Pattern: regexp.MustCompile(`(unrestricted|unfiltered|uncensored|unbound|unchained|unleashed)\s+(ai|artificial\s+intelligence|language\s+model|llm|assistant|chatbot|gpt|model)`),
			Weight:  0.4,
			Type:    "jailbreak",
		},
		{
			Name:    "grandma_exploit",
			Pattern: regexp.MustCompile(`(grandma|grandmother|grandpa|grandfather)\s+(used\s+to|would|always)\s+(tell|read|say|recite)`),
			Weight:  0.2,
			Type:    "jailbreak",
		},
	}
}

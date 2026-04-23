package proxy

import (
	"errors"
	"testing"
)

func TestIncrementalSecurityVerdict(t *testing.T) {
	cases := []struct {
		name     string
		original string
		blocked  bool
		flagged  bool
		want     string
	}{
		// Block beats flag, block beats original.
		{"blocked_only", "allowed", true, false, "blocked"},
		{"blocked_beats_flag", "allowed", true, true, "blocked"},
		{"blocked_preserves_original_on_override", "sanitized", true, false, "blocked"},

		// Flag when original is allow → canonical "warned".
		{"flag_on_allow", "allowed", false, true, canonicalFlaggedPolicyAction},

		// Flag when original is already warned/blocked/sanitized → original unchanged.
		{"flag_on_warned", "warned", false, true, "warned"},
		{"flag_on_blocked", "blocked", false, true, "blocked"},
		{"flag_on_sanitized", "sanitized", false, true, "sanitized"},

		// Neither block nor flag → original unchanged.
		{"no_signal_allow", "allowed", false, false, "allowed"},
		{"no_signal_warned", "warned", false, false, "warned"},

		// Key regression: transport_error path — even though outcome will be
		// stream_transport_error, security verdict should NOT be lost.
		// (Callers pass blocked=false, flagged=true when flag was observed
		// before transport failed; verdict should still say "warned".)
		{"flagged_then_transport_error", "allowed", false, true, canonicalFlaggedPolicyAction},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := incrementalSecurityVerdict(c.original, c.blocked, c.flagged)
			if got != c.want {
				t.Errorf("incrementalSecurityVerdict(%q, blocked=%v, flagged=%v) = %q, want %q",
					c.original, c.blocked, c.flagged, got, c.want)
			}
		})
	}
}

// TestClassifyBufferedOutcome_WarnedRecognized — FR-F7.3.1 regression
// guard. applyFlagCorrelation возвращает "warned" для флагнутых
// потоков в buffered path. classifyBufferedOutcome должен распознавать
// "warned" так же как "flagged", иначе outcome будет stream_completed
// вместо stream_flagged.
func TestClassifyBufferedOutcome_WarnedRecognized(t *testing.T) {
	// "warned" — canonical flag от applyFlagCorrelation.
	got := classifyBufferedOutcome("warned", false, nil)
	if got != OutcomeStreamFlagged {
		t.Errorf("classifyBufferedOutcome(%q, ...) = %q, want %q",
			"warned", got, OutcomeStreamFlagged)
	}
}

func TestClassifyUsageSource(t *testing.T) {
	boom := errors.New("parser fatal")
	partial := StreamUsage{Found: true, Partial: true}
	full := StreamUsage{Found: true, Partial: false}
	notFound := StreamUsage{Found: false}
	// F7.4: table covers all three UsageSource values.
	cases := []struct {
		name      string
		u         StreamUsage
		parseErr  error
		completed bool
		want      string
	}{
		// Happy paths: normal completed stream.
		{"final_completed", full, nil, true, UsageSourceFinal},
		// Partial usage but stream completed normally → final (not partial).
		// PR-F7.4 invariant: stream_completed overrides Partial flag.
		{"partial_flag_but_completed", partial, nil, true, UsageSourceFinal},

		// Interrupted stream + found.
		{"final_interrupted", full, nil, false, UsageSourceFinal},
		{"partial_interrupted", partial, nil, false, UsageSourcePartial},

		// No usage found.
		{"none_found_false", notFound, nil, true, UsageSourceNone},
		{"none_found_false_incomplete", notFound, nil, false, UsageSourceNone},

		// Parser error → none.
		{"none_parse_error_found", full, boom, true, UsageSourceNone},
		{"none_parse_error_partial", partial, boom, false, UsageSourceNone},
		{"none_parse_error_notfound", notFound, boom, false, UsageSourceNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyUsageSource(c.u, c.parseErr, c.completed)
			if got != c.want {
				t.Errorf("classifyUsageSource(%+v, parseErr=%v, completed=%v) = %q, want %q",
					c.u, c.parseErr, c.completed, got, c.want)
			}
		})
	}
}

func TestClassifyIncrementalOutcome(t *testing.T) {
	boom := errors.New("parser fatal")
	cases := []struct {
		name         string
		blocked      bool
		transportErr bool
		parseErr     error
		overBudget   bool
		flagged      bool
		want         string
	}{
		{"clean_completed", false, false, nil, false, false, OutcomeStreamCompleted},
		{"flagged", false, false, nil, false, true, OutcomeStreamFlagged},
		{"budget_soft", false, false, nil, true, false, OutcomeStreamBudgetExceededSoft},
		{"parse_failed", false, false, boom, false, false, OutcomeStreamUsageParseFailed},
		{"transport_error", false, true, nil, false, false, OutcomeStreamTransportError},
		{"blocked_midflight", true, false, nil, false, false, OutcomeStreamBlockedMidflight},

		// Priority checks: block beats all others.
		{"priority_block_over_transport", true, true, nil, false, false, OutcomeStreamBlockedMidflight},
		{"priority_block_over_parse", true, false, boom, false, false, OutcomeStreamBlockedMidflight},
		{"priority_block_over_budget", true, false, nil, true, false, OutcomeStreamBlockedMidflight},
		{"priority_block_over_flag", true, false, nil, false, true, OutcomeStreamBlockedMidflight},
		// Transport error beats parse/budget/flag.
		{"priority_transport_over_parse", false, true, boom, false, false, OutcomeStreamTransportError},
		{"priority_transport_over_budget", false, true, nil, true, false, OutcomeStreamTransportError},
		{"priority_transport_over_flag", false, true, nil, false, true, OutcomeStreamTransportError},
		// Parse error beats budget/flag.
		{"priority_parse_over_budget", false, false, boom, true, false, OutcomeStreamUsageParseFailed},
		{"priority_parse_over_flag", false, false, boom, false, true, OutcomeStreamUsageParseFailed},
		// Budget beats flag.
		{"priority_budget_over_flag", false, false, nil, true, true, OutcomeStreamBudgetExceededSoft},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyIncrementalOutcome(c.blocked, c.transportErr, c.parseErr, c.overBudget, c.flagged)
			if got != c.want {
				t.Errorf("classifyIncrementalOutcome(%+v) = %q, want %q", c, got, c.want)
			}
		})
	}
}

func TestClassifyBufferedOutcome(t *testing.T) {
	boom := errors.New("parser fatal")
	cases := []struct {
		name     string
		policy   string
		fallback bool
		parseErr error
		want     string
	}{
		// Non-fallback paths.
		{"non_fallback_allowed", "allowed", false, nil, OutcomeStreamCompleted},
		{"non_fallback_sanitized", "sanitized", false, nil, OutcomeStreamCompleted},
		{"non_fallback_blocked", "blocked", false, nil, OutcomeStreamBlocked},
		{"non_fallback_flagged", "flagged", false, nil, OutcomeStreamFlagged},
		{"non_fallback_parse_error", "allowed", false, boom, OutcomeStreamUsageParseFailed},

		// Fallback paths — fallback outcome dominates regardless of inner verdict.
		{"fallback_allowed", "allowed", true, nil, OutcomeStreamBufferedFallback},
		{"fallback_blocked", "blocked", true, nil, OutcomeStreamBufferedFallback},
		{"fallback_flagged", "flagged", true, nil, OutcomeStreamBufferedFallback},
		{"fallback_sanitized", "sanitized", true, nil, OutcomeStreamBufferedFallback},
		{"fallback_parse_error", "allowed", true, boom, OutcomeStreamBufferedFallback},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyBufferedOutcome(c.policy, c.fallback, c.parseErr)
			if got != c.want {
				t.Errorf("classifyBufferedOutcome(%+v) = %q, want %q", c, got, c.want)
			}
		})
	}
}

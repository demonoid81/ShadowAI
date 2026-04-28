package proxy

import (
	"github.com/shadowai/backend/internal/dlp"
	"github.com/shadowai/backend/internal/firewall"
)

type sanitizeFindingSpan struct {
	Start int
	End   int
}

func firewallFindingSpans(findings []firewall.Finding) []sanitizeFindingSpan {
	spans := make([]sanitizeFindingSpan, 0, len(findings))
	for _, f := range findings {
		spans = append(spans, sanitizeFindingSpan{Start: f.Start, End: f.End})
	}
	return spans
}

func dlpFindingSpans(findings []dlp.Finding) []sanitizeFindingSpan {
	spans := make([]sanitizeFindingSpan, 0, len(findings))
	for _, f := range findings {
		spans = append(spans, sanitizeFindingSpan{Start: f.Start, End: f.End})
	}
	return spans
}

func sanitizeFindingCoverage(
	spans []sanitizeFindingSpan,
	windowStartAbs int,
	deltaStartAbs int,
	deltaEndAbs int,
) (hasCurrentDeltaFinding bool, unsafeCrossChunkFinding bool) {
	for _, span := range spans {
		if span.Start < 0 || span.End <= span.Start {
			continue
		}
		absStart := windowStartAbs + span.Start
		absEnd := windowStartAbs + span.End
		if absEnd <= deltaStartAbs {
			continue
		}
		if absStart >= deltaStartAbs && absEnd <= deltaEndAbs {
			hasCurrentDeltaFinding = true
			continue
		}
		return hasCurrentDeltaFinding, true
	}
	return hasCurrentDeltaFinding, false
}

func unsafeCrossChunkSanitizeVerdict(inspector, reason string) incrementalVerdict {
	if inspector == "" {
		inspector = "dlp"
	}
	msg := "unsafe cross-chunk sanitize verdict: sensitive match spans already emitted chunks"
	if reason != "" {
		msg += ": " + reason
	}
	return incrementalVerdict{
		Block:         true,
		InspectorName: inspector,
		Reason:        msg,
	}
}

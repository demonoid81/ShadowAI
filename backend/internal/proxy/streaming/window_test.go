package streaming

import (
	"strings"
	"testing"
)

func TestInspectionWindow_SlidingBounds(t *testing.T) {
	w := &InspectionWindow{WindowCap: 16, AccumCap: 64}
	w.Append("abcd") // 4 bytes
	w.Append("efgh") // 8 bytes
	if got := w.Window(); got != "abcdefgh" {
		t.Errorf("window = %q, want abcdefgh", got)
	}
	w.Append("ijklmnop") // 16 bytes total — at cap
	if got := w.Window(); got != "abcdefghijklmnop" {
		t.Errorf("window = %q", got)
	}
	w.Append("XYZ") // overflow 3 bytes — oldest 3 dropped
	if got := w.Window(); got != "defghijklmnopXYZ" {
		t.Errorf("window = %q, want sliding drop", got)
	}
}

func TestInspectionWindow_AccumulatedUnbounded_WithinCap(t *testing.T) {
	w := &InspectionWindow{WindowCap: 8, AccumCap: 32}
	for _, s := range []string{"alpha-", "beta-", "gamma-"} {
		w.Append(s)
	}
	// All 17 bytes under 32-cap → accumulated keeps everything.
	if got := w.Accumulated(); got != "alpha-beta-gamma-" {
		t.Errorf("accumulated = %q", got)
	}
}

func TestInspectionWindow_AccumulatedCaps(t *testing.T) {
	w := &InspectionWindow{WindowCap: 4, AccumCap: 10}
	w.Append(strings.Repeat("x", 8))
	w.Append(strings.Repeat("y", 8))
	if l := len(w.Accumulated()); l != 10 {
		t.Errorf("accumulated len = %d, want 10 (capped)", l)
	}
}

func TestInspectionWindow_EmptyDelta(t *testing.T) {
	w := NewInspectionWindow()
	w.Append("") // no-op
	if w.Len() != 0 {
		t.Errorf("len = %d, want 0 after empty append", w.Len())
	}
}

// TestInspectionWindow_CrossChunkPattern — ключевой use case:
// pattern-matching должен работать через границы chunk'ов, если
// pattern помещается в window cap.
func TestInspectionWindow_CrossChunkPattern(t *testing.T) {
	w := NewInspectionWindow()
	// API key вида "sk-" + 48 chars — ~51 bytes, помещается в 8KB
	// window с запасом, даже если разбит на frame'ы по 1 байту.
	parts := []string{"s", "k", "-", "A", "B", "C", "D", "E", "F", "1", "2", "3"}
	for _, p := range parts {
		w.Append(p)
	}
	if got := w.Window(); !strings.Contains(got, "sk-ABCDEF123") {
		t.Errorf("cross-chunk pattern lost: window = %q", got)
	}
}

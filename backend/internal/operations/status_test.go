package operations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildSnapshot_OKWarnUnknownCounts(t *testing.T) {
	snap := BuildSnapshot(RuntimeConfig{
		AuditPayloadMode:           "redacted",
		AuditRetentionDays:         90,
		AuditPurgeInterval:         time.Hour,
		AuditAnchorInterval:        time.Hour,
		AuditAnchorSink:            "file://",
		AuditAnchorAdditionalSinks: "immudb://",
		AuditAnchorSigningEnabled:  true,
		AuditAnchorPubKeyID:        "ed25519-k1",
		AuditChainEnabled:          true,
		SIEMEnabled:                true,
		BYOKEnabled:                true,
	}, DependencyStatus{DBOK: true, RedisOK: true}, time.Unix(10, 0).UTC())

	if snap.Summary.Total != 8 {
		t.Fatalf("total = %d, want 8", snap.Summary.Total)
	}
	if snap.Summary.Error != 0 {
		t.Fatalf("error = %d, want 0", snap.Summary.Error)
	}
	if snap.Summary.Unknown != 3 {
		t.Fatalf("unknown = %d, want 3 external-source unknowns", snap.Summary.Unknown)
	}
	if got := findSignal(t, snap, "evidence_anchors"); got.Status != StatusOK {
		t.Fatalf("evidence_anchors status = %s, want ok", got.Status)
	}
}

func TestBuildSnapshot_ReadinessDegraded(t *testing.T) {
	snap := BuildSnapshot(RuntimeConfig{AuditRetentionDays: 30}, DependencyStatus{DBOK: true, RedisOK: false}, time.Now())
	signal := findSignal(t, snap, "readiness")
	if signal.Status != StatusError {
		t.Fatalf("readiness status = %s, want error", signal.Status)
	}
	failed, ok := signal.Details["failed_checks"].([]string)
	if !ok || len(failed) != 1 || failed[0] != "redis" {
		t.Fatalf("failed_checks = %#v, want [redis]", signal.Details["failed_checks"])
	}
}

func TestBuildSnapshot_RetentionDisabledIsWarn(t *testing.T) {
	snap := BuildSnapshot(RuntimeConfig{AuditRetentionDays: 0}, DependencyStatus{DBOK: true, RedisOK: true}, time.Now())
	signal := findSignal(t, snap, "audit_retention")
	if signal.Status != StatusWarn {
		t.Fatalf("audit_retention status = %s, want warn", signal.Status)
	}
}

func TestBuildSnapshot_AnchorsNoExternalSinkIsWarn(t *testing.T) {
	snap := BuildSnapshot(RuntimeConfig{AuditRetentionDays: 30, AuditAnchorInterval: time.Hour}, DependencyStatus{DBOK: true, RedisOK: true}, time.Now())
	signal := findSignal(t, snap, "evidence_anchors")
	if signal.Status != StatusWarn {
		t.Fatalf("evidence_anchors status = %s, want warn", signal.Status)
	}
}

func TestBuildSnapshot_DoesNotExposeSecrets(t *testing.T) {
	snap := BuildSnapshot(RuntimeConfig{
		AuditRetentionDays:        30,
		AuditAnchorInterval:       time.Hour,
		AuditAnchorSink:           "immudb://",
		AuditAnchorSigningEnabled: true,
		AuditChainEnabled:         true,
	}, DependencyStatus{DBOK: true, RedisOK: true}, time.Now())

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"AUDIT_CHAIN_SECRET", "AUDIT_ANCHOR_SIGNING_KEY", "token", "password", "secret"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("snapshot contains forbidden secret marker %q: %s", forbidden, string(body))
		}
	}
}

func TestHandler_StatusWithNilDependenciesIsDegraded(t *testing.T) {
	h := &Handler{
		cfg: RuntimeConfig{AuditRetentionDays: 30},
		now: func() time.Time { return time.Unix(20, 0).UTC() },
	}
	req := httptest.NewRequest(http.MethodGet, "/api/operations/status", nil)
	rec := httptest.NewRecorder()

	h.Status(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}
	var snap Snapshot
	if err := json.NewDecoder(rec.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if findSignal(t, snap, "readiness").Status != StatusError {
		t.Fatalf("nil dependencies should produce degraded readiness")
	}
}

func findSignal(t *testing.T, snap Snapshot, key string) Signal {
	t.Helper()
	for _, signal := range snap.Signals {
		if signal.Key == key {
			return signal
		}
	}
	t.Fatalf("signal %q not found", key)
	return Signal{}
}

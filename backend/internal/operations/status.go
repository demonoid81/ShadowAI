package operations

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/shadowai/backend/internal/config"
)

type SignalStatus string

const (
	StatusOK      SignalStatus = "ok"
	StatusWarn    SignalStatus = "warn"
	StatusError   SignalStatus = "error"
	StatusUnknown SignalStatus = "unknown"
)

type Signal struct {
	Key     string         `json:"key"`
	Status  SignalStatus   `json:"status"`
	Source  string         `json:"source"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

type Summary struct {
	Total   int `json:"total"`
	OK      int `json:"ok"`
	Warn    int `json:"warn"`
	Error   int `json:"error"`
	Unknown int `json:"unknown"`
}

type Snapshot struct {
	GeneratedAt time.Time `json:"generated_at"`
	Summary     Summary   `json:"summary"`
	Signals     []Signal  `json:"signals"`
}

type DependencyStatus struct {
	DBOK    bool
	RedisOK bool
}

type RuntimeConfig struct {
	AuditPayloadMode           string
	AuditRetentionDays         int
	AuditPurgeInterval         time.Duration
	AuditAnchorInterval        time.Duration
	AuditAnchorSink            string
	AuditAnchorAdditionalSinks string
	AuditAnchorSigningEnabled  bool
	AuditAnchorPubKeyID        string
	AuditChainEnabled          bool
	SIEMEnabled                bool
	BYOKEnabled                bool
}

type Handler struct {
	cfg   RuntimeConfig
	db    *sql.DB
	redis redis.UniversalClient
	now   func() time.Time
}

func RuntimeConfigFromConfig(cfg *config.Config) RuntimeConfig {
	if cfg == nil {
		return RuntimeConfig{}
	}
	return RuntimeConfig{
		AuditPayloadMode:           cfg.AuditPayloadMode,
		AuditRetentionDays:         cfg.AuditRetentionDays,
		AuditPurgeInterval:         cfg.AuditPurgeInterval,
		AuditAnchorInterval:        cfg.AuditAnchorInterval,
		AuditAnchorSink:            cfg.AuditAnchorSink,
		AuditAnchorAdditionalSinks: cfg.AuditAnchorAdditionalSinks,
		AuditAnchorSigningEnabled:  strings.TrimSpace(cfg.AuditAnchorSigningKey) != "",
		AuditAnchorPubKeyID:        cfg.AuditAnchorPubKeyID,
		AuditChainEnabled:          strings.TrimSpace(cfg.AuditChainSecret) != "",
		SIEMEnabled:                cfg.SIEMEnabled,
		BYOKEnabled:                cfg.BYOKEnabled,
	}
}

func NewHandler(cfg *config.Config, db *sql.DB, redis redis.UniversalClient) *Handler {
	return &Handler{
		cfg:   RuntimeConfigFromConfig(cfg),
		db:    db,
		redis: redis,
		now:   time.Now,
	}
}

func BuildSnapshot(cfg RuntimeConfig, deps DependencyStatus, generatedAt time.Time) Snapshot {
	signals := []Signal{
		{
			Key:     "liveness",
			Status:  StatusOK,
			Source:  "process",
			Message: "process is serving HTTP",
		},
		readinessSignal(deps),
		auditRetentionSignal(cfg),
		evidenceAnchorsSignal(cfg),
		siemSignal(cfg),
		{
			Key:     "evidence_export_cronjob",
			Status:  StatusUnknown,
			Source:  "external_scheduler",
			Message: "no backend source for last evidence export job status is configured",
		},
		{
			Key:     "evidence_audit_report_cronjob",
			Status:  StatusUnknown,
			Source:  "external_scheduler",
			Message: "no backend source for last retention audit report job status is configured",
		},
		{
			Key:     "prometheus_alerts",
			Status:  StatusUnknown,
			Source:  "prometheus",
			Message: "Prometheus alert state is not integrated with this API yet",
		},
	}

	return Snapshot{
		GeneratedAt: generatedAt.UTC(),
		Summary:     summarize(signals),
		Signals:     signals,
	}
}

func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	resp := BuildSnapshot(h.cfg, h.checkDependencies(ctx), h.now())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) checkDependencies(ctx context.Context) DependencyStatus {
	status := DependencyStatus{}
	if h.db != nil && h.db.PingContext(ctx) == nil {
		status.DBOK = true
	}
	if h.redis != nil && h.redis.Ping(ctx).Err() == nil {
		status.RedisOK = true
	}
	return status
}

func readinessSignal(deps DependencyStatus) Signal {
	failed := []string{}
	if !deps.DBOK {
		failed = append(failed, "db")
	}
	if !deps.RedisOK {
		failed = append(failed, "redis")
	}
	if len(failed) == 0 {
		return Signal{
			Key:     "readiness",
			Status:  StatusOK,
			Source:  "db_redis_ping",
			Message: "database and redis are reachable",
			Details: map[string]any{"db": "ok", "redis": "ok"},
		}
	}
	return Signal{
		Key:     "readiness",
		Status:  StatusError,
		Source:  "db_redis_ping",
		Message: "one or more runtime dependencies are unreachable",
		Details: map[string]any{"failed_checks": failed},
	}
}

func auditRetentionSignal(cfg RuntimeConfig) Signal {
	details := map[string]any{
		"payload_mode":            cfg.AuditPayloadMode,
		"retention_days":          cfg.AuditRetentionDays,
		"purge_scheduler_enabled": cfg.AuditPurgeInterval > 0,
	}
	if cfg.AuditRetentionDays <= 0 {
		return Signal{
			Key:     "audit_retention",
			Status:  StatusWarn,
			Source:  "runtime_config",
			Message: "audit retention TTL is disabled",
			Details: details,
		}
	}
	return Signal{
		Key:     "audit_retention",
		Status:  StatusOK,
		Source:  "runtime_config",
		Message: "audit retention TTL is configured",
		Details: details,
	}
}

func evidenceAnchorsSignal(cfg RuntimeConfig) Signal {
	details := map[string]any{
		"anchor_scheduler_enabled": cfg.AuditAnchorInterval > 0,
		"external_sink":            strings.TrimSpace(cfg.AuditAnchorSink),
		"additional_sinks":         nonEmptyCSVCount(cfg.AuditAnchorAdditionalSinks),
		"signing_enabled":          cfg.AuditAnchorSigningEnabled,
		"pubkey_id_configured":     strings.TrimSpace(cfg.AuditAnchorPubKeyID) != "",
		"chain_enabled":            cfg.AuditChainEnabled,
	}
	if cfg.AuditAnchorInterval <= 0 {
		return Signal{
			Key:     "evidence_anchors",
			Status:  StatusUnknown,
			Source:  "runtime_config",
			Message: "audit anchor scheduler is disabled or not configured",
			Details: details,
		}
	}
	if strings.TrimSpace(cfg.AuditAnchorSink) == "" {
		return Signal{
			Key:     "evidence_anchors",
			Status:  StatusWarn,
			Source:  "runtime_config",
			Message: "anchors are scheduled but no external witness sink is configured",
			Details: details,
		}
	}
	return Signal{
		Key:     "evidence_anchors",
		Status:  StatusOK,
		Source:  "runtime_config",
		Message: "anchor scheduler and external witness sink are configured",
		Details: details,
	}
}

func siemSignal(cfg RuntimeConfig) Signal {
	details := map[string]any{
		"enabled":      cfg.SIEMEnabled,
		"byok_enabled": cfg.BYOKEnabled,
	}
	if !cfg.SIEMEnabled {
		return Signal{
			Key:     "siem_delivery",
			Status:  StatusUnknown,
			Source:  "runtime_config",
			Message: "SIEM delivery is disabled or not configured",
			Details: details,
		}
	}
	return Signal{
		Key:     "siem_delivery",
		Status:  StatusOK,
		Source:  "runtime_config",
		Message: "SIEM delivery is enabled; delivery health requires metrics/alert review",
		Details: details,
	}
}

func summarize(signals []Signal) Summary {
	s := Summary{Total: len(signals)}
	for _, signal := range signals {
		switch signal.Status {
		case StatusOK:
			s.OK++
		case StatusWarn:
			s.Warn++
		case StatusError:
			s.Error++
		case StatusUnknown:
			s.Unknown++
		}
	}
	return s
}

func nonEmptyCSVCount(value string) int {
	count := 0
	for _, item := range strings.Split(value, ",") {
		if strings.TrimSpace(item) != "" {
			count++
		}
	}
	return count
}

package adminaudit

import (
	"context"
	"encoding/json"
	"log"

	"github.com/shadowai/backend/internal/domain"
)

// Event — struct для сборки admin event'а в вызывающем коде.
// Metadata принимает любой marshalable struct/map — сервис сам
// выполняет JSON-encode и guarantees, что invalid JSON не ломает
// request-path (фолбэк на empty metadata + log).
type Event struct {
	ActorUserID *string
	Action      string
	Resource    string
	TargetID    string
	Path        string
	Method      string
	StatusCode  int
	Success     bool
	Metadata    any
}

// Recorder — интерфейс для DI в handler'ах (mock'ается в тестах).
type Recorder interface {
	Record(ctx context.Context, ev Event)
}

// Service — синхронный writer admin events. Ошибка Insert логируется,
// но не пропагирует в caller: admin-audit не должен ломать основной
// endpoint (fail-open для availability).
type Service struct {
	repo Repo
}

// Repo — минимальный интерфейс, чтобы Service был testable без БД.
// Production: *Repository (implements).
type Repo interface {
	Insert(ctx context.Context, e *domain.AdminEvent) error
}

// NewService. Если repo=nil, Record становится no-op — полезно для
// dev без admin-audit БД-таблицы.
func NewService(repo Repo) *Service {
	return &Service{repo: repo}
}

// Record пишет один admin event. Sync. Не блокирует больше чем
// один INSERT.
func (s *Service) Record(ctx context.Context, ev Event) {
	if s == nil || s.repo == nil {
		return
	}
	metaStr := ""
	if ev.Metadata != nil {
		b, err := json.Marshal(ev.Metadata)
		if err != nil {
			log.Printf("adminaudit: failed to marshal metadata: %v", err)
		} else {
			metaStr = string(b)
		}
	}
	if err := s.repo.Insert(ctx, &domain.AdminEvent{
		ActorUserID:  ev.ActorUserID,
		Action:       ev.Action,
		Resource:     ev.Resource,
		TargetID:     ev.TargetID,
		Path:         ev.Path,
		Method:       ev.Method,
		StatusCode:   ev.StatusCode,
		Success:      ev.Success,
		MetadataJSON: metaStr,
	}); err != nil {
		log.Printf("adminaudit: insert failed (non-fatal): %v", err)
	}
}

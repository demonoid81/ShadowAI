package audit

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"github.com/shadowai/backend/internal/domain"
	"github.com/shadowai/backend/internal/metrics"
)

// Repo абстрагирует Repository для тестируемости.
// Production использует *Repository, тесты могут подставить in-memory mock.
type Repo interface {
	Insert(ctx context.Context, log *domain.AuditLog) error
	// hasShadow: "" | "any" | "yes" | "no" — фильтр по наличию
	// shadow_decisions_json. "yes" → IS NOT NULL, "no" → IS NULL,
	// пусто/"any" → без фильтра (backward compat для call-site'ов).
	List(ctx context.Context, limit, offset int, userID, model, policyAction, hasShadow string) ([]domain.AuditLog, int, error)

	// PR-A: retention/purge.
	PurgeOlderThan(ctx context.Context, cutoff time.Time, chunkSize int) (int, error)
	// PR-L2: retention-aware purge с exclusion list. Rows, где
	// user_id in exceptUserIDs, НЕ удаляются (защита evidence для
	// users'ов под active legal hold). nil/empty exceptUserIDs →
	// идентично PurgeOlderThan.
	//
	// PR-L2.1: scheduler перешёл на enterprise-only
	// PurgeOlderThanRespectingHolds (single-SQL, race-free). Этот
	// метод остаётся в interface для backward-compat с Core CLI и
	// внешними consumer'ами, которые передают свой snapshot.
	PurgeOlderThanExcept(ctx context.Context, cutoff time.Time, chunkSize int, exceptUserIDs []string) (int, error)
	// PR-D.1: target parameter разделяет purge-runs по таблицам
	// (audit_logs vs admin_event_logs). target="" → audit_logs (BC).
	RecordPurgeRun(ctx context.Context, cutoff time.Time, rowsDeleted int, target string) error
	LastPurgeRun(ctx context.Context, target string) (*domain.PurgeRun, error)
	TotalRowsPurged(ctx context.Context, target string) (int, error)
}

type Service struct {
	repo     Repo
	ch       chan *domain.AuditLog
	done     chan struct{}
	dropped  atomic.Uint64 // счётчик отброшенных записей (канал переполнен)
	inserted atomic.Uint64 // счётчик успешно записанных
	failed   atomic.Uint64 // счётчик ошибок на DB.Insert
}

func NewService(repo Repo) *Service {
	s := &Service{
		repo: repo,
		ch:   make(chan *domain.AuditLog, 1000),
		done: make(chan struct{}),
	}
	go s.worker()
	return s
}

func (s *Service) Log(entry *domain.AuditLog) {
	select {
	case s.ch <- entry:
		metrics.RecordAuditQueue(len(s.ch))
	default:
		s.dropped.Add(1)
		metrics.AuditDroppedTotal.Inc()
		log.Printf("audit: channel full, dropping entry (total dropped=%d)", s.dropped.Load())
	}
}

// Stats возвращает метрики audit pipeline для observability/monitoring.
func (s *Service) Stats() (queueDepth int, dropped, inserted, failed uint64) {
	return len(s.ch), s.dropped.Load(), s.inserted.Load(), s.failed.Load()
}

func (s *Service) worker() {
	defer close(s.done)
	for entry := range s.ch {
		metrics.RecordAuditQueue(len(s.ch))
		if err := s.repo.Insert(context.Background(), entry); err != nil {
			s.failed.Add(1)
			metrics.AuditFailedTotal.Inc()
			log.Printf("audit: insert error (total failed=%d): %v", s.failed.Load(), err)
		} else {
			s.inserted.Add(1)
			metrics.AuditInsertedTotal.Inc()
		}
	}
}

// Close останавливает worker. Используется в тестах для детерминистичного flush.
func (s *Service) Close() {
	close(s.ch)
	<-s.done
}

func (s *Service) GetRepo() Repo {
	return s.repo
}

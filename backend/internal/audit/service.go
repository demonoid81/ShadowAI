package audit

import (
	"context"
	"log"

	"github.com/shadowai/backend/internal/domain"
)

// Repo абстрагирует Repository для тестируемости.
// Production использует *Repository, тесты могут подставить in-memory mock.
type Repo interface {
	Insert(ctx context.Context, log *domain.AuditLog) error
	List(ctx context.Context, limit, offset int, userID, model, policyAction string) ([]domain.AuditLog, int, error)
}

type Service struct {
	repo Repo
	ch   chan *domain.AuditLog
	done chan struct{}
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
	default:
		log.Println("audit: channel full, dropping entry")
	}
}

func (s *Service) worker() {
	defer close(s.done)
	for entry := range s.ch {
		if err := s.repo.Insert(context.Background(), entry); err != nil {
			log.Printf("audit: insert error: %v", err)
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

package audit

import (
	"context"
	"log"

	"github.com/shadowai/backend/internal/domain"
)

type Service struct {
	repo *Repository
	ch   chan *domain.AuditLog
}

func NewService(repo *Repository) *Service {
	s := &Service{
		repo: repo,
		ch:   make(chan *domain.AuditLog, 1000),
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
	for entry := range s.ch {
		if err := s.repo.Insert(context.Background(), entry); err != nil {
			log.Printf("audit: insert error: %v", err)
		}
	}
}

func (s *Service) GetRepo() *Repository {
	return s.repo
}

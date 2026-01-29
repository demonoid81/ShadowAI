package policy

import (
	"context"
	"github.com/google/uuid"
	"github.com/shadowai/backend/internal/domain"
)

type Service struct {
	repo   *Repository
	Engine *Engine
}

func NewService(repo *Repository) *Service {
	return &Service{
		repo:   repo,
		Engine: NewEngine(repo),
	}
}

func (s *Service) List(ctx context.Context) ([]domain.PolicyRule, error) {
	return s.repo.List(ctx)
}

func (s *Service) Create(ctx context.Context, p *domain.PolicyRule) error {
	p.ID = uuid.New().String()
	return s.repo.Create(ctx, p)
}

func (s *Service) Update(ctx context.Context, p *domain.PolicyRule) error {
	return s.repo.Update(ctx, p)
}

func (s *Service) Delete(ctx context.Context, id string) error {
	return s.repo.Delete(ctx, id)
}

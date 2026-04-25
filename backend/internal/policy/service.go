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

func (s *Service) List(ctx context.Context, orgID string) ([]domain.PolicyRule, error) {
	return s.repo.List(ctx, orgID)
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

func (s *Service) DeleteScoped(ctx context.Context, id, orgID string) error {
	return s.repo.DeleteScoped(ctx, id, orgID)
}

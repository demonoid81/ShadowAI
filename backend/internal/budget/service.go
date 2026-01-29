package budget

import (
	"context"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"

	"github.com/shadowai/backend/internal/domain"
)

type Service struct {
	repo  *Repository
	redis *redis.Client
}

func NewService(repo *Repository, rdb *redis.Client) *Service {
	return &Service{repo: repo, redis: rdb}
}

func (s *Service) GetBudget(ctx context.Context, userID string) (*domain.Budget, error) {
	return s.repo.GetByUserID(ctx, userID)
}

func (s *Service) UpdateBudget(ctx context.Context, b *domain.Budget) error {
	return s.repo.Upsert(ctx, b)
}

func (s *Service) CheckBudget(ctx context.Context, userID string) (bool, error) {
	b, err := s.repo.GetByUserID(ctx, userID)
	if err != nil {
		return true, nil // no budget = unlimited
	}

	spentKey := fmt.Sprintf("budget:%s:spent", userID)
	spentStr, err := s.redis.Get(ctx, spentKey).Result()
	if err == redis.Nil {
		spentStr = "0"
	} else if err != nil {
		return true, err
	}

	spent, _ := strconv.ParseFloat(spentStr, 64)
	totalSpent := b.MonthlySpentUSD + spent

	return totalSpent < b.MonthlyLimitUSD, nil
}

func (s *Service) RecordUsage(ctx context.Context, userID string, cost float64, tokens int) error {
	spentKey := fmt.Sprintf("budget:%s:spent", userID)
	tokensKey := fmt.Sprintf("budget:%s:tokens", userID)

	pipe := s.redis.Pipeline()
	pipe.IncrByFloat(ctx, spentKey, cost)
	pipe.IncrBy(ctx, tokensKey, int64(tokens))
	_, err := pipe.Exec(ctx)
	return err
}

func (s *Service) SyncToPG(ctx context.Context, userID string) error {
	spentKey := fmt.Sprintf("budget:%s:spent", userID)
	tokensKey := fmt.Sprintf("budget:%s:tokens", userID)

	spentStr, _ := s.redis.GetDel(ctx, spentKey).Result()
	tokensStr, _ := s.redis.GetDel(ctx, tokensKey).Result()

	spent, _ := strconv.ParseFloat(spentStr, 64)
	tokens, _ := strconv.Atoi(tokensStr)

	if spent > 0 || tokens > 0 {
		return s.repo.UpdateSpent(ctx, userID, spent, tokens)
	}
	return nil
}

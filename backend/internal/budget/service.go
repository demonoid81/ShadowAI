package budget

import (
	"context"
	"fmt"
	"strconv"

	"github.com/redis/go-redis/v9"

	"github.com/shadowai/backend/internal/domain"
)

// BudgetRepo абстрагирует Repository для тестируемости.
type BudgetRepo interface {
	GetByUserID(ctx context.Context, userID string) (*domain.Budget, error)
	Upsert(ctx context.Context, b *domain.Budget) error
	UpdateSpent(ctx context.Context, userID string, addCost float64, addTokens int) error
}

type Service struct {
	repo  BudgetRepo
	redis *redis.Client
}

func NewService(repo BudgetRepo, rdb *redis.Client) *Service {
	return &Service{repo: repo, redis: rdb}
}

func (s *Service) GetBudget(ctx context.Context, userID string) (*domain.Budget, error) {
	return s.repo.GetByUserID(ctx, userID)
}

func (s *Service) UpdateBudget(ctx context.Context, b *domain.Budget) error {
	return s.repo.Upsert(ctx, b)
}

func (s *Service) CheckBudgetAfterUsage(ctx context.Context, userID string, additionalTokens int, additionalSpent float64) (bool, error) {
	b, err := s.repo.GetByUserID(ctx, userID)
	if err != nil {
		return true, nil // no budget = unlimited
	}

	spentKey := fmt.Sprintf("budget:%s:spent", userID)
	tokensKey := fmt.Sprintf("budget:%s:tokens", userID)
	spentStr, err := s.redis.Get(ctx, spentKey).Result()
	if err == redis.Nil {
		spentStr = "0"
	} else if err != nil {
		return true, err
	}
	tokensStr, err := s.redis.Get(ctx, tokensKey).Result()
	if err == redis.Nil {
		tokensStr = "0"
	} else if err != nil {
		return true, err
	}

	spent, _ := strconv.ParseFloat(spentStr, 64)
	tokens, _ := strconv.ParseInt(tokensStr, 10, 64)

	totalSpent := b.MonthlySpentUSD + spent + additionalSpent
	totalTokens := b.MonthlyTokensUsed + int(tokens) + additionalTokens

	if b.MonthlyLimitUSD > 0 && totalSpent >= b.MonthlyLimitUSD {
		return false, nil
	}
	if b.MonthlyTokenLimit > 0 && totalTokens >= b.MonthlyTokenLimit {
		return false, nil
	}
	return true, nil
}

func (s *Service) CheckBudget(ctx context.Context, userID string, additionalTokens int) (bool, error) {
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
	tokens, _ := s.redis.Get(ctx, fmt.Sprintf("budget:%s:tokens", userID)).Int64()
	totalSpent := b.MonthlySpentUSD + spent
	totalTokens := b.MonthlyTokensUsed + int(tokens) + additionalTokens

	if b.MonthlyLimitUSD > 0 && totalSpent >= b.MonthlyLimitUSD {
		return false, nil
	}
	if b.MonthlyTokenLimit > 0 && totalTokens >= b.MonthlyTokenLimit {
		return false, nil
	}

	return true, nil
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

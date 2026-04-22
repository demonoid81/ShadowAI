//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErasureStatus, ErasureResult и константы перенесены в erasure_types.go
// (core Apache 2.0). Остальные типы (ErasureService, AuditScrubber,
// BudgetDeleter) и логика EraseUser остаются здесь под
// //go:build enterprise.

// AuditScrubber — интерфейс для scrubbing audit_logs по user_id
// (в рамках переданной *sql.Tx). Реализован audit.Repository.
type AuditScrubber interface {
	ScrubUserDataTx(ctx context.Context, tx *sql.Tx, userID string) (int, error)
}

// BudgetDeleter — интерфейс для удаления budget-row по user_id.
// Реализован budget.Repository.
type BudgetDeleter interface {
	DeleteByUserIDTx(ctx context.Context, tx *sql.Tx, userID string) (int, error)
}

// ErasureService — orchestration erasure-workflow в одной DB-транзакции.
//
// Sequence:
//  1. Lock user row (SELECT ... FOR UPDATE) или see if already erased;
//  2. Scrub audit_logs (user_id→NULL, bodies→NULL, shadow→NULL, pii→NULL);
//  3. Delete budgets;
//  4. Delete user row;
//  5. Insert user_erasure_runs.
//
// При любой ошибке — transaction rollback, ничего не менялось.
type ErasureService struct {
	db         *sql.DB
	auditScrub AuditScrubber
	budgetDel  BudgetDeleter
	// PR-L1: optional legal-hold check. nil → check пропускается
	// (unit tests / dev без legalhold таблицы). В prod bundle всегда
	// передаёт non-nil.
	holdChecker HoldChecker
}

// HoldChecker — interface для pre-erasure legal-hold check. Satisfies
// в enterprise-сборке через legalhold.Service; в core — unreachable
// (erasure сам под enterprise tag).
type HoldChecker interface {
	HasActiveHold(ctx context.Context, userID string) (bool, error)
}

// NewErasureService — DI constructor. auditScrub + budgetDel
// обязательны; holdChecker опционален (nil OK для старых деплоев
// без legalhold таблицы).
func NewErasureService(db *sql.DB, auditScrub AuditScrubber, budgetDel BudgetDeleter) *ErasureService {
	return &ErasureService{db: db, auditScrub: auditScrub, budgetDel: budgetDel}
}

// WithHoldChecker — chainable setter. Возвращает тот же ErasureService
// для удобства wiring. Использовать из enterprise_wire.go.
func (s *ErasureService) WithHoldChecker(hc HoldChecker) *ErasureService {
	s.holdChecker = hc
	return s
}

// EraseUser выполняет полный erasure-workflow для targetUserID.
// actorUserID — UUID admin'а, инициировавшего операцию; попадает в
// user_erasure_runs.initiated_by_user_id.
//
// Идемпотентность:
//   - Если user уже erased (есть запись в user_erasure_runs) —
//     возвращает ErasureAlreadyErased без изменений БД.
//   - Если user не существует и erase-run'а нет — ErasureNotFound.
//   - Иначе — ErasureCompleted.
func (s *ErasureService) EraseUser(ctx context.Context, actorUserID, targetUserID string) (*ErasureResult, error) {
	if targetUserID == "" {
		return nil, errors.New("erasure: targetUserID required")
	}

	// PR-L1: legal hold check ДО открытия транзакции. Fail-closed:
	// если holdChecker возвращает err (недоступна legal_holds
	// таблица), мы отвергаем erasure — compliance выше availability.
	if s.holdChecker != nil {
		hasHold, err := s.holdChecker.HasActiveHold(ctx, targetUserID)
		if err != nil {
			return nil, fmt.Errorf("erasure: hold check: %w", err)
		}
		if hasHold {
			return &ErasureResult{UserID: targetUserID, Status: ErasureHoldActive}, nil
		}
	}

	// Начинаем транзакцию — все операции atomic.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("erasure: begin tx: %w", err)
	}
	// Защитный rollback; если мы успешно commit'нули, дополнительный
	// rollback — no-op для Postgres driver.
	defer func() { _ = tx.Rollback() }()

	// 1. Lock user row (если есть). FOR UPDATE блокирует параллельные
	// erase-run'ы на тот же target.
	var exists bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 FOR UPDATE)`,
		targetUserID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("erasure: lock user: %w", err)
	}

	if !exists {
		// User нет. Проверяем, был ли уже erased ранее.
		// Проверка в той же tx чтобы linearize c concurrent erase.
		var alreadyErased bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM user_erasure_runs WHERE target_user_id = $1)`,
			targetUserID).Scan(&alreadyErased); err != nil {
			return nil, fmt.Errorf("erasure: check prior run: %w", err)
		}
		// Transaction ничего не меняла — можно просто rollback.
		if alreadyErased {
			return &ErasureResult{UserID: targetUserID, Status: ErasureAlreadyErased}, nil
		}
		return &ErasureResult{UserID: targetUserID, Status: ErasureNotFound}, nil
	}

	// 2. Scrub audit_logs: user_id → NULL + bodies/shadow/pii_types → NULL.
	rowsScrubbed, err := s.auditScrub.ScrubUserDataTx(ctx, tx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("erasure: scrub audit: %w", err)
	}

	// 3. Delete budgets.
	budgetsDeleted, err := s.budgetDel.DeleteByUserIDTx(ctx, tx, targetUserID)
	if err != nil {
		return nil, fmt.Errorf("erasure: delete budget: %w", err)
	}

	// 4. Delete user row. FK audit_logs(user_id) устанавливает nil
	// благодаря шагу 2 — ON DELETE не требует changes schema.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM users WHERE id = $1`, targetUserID); err != nil {
		return nil, fmt.Errorf("erasure: delete user: %w", err)
	}

	// 5. Record erasure run. Pass actor as NULL если actor сам себя
	// удаляет (edge case — self-erase админом).
	var actorRef any
	if actorUserID != "" && actorUserID != targetUserID {
		actorRef = actorUserID
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_erasure_runs
		 (target_user_id, initiated_by_user_id, audit_rows_scrubbed, budgets_deleted)
		 VALUES ($1, $2, $3, $4)`,
		targetUserID, actorRef, rowsScrubbed, budgetsDeleted); err != nil {
		return nil, fmt.Errorf("erasure: record run: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("erasure: commit: %w", err)
	}

	return &ErasureResult{
		UserID:            targetUserID,
		Status:            ErasureCompleted,
		AuditRowsScrubbed: rowsScrubbed,
		BudgetsDeleted:    budgetsDeleted,
	}, nil
}

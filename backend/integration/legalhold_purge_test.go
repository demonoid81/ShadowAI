//go:build enterprise && integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/legalhold"
)

// TestCoord_HoldBeforePurge_RowsProtected — PR-L3 guarantee case A:
// apply_hold commit раньше purge commit → rows user'а под hold'ом
// ДОЛЖНЫ остаться даже если старше cutoff'а.
//
// Sequential timing (sufficient для доказательства: advisory lock
// serialize concurrent case тоже, но sequential детерминистичен
// и достаточен для контракта).
func TestCoord_HoldBeforePurge_RowsProtected(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "held@example.com")
	// Audit row старше cutoff'а — должен быть eligible для purge
	// (но защищён hold'ом).
	auditID := insertAuditLog(t, db, userID, time.Now().Add(-48*time.Hour))

	// 1. apply_hold FIRST → commit.
	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "LEG-A",
		Reason:       "testing hold-before-purge",
	})
	if err != nil {
		t.Fatalf("apply_hold: %v", err)
	}
	if !hold.IsActive {
		t.Fatal("hold not active")
	}

	// 2. purge SECOND.
	aRepo := audit.NewRepository(db)
	cutoff := time.Now().Add(-24 * time.Hour)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}

	// Expectation: deleted=0 (row защищён hold'ом), audit_log всё
	// ещё в БД.
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 (row защищён hold'ом)", deleted)
	}
	if !auditLogExists(t, db, auditID) {
		t.Error("audit_log удалён, хотя user под active hold")
	}

	// RecordRun тоже должен быть записан (purge произошёл, просто
	// ничего не нашёл).
	var runCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_purge_runs WHERE target = 'audit_logs'`).
		Scan(&runCount); err != nil {
		t.Fatalf("count runs: %v", err)
	}
	if runCount != 1 {
		t.Errorf("audit_purge_runs count = %d, want 1 (coordinated purge должен писать run даже при 0 rows)", runCount)
	}
}

// TestCoord_PurgeBeforeHold_RowsDeleted — PR-L3 guarantee case B:
// purge commit раньше apply_hold commit → удаление допустимо.
// Hold, applied ПОСЛЕ purge, не защитит rows — они уже удалены.
func TestCoord_PurgeBeforeHold_RowsDeleted(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "late-hold@example.com")
	auditID := insertAuditLog(t, db, userID, time.Now().Add(-48*time.Hour))

	// 1. purge FIRST — hold ещё не существует → row delete-eligible.
	aRepo := audit.NewRepository(db)
	cutoff := time.Now().Add(-24 * time.Hour)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
	if auditLogExists(t, db, auditID) {
		t.Error("audit_log не удалён на purge-first path")
	}

	// 2. apply_hold LATE — должен пройти normally (user существует).
	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "LEG-B",
		Reason:       "testing purge-before-hold",
	})
	if err != nil {
		t.Fatalf("apply_hold after purge: %v", err)
	}
	if !hold.IsActive {
		t.Fatal("hold not active после apply")
	}

	// Row уже удалён — это допустимо по контракту PR-L3.
	if auditLogExists(t, db, auditID) {
		t.Error("audit_log существует после purge — несогласованность")
	}
}

// TestCoord_MixedUsers — regression: purge удаляет только rows
// тех users'ов, у которых НЕТ active hold'а. rows пользователей
// под hold'ом остаются нетронутыми в том же purge-tick'е.
func TestCoord_MixedUsers(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	heldUserID := insertTestUser(t, db, "held-mix@example.com")
	freeUserID := insertTestUser(t, db, "free-mix@example.com")

	oldTS := time.Now().Add(-48 * time.Hour)
	heldAuditID := insertAuditLog(t, db, heldUserID, oldTS)
	freeAuditID := insertAuditLog(t, db, freeUserID, oldTS)

	// apply_hold на held-user.
	hRepo := legalhold.NewPGRepository(db)
	if _, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: heldUserID,
		CaseRef:      "MIX-1",
		Reason:       "mixed test",
	}); err != nil {
		t.Fatalf("apply_hold: %v", err)
	}

	// purge.
	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx,
		time.Now().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (только free-user's row)", deleted)
	}
	if !auditLogExists(t, db, heldAuditID) {
		t.Error("held-user audit удалён — lock не сработал")
	}
	if auditLogExists(t, db, freeAuditID) {
		t.Error("free-user audit не удалён — over-protection")
	}
}

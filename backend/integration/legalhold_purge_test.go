//go:build enterprise && integration

package integration

import (
	"context"
	"database/sql"
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
	// PR-L2.3: Create делает pending — нужен approve другим admin'ом
	// чтобы получить active. approverID (non-empty "admin-approver")
	// != createdBy (nil в этом теста — см. Hold struct без CreatedBy),
	// поэтому 4-eyes check пропускает.
	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "LEG-A",
		Reason:       "testing hold-before-purge",
	})
	if err != nil {
		t.Fatalf("apply_hold: %v", err)
	}
	approverID := insertTestUser(t, db, "approver-a@example.com")
	approved, err := hRepo.Approve(ctx, hold.ID, approverID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !approved.IsActive {
		t.Fatal("hold not active after approve")
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
	// PR-L2.3: Create делает pending; approve делает active.
	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "LEG-B",
		Reason:       "testing purge-before-hold",
	})
	if err != nil {
		t.Fatalf("apply_hold after purge: %v", err)
	}
	approverID := insertTestUser(t, db, "approver-b@example.com")
	approved, err := hRepo.Approve(ctx, hold.ID, approverID)
	if err != nil {
		t.Fatalf("approve after purge: %v", err)
	}
	if !approved.IsActive {
		t.Fatal("hold not active после apply+approve")
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

	// apply_hold на held-user + approve (L2.3 pending→active).
	hRepo := legalhold.NewPGRepository(db)
	heldHold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: heldUserID,
		CaseRef:      "MIX-1",
		Reason:       "mixed test",
	})
	if err != nil {
		t.Fatalf("apply_hold: %v", err)
	}
	approverID := insertTestUser(t, db, "approver-mix@example.com")
	if _, err := hRepo.Approve(ctx, heldHold.ID, approverID); err != nil {
		t.Fatalf("approve: %v", err)
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

func TestCoord_DateRangeHold_ProtectsOnlyRowsInsideRange(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "date-range@example.com")
	from := time.Now().UTC().Add(-72 * time.Hour)
	to := time.Now().UTC().Add(-36 * time.Hour)
	insideID := insertAuditLog(t, db, userID, from.Add(12*time.Hour))
	outsideID := insertAuditLog(t, db, userID, from.Add(-12*time.Hour))

	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID:  userID,
		CaseRef:       "DATE-1",
		Reason:        "date range purge protection",
		ScopeType:     legalhold.ScopeDateRange,
		ScopeDateFrom: &from,
		ScopeDateTo:   &to,
	})
	if err != nil {
		t.Fatalf("create date-range hold: %v", err)
	}
	approverID := insertTestUser(t, db, "approver-date@example.com")
	if _, err := hRepo.Approve(ctx, hold.ID, approverID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, time.Now().UTC().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1 row вне date-range", deleted)
	}
	if !auditLogExists(t, db, insideID) {
		t.Error("audit row внутри date-range был удалён")
	}
	if auditLogExists(t, db, outsideID) {
		t.Error("audit row вне date-range не был удалён")
	}
}

// TestCoord_PendingHold_DoesNotProtect — PR-L2.3 regression guard:
// pending hold (без approve) НЕ защищает audit от purge. Только
// status='active' участвует в purge-protection. Этот контракт
// критичен: creator не может protect'ить audit в обход 4-eyes.
func TestCoord_PendingHold_DoesNotProtect(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "pending-only@example.com")
	auditID := insertAuditLog(t, db, userID, time.Now().Add(-48*time.Hour))

	// Create pending — НЕ approve.
	hRepo := legalhold.NewPGRepository(db)
	if _, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "PEND-1",
		Reason:       "pending without approve",
	}); err != nil {
		t.Fatalf("create pending: %v", err)
	}

	// Purge должен удалить row несмотря на существующий pending.
	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx,
		time.Now().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (pending НЕ защищает)", deleted)
	}
	if auditLogExists(t, db, auditID) {
		t.Error("pending hold защитил audit — L2.3 contract нарушен")
	}
}

// TestCoord_ApprovedThenReleased_NoLongerProtects — L2.3: approve
// → active → release → released transition. После release pending
// hold не должен continue защищать (released — terminal state).
func TestCoord_ApprovedThenReleased_NoLongerProtects(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "released-mix@example.com")
	auditID := insertAuditLog(t, db, userID, time.Now().Add(-48*time.Hour))

	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "REL-1",
		Reason:       "approve then release",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	approverID := insertTestUser(t, db, "approver-rel@example.com")
	if _, err := hRepo.Approve(ctx, hold.ID, approverID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := hRepo.Release(ctx, hold.ID, approverID); err != nil {
		t.Fatalf("request release: %v", err)
	}
	releaseApproverID := insertTestUser(t, db, "release-approver-rel@example.com")
	if _, err := hRepo.ApproveRelease(ctx, hold.ID, releaseApproverID); err != nil {
		t.Fatalf("approve release: %v", err)
	}

	// Released hold → purge удаляет row.
	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx,
		time.Now().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1 (released hold не должен защищать)", deleted)
	}
	if auditLogExists(t, db, auditID) {
		t.Error("released hold продолжает защищать audit")
	}
}

func TestCoord_ReleasePendingStillProtects(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "release-pending-protects@example.com")
	auditID := insertAuditLog(t, db, userID, time.Now().Add(-48*time.Hour))

	hRepo := legalhold.NewPGRepository(db)
	hold, err := hRepo.Create(ctx, &legalhold.Hold{
		TargetUserID: userID,
		CaseRef:      "REL-PEND-1",
		Reason:       "release pending protects",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	approverID := insertTestUser(t, db, "approver-rel-pend@example.com")
	if _, err := hRepo.Approve(ctx, hold.ID, approverID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := hRepo.Release(ctx, hold.ID, approverID); err != nil {
		t.Fatalf("request release: %v", err)
	}

	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, time.Now().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted = %d, want 0 для release_pending hold", deleted)
	}
	if !auditLogExists(t, db, auditID) {
		t.Error("release_pending hold не защитил audit row")
	}
}

func TestCoord_QueryScopeHold_ProtectsOnlyMatchingRows(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "query-scope@example.com")
	oldTS := time.Now().UTC().Add(-48 * time.Hour)
	matchingID := insertAuditLogWithFields(t, db, userID, oldTS, "openai", "blocked")
	outsideID := insertAuditLogWithFields(t, db, userID, oldTS, "anthropic", "allowed")

	hold := createQueryScopeHold(t, ctx, db, userID, `{
		"v":1,
		"all":[
			{"field":"provider","op":"eq","value":"openai"},
			{"field":"policy_action","op":"eq","value":"blocked"}
		]
	}`)
	approveHold(t, ctx, db, hold.ID, "approver-query@example.com")

	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, time.Now().UTC().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1 row outside query_scope", deleted)
	}
	if !auditLogExists(t, db, matchingID) {
		t.Error("matching query_scope row was purged")
	}
	if auditLogExists(t, db, outsideID) {
		t.Error("outside query_scope row was not purged")
	}
}

func TestCoord_QueryScopeReleasePending_StillProtectsMatchingRows(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "query-release-pending@example.com")
	oldTS := time.Now().UTC().Add(-48 * time.Hour)
	matchingID := insertAuditLogWithFields(t, db, userID, oldTS, "openai", "blocked")
	outsideID := insertAuditLogWithFields(t, db, userID, oldTS, "openai", "allowed")

	hold := createQueryScopeHold(t, ctx, db, userID, `{
		"v":1,
		"field":"policy_action",
		"op":"eq",
		"value":"blocked"
	}`)
	approverID := approveHold(t, ctx, db, hold.ID, "approver-query-release@example.com")
	hRepo := legalhold.NewPGRepository(db)
	if _, err := hRepo.Release(ctx, hold.ID, approverID); err != nil {
		t.Fatalf("request release: %v", err)
	}

	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, time.Now().UTC().Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1 row outside query_scope", deleted)
	}
	if !auditLogExists(t, db, matchingID) {
		t.Error("release_pending query_scope did not protect matching row")
	}
	if auditLogExists(t, db, outsideID) {
		t.Error("outside query_scope row was not purged")
	}
}

func TestCoord_QueryScopeInvalidStoredSelector_AbortsPurge(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	userID := insertTestUser(t, db, "query-invalid@example.com")
	oldTS := time.Now().UTC().Add(-48 * time.Hour)
	matchingID := insertAuditLogWithFields(t, db, userID, oldTS, "openai", "blocked")
	outsideID := insertAuditLogWithFields(t, db, userID, oldTS, "anthropic", "allowed")

	hold := createQueryScopeHold(t, ctx, db, userID, `{
		"v":1,
		"field":"provider",
		"op":"eq",
		"value":"openai"
	}`)
	approveHold(t, ctx, db, hold.ID, "approver-query-invalid@example.com")

	if _, err := db.ExecContext(ctx,
		`UPDATE legal_holds
		    SET scope_query_json = '{"v":1,"field":"user_id","op":"eq","value":"other-user"}'::jsonb
		  WHERE id = $1`, hold.ID); err != nil {
		t.Fatalf("corrupt stored selector: %v", err)
	}

	aRepo := audit.NewRepository(db)
	deleted, err := aRepo.PurgeOlderThanRespectingHoldsAndRecordRun(ctx, time.Now().UTC().Add(-24*time.Hour), 100)
	if err == nil {
		t.Fatal("purge err = nil, want invalid stored selector error")
	}
	if deleted != 0 {
		t.Fatalf("deleted = %d, want 0 on fail-closed selector compile", deleted)
	}
	if !auditLogExists(t, db, matchingID) || !auditLogExists(t, db, outsideID) {
		t.Fatal("purge deleted rows despite invalid stored selector")
	}
	assertAdminEventExists(t, db, "legal_hold_query_scope_compile_failed", hold.ID)
}

func insertAuditLogWithFields(t *testing.T, db *sql.DB, userID string, createdAt time.Time, provider, policyAction string) string {
	t.Helper()
	id := insertAuditLog(t, db, userID, createdAt)
	if _, err := db.Exec(
		`UPDATE audit_logs SET provider = $2, policy_action = $3 WHERE id = $1`,
		id, provider, policyAction); err != nil {
		t.Fatalf("update audit_log fields: %v", err)
	}
	return id
}

func createQueryScopeHold(t *testing.T, ctx context.Context, db *sql.DB, userID, selector string) *legalhold.Hold {
	t.Helper()
	hRepo := legalhold.NewPGRepository(db)
	svc := legalhold.NewService(hRepo)
	hold, _, err := svc.CreateQueryScopedHoldInOrg(
		ctx, userID, "QUERY-SCOPE", "query scope purge protection", "", "", []byte(selector),
	)
	if err != nil {
		t.Fatalf("create query_scope hold: %v", err)
	}
	return hold
}

func approveHold(t *testing.T, ctx context.Context, db *sql.DB, holdID, approverEmail string) string {
	t.Helper()
	approverID := insertTestUser(t, db, approverEmail)
	hRepo := legalhold.NewPGRepository(db)
	if _, err := hRepo.Approve(ctx, holdID, approverID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	return approverID
}

func assertAdminEventExists(t *testing.T, db *sql.DB, action, targetID string) {
	t.Helper()
	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS(
		    SELECT 1 FROM admin_event_logs
		     WHERE action = $1 AND target_id = $2 AND success = false
		)`, action, targetID).Scan(&exists); err != nil {
		t.Fatalf("query admin event: %v", err)
	}
	if !exists {
		t.Fatalf("admin event %s for target %s not found", action, targetID)
	}
}

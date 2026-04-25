//go:build enterprise && integration

package integration

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/shadowai/backend/internal/adminaudit"
	"github.com/shadowai/backend/internal/audit"
	"github.com/shadowai/backend/internal/domain"
	_ "github.com/lib/pq"
)

// TestPurgeAndRecord_TrueAtomic_RollbackOnRecordFailure — W2.5 acceptance
// criterion #3: если recordPurgeRunChained падает, DELETE не коммитится.
//
// Симулируем: audit.Repository.PurgeAndRecord с нарочно поломанным
// chainSecret (неправильный secret → advisory lock упадёт, или record INSERT
// упадёт). Но проще: используем adminaudit.PurgeAndRecord с recordFn, который
// возвращает error, и проверяем, что admin_event_logs строки не удалены.
func TestPurgeAndRecord_TrueAtomic_RollbackOnRecordFailure(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	// Вставляем старые admin_event_logs строки для purge.
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	insertAdminEvent(t, db, oldTime)
	insertAdminEvent(t, db, oldTime)
	insertAdminEvent(t, db, oldTime)

	// Verify we have 3 rows before purge.
	n := countAdminEvents(t, db)
	if n != 3 {
		t.Fatalf("pre-purge admin_event_logs = %d, want 3", n)
	}

	adminRepo := adminaudit.NewRepository(db)
	cutoff := time.Now().UTC()
	boom := errors.New("simulated record failure")

	// recordFn that always returns error.
	_, err := adminRepo.PurgeAndRecord(ctx, cutoff, 100, func(c context.Context, tx *sql.Tx, total int) error {
		return boom
	})
	if err == nil {
		t.Fatal("PurgeAndRecord should have returned error")
	}

	// Rows must NOT have been deleted — tx was rolled back.
	n = countAdminEvents(t, db)
	if n != 3 {
		t.Errorf("after failed PurgeAndRecord, admin_event_logs = %d, want 3 (tx must have rolled back)", n)
	}

	// audit_purge_runs must be empty.
	var purgeRunCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_purge_runs`).Scan(&purgeRunCount)
	if purgeRunCount != 0 {
		t.Errorf("audit_purge_runs = %d, want 0 (no evidence without successful delete)", purgeRunCount)
	}
}

// TestPurgeAndRecord_TrueAtomic_SuccessCase — W2.5 acceptance criterion:
// на успешном пути rows удалены и evidence row появилась в той же tx.
func TestPurgeAndRecord_TrueAtomic_SuccessCase(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	const chainSecret = "audit-chain-secret-test-32chars!!"
	auditRepo := audit.NewRepository(db).WithChainSecret(chainSecret)

	// Вставляем старые audit_logs.
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	insertAuditLog(t, db, insertTestUser(t, db, "u@test.com"), oldTime)
	insertAuditLog(t, db, insertTestUser(t, db, "v@test.com"), oldTime)

	n := countAuditLogs(t, db)
	if n != 2 {
		t.Fatalf("pre-purge audit_logs = %d, want 2", n)
	}

	cutoff := time.Now().UTC()
	deleted, err := auditRepo.PurgeAndRecord(ctx, cutoff, 100, audit.PurgeTargetAuditLogs, "", "global")
	if err != nil {
		t.Fatalf("PurgeAndRecord err: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}

	// Rows должны быть удалены.
	n = countAuditLogs(t, db)
	if n != 0 {
		t.Errorf("post-purge audit_logs = %d, want 0", n)
	}

	// Evidence row должна существовать.
	var purgeRunCount int
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_purge_runs WHERE rows_deleted = $1`, 2).Scan(&purgeRunCount)
	if purgeRunCount != 1 {
		t.Errorf("audit_purge_runs with rows_deleted=2: count=%d, want 1", purgeRunCount)
	}
}

// TestAdminPurgeAndRecord_TrueAtomic_RollbackOnRecordFailure — симметричный
// тест для adminaudit.PurgeAndRecord: record failure → rows не удалены.
func TestAdminPurgeAndRecord_TrueAtomic_RollbackOnRecordFailure(t *testing.T) {
	db, teardown := startPostgres(t)
	defer teardown()
	applyAllMigrations(t, db)

	ctx := context.Background()
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	insertAdminEvent(t, db, oldTime)
	insertAdminEvent(t, db, oldTime)

	n := countAdminEvents(t, db)
	if n != 2 {
		t.Fatalf("pre-purge = %d, want 2", n)
	}

	adminRepo := adminaudit.NewRepository(db)
	cutoff := time.Now().UTC()
	_, err := adminRepo.PurgeAndRecord(ctx, cutoff, 100, func(c context.Context, tx *sql.Tx, total int) error {
		return errors.New("record fail")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	n = countAdminEvents(t, db)
	if n != 2 {
		t.Errorf("after failed record, admin_event_logs = %d, want 2 (rollback)", n)
	}
}

// Helpers

func insertAdminEvent(t *testing.T, db *sql.DB, createdAt time.Time) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO admin_event_logs (actor_user_id, action, resource, path, method, status_code, success, created_at)
		 VALUES (NULL, 'test', 'test', '/test', 'GET', 200, true, $1)`, createdAt)
	if err != nil {
		t.Fatalf("insertAdminEvent: %v", err)
	}
}

func countAdminEvents(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_event_logs`).Scan(&n)
	return n
}

func countAuditLogs(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	db.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_logs`).Scan(&n)
	return n
}

// domainHelper to satisfy audit.NewRepository usage
var _ = domain.AuditLog{}

//go:build enterprise && integration

// Package integration — PR-L4 targeted Postgres concurrency harness.
// НЕ общий integration framework для всего проекта — только для
// proof of PR-L3 commit-order guarantee между
// legalhold.PGRepository.Create и
// audit.Repository.PurgeOlderThanRespectingHoldsAndRecordRun.
//
// Requirements: Docker daemon для testcontainers-go.
//
// Запуск:
//
//	cd backend && go test -tags 'enterprise integration' ./integration -count=1
//
// Обычный `go test ./...` эти файлы не компилирует (build tag
// excludes) и не требует Docker.

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// startPostgres поднимает postgres:16-alpine контейнер и возвращает
// *sql.DB + teardown func. Ошибка помечает тест как skipped, если
// Docker недоступен (environment без Docker не должен падать —
// CI without Docker просто пропустит integration suite).
func startPostgres(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("shadowai_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Skipf("testcontainers postgres unavailable (Docker?): %v", err)
	}

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("container dsn: %v", err)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("sql.Open: %v", err)
	}
	db.SetMaxOpenConns(10)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("ping: %v", err)
	}
	teardown := func() {
		db.Close()
		_ = pgContainer.Terminate(ctx)
	}
	return db, teardown
}

// applyAllMigrations прогоняет core (migrations/) + enterprise
// (migrations-enterprise/) SQL-файлы в lex order по имени. PR-L4
// scope — proof of coordination, поэтому применяем весь набор
// (009-014 нужны).
func applyAllMigrations(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// Путь к migrations относительно backend/ — тесты запускаются
	// из backend/integration/, поднимаемся на уровень.
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	dirs := []string{
		filepath.Join(repoRoot, "migrations"),
		filepath.Join(repoRoot, "migrations-enterprise"),
	}
	var files []string
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatalf("readdir %s: %v", d, err)
		}
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".sql" {
				continue
			}
			files = append(files, filepath.Join(d, e.Name()))
		}
	}
	// Files sorted by basename globally: 001_*.sql, ..., 014_*.sql.
	sort.Slice(files, func(i, j int) bool {
		return filepath.Base(files[i]) < filepath.Base(files[j])
	})

	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := db.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", filepath.Base(f), err)
		}
	}
}

// insertTestUser создаёт запись в users. Возвращает UUID.
func insertTestUser(t *testing.T, db *sql.DB, email string) string {
	t.Helper()
	var id string
	apiKey := "k-" + email
	err := db.QueryRow(
		`INSERT INTO users (email, password, role, api_key, is_active)
		 VALUES ($1, 'x', 'user', $2, true) RETURNING id`,
		email, apiKey).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

// insertAuditLog создаёт запись audit_logs с заданным created_at.
// user_id — FK; ставим НЕ NULL для проверки hold-защиты.
func insertAuditLog(t *testing.T, db *sql.DB, userID string, createdAt time.Time) string {
	t.Helper()
	var id string
	err := db.QueryRow(
		`INSERT INTO audit_logs (user_id, endpoint, status_code, created_at)
		 VALUES ($1, '/test', 200, $2) RETURNING id`,
		userID, createdAt).Scan(&id)
	if err != nil {
		t.Fatalf("insert audit_log: %v", err)
	}
	return id
}

// auditLogExists — helper для assertion.
func auditLogExists(t *testing.T, db *sql.DB, id string) bool {
	t.Helper()
	var exists bool
	err := db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM audit_logs WHERE id = $1)`, id).Scan(&exists)
	if err != nil {
		t.Fatalf("exists: %v", err)
	}
	return exists
}

// — guard: отсутствие unused error в некоторых build-конфигах.
var _ = fmt.Sprintf

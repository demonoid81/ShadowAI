// cmd/migrate — idempotent SQL migration runner for ShadowAI.
//
// Reads *.sql files from a directory in lexicographic order and applies each
// once, tracked by a schema_migrations table. Safe to run as a Kubernetes
// init container or pre-upgrade Job.
//
// Usage:
//
//	migrate [--dir /migrations] [--enterprise-dir /migrations-enterprise]
//
// Environment:
//
//	DATABASE_URL — required Postgres DSN
//
// Exit codes:
//
//	0 — all pending migrations applied (or already applied)
//	1 — migration failure
//	2 — configuration error
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/lib/pq"
)

func main() {
	coreDir := flag.String("dir", "/migrations", "Directory of core SQL migration files")
	entDir := flag.String("enterprise-dir", "", "Directory of enterprise SQL migration files (optional)")
	flag.Parse()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "DATABASE_URL is required")
		os.Exit(2)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db open: %v\n", err)
		os.Exit(2)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "db ping: %v\n", err)
		os.Exit(1)
	}

	if err := ensureMigrationsTable(db); err != nil {
		fmt.Fprintf(os.Stderr, "init migrations table: %v\n", err)
		os.Exit(1)
	}

	dirs := []string{*coreDir}
	if *entDir != "" {
		dirs = append(dirs, *entDir)
	}

	for _, dir := range dirs {
		if err := runDir(db, dir); err != nil {
			fmt.Fprintf(os.Stderr, "migrate %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
	log.Println("migrate: all migrations applied")
}

func ensureMigrationsTable(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version     VARCHAR(255) PRIMARY KEY,
		applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	return err
}

func runDir(db *sql.DB, dir string) error {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil // optional enterprise dir may not exist in core builds
	}
	if err != nil {
		return fmt.Errorf("read dir %s: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, f := range files {
		version := filepath.Base(f)
		applied, err := isApplied(db, version)
		if err != nil {
			return fmt.Errorf("check %s: %w", version, err)
		}
		if applied {
			log.Printf("migrate: skip %s (already applied)", version)
			continue
		}
		if err := applyFile(db, filepath.Join(dir, f), version); err != nil {
			return fmt.Errorf("apply %s: %w", version, err)
		}
		log.Printf("migrate: applied %s", version)
	}
	return nil
}

func isApplied(db *sql.DB, version string) (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version=$1`, version).Scan(&count)
	return count > 0, err
}

func applyFile(db *sql.DB, path, version string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(string(content)); err != nil {
		return fmt.Errorf("exec SQL: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return tx.Commit()
}

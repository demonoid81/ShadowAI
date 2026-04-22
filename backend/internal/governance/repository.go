//go:build enterprise

// Enterprise Component (see ENTERPRISE.md / LICENSE.enterprise).
// Compiled only under -tags enterprise.

package governance

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// PGRepository — production реализация Repository поверх PostgreSQL.
// Рассчитано на singleton-модель (phase 1): ровно одна is_active=true
// строка в provider_governance_policies.
type PGRepository struct {
	db *sql.DB
}

// NewPGRepository. Если db=nil, возвращает nil-pointer; service
// правильно деградирует к CodeGovernanceDisabled.
func NewPGRepository(db *sql.DB) *PGRepository {
	return &PGRepository{db: db}
}

// GetActive читает current active политику. Если строки нет вовсе
// (не было миграции / seed удалён) — возвращает (nil, nil). Это
// штатное "governance не сконфигурирован".
func (r *PGRepository) GetActive(ctx context.Context) (*Policy, error) {
	if r == nil || r.db == nil {
		return nil, nil
	}
	const q = `SELECT id, name, mode, rules_json, role_rules_json,
	           updated_at, updated_by, is_active
	           FROM provider_governance_policies
	           WHERE is_active = true
	           ORDER BY updated_at DESC
	           LIMIT 1`
	var (
		p             Policy
		rulesJSON     []byte
		roleRulesJSON []byte
		updatedBy     sql.NullString
	)
	err := r.db.QueryRowContext(ctx, q).Scan(
		&p.ID, &p.Name, &p.Mode, &rulesJSON, &roleRulesJSON,
		&p.UpdatedAt, &updatedBy, &p.IsActive,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("governance: get active: %w", err)
	}
	if updatedBy.Valid {
		s := updatedBy.String
		p.UpdatedBy = &s
	}
	if len(rulesJSON) > 0 {
		if err := json.Unmarshal(rulesJSON, &p.Rules); err != nil {
			// Corrupted JSON в БД — fail-closed для compliance.
			// Лучше отказать в запросах, чем пропустить по пустому
			// allowlist.
			return nil, fmt.Errorf("governance: rules_json corrupt: %w", err)
		}
	}
	if len(roleRulesJSON) > 0 {
		if err := json.Unmarshal(roleRulesJSON, &p.RoleRules); err != nil {
			return nil, fmt.Errorf("governance: role_rules_json corrupt: %w", err)
		}
	}
	return &p, nil
}

// Upsert перезаписывает активную политику. Для singleton-модели:
// если active уже есть — UPDATE; если нет — INSERT. Actor пустой
// для CLI/системных операций.
//
// Полезная инвариант: after Upsert ровно одна is_active строка.
// В phase 1 мы НЕ переводим старую в is_active=false — просто
// перезаписываем single row. В PR-G2 появится history (supersede-
// chain через inactive rows).
func (r *PGRepository) Upsert(ctx context.Context, p *Policy, actor string) (*Policy, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("governance: repository not configured")
	}
	if p == nil {
		return nil, fmt.Errorf("governance: nil policy")
	}
	if !p.Mode.IsValid() {
		return nil, fmt.Errorf("governance: invalid mode %q", p.Mode)
	}
	rules := p.Rules
	if rules == nil {
		rules = []ProviderRule{}
	}
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return nil, fmt.Errorf("governance: marshal rules: %w", err)
	}
	roleRules := p.RoleRules
	if roleRules == nil {
		roleRules = []RoleRule{}
	}
	roleRulesJSON, err := json.Marshal(roleRules)
	if err != nil {
		return nil, fmt.Errorf("governance: marshal role_rules: %w", err)
	}
	name := p.Name
	if name == "" {
		name = "default"
	}
	var actorArg any
	if actor != "" {
		actorArg = actor
	} else {
		actorArg = nil
	}

	// Ищем existing active. Если есть — UPDATE; если нет — INSERT.
	var existingID string
	err = r.db.QueryRowContext(ctx,
		`SELECT id FROM provider_governance_policies WHERE is_active = true LIMIT 1`,
	).Scan(&existingID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		const ins = `INSERT INTO provider_governance_policies
		    (name, mode, rules_json, role_rules_json, updated_at, updated_by, is_active)
		    VALUES ($1, $2, $3, $4, now(), $5, true)
		    RETURNING id, updated_at`
		var newID string
		var updAt time.Time
		if err := r.db.QueryRowContext(ctx, ins,
			name, string(p.Mode), rulesJSON, roleRulesJSON, actorArg,
		).Scan(&newID, &updAt); err != nil {
			return nil, fmt.Errorf("governance: insert: %w", err)
		}
		p.ID = newID
		p.Name = name
		p.Rules = rules
		p.RoleRules = roleRules
		p.UpdatedAt = updAt
		p.IsActive = true
		if actor != "" {
			a := actor
			p.UpdatedBy = &a
		}
		return p, nil
	case err == nil:
		const upd = `UPDATE provider_governance_policies
		    SET name = $1, mode = $2, rules_json = $3, role_rules_json = $4,
		        updated_at = now(), updated_by = $5
		    WHERE id = $6
		    RETURNING updated_at`
		var updAt time.Time
		if err := r.db.QueryRowContext(ctx, upd,
			name, string(p.Mode), rulesJSON, roleRulesJSON, actorArg, existingID,
		).Scan(&updAt); err != nil {
			return nil, fmt.Errorf("governance: update: %w", err)
		}
		p.ID = existingID
		p.Name = name
		p.Rules = rules
		p.RoleRules = roleRules
		p.UpdatedAt = updAt
		p.IsActive = true
		if actor != "" {
			a := actor
			p.UpdatedBy = &a
		}
		return p, nil
	default:
		return nil, fmt.Errorf("governance: check active: %w", err)
	}
}

package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/shadowai/backend/internal/domain"
)

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) List(ctx context.Context) ([]domain.PolicyRule, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, rule_type, config, is_active, priority FROM policy_rules ORDER BY priority ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []domain.PolicyRule
	for rows.Next() {
		var p domain.PolicyRule
		var configJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.RuleType, &configJSON, &p.IsActive, &p.Priority); err != nil {
			return nil, err
		}
		json.Unmarshal(configJSON, &p.Config)
		rules = append(rules, p)
	}
	return rules, nil
}

func (r *Repository) Create(ctx context.Context, p *domain.PolicyRule) error {
	configJSON, _ := json.Marshal(p.Config)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO policy_rules (id, name, rule_type, config, is_active, priority) VALUES ($1,$2,$3,$4,$5,$6)`,
		p.ID, p.Name, p.RuleType, configJSON, p.IsActive, p.Priority)
	return err
}

func (r *Repository) Update(ctx context.Context, p *domain.PolicyRule) error {
	configJSON, _ := json.Marshal(p.Config)
	_, err := r.db.ExecContext(ctx,
		`UPDATE policy_rules SET name=$1, rule_type=$2, config=$3, is_active=$4, priority=$5 WHERE id=$6`,
		p.Name, p.RuleType, configJSON, p.IsActive, p.Priority, p.ID)
	return err
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM policy_rules WHERE id=$1`, id)
	return err
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.PolicyRule, error) {
	var p domain.PolicyRule
	var configJSON []byte
	err := r.db.QueryRowContext(ctx, `SELECT id, name, rule_type, config, is_active, priority FROM policy_rules WHERE id=$1`, id).
		Scan(&p.ID, &p.Name, &p.RuleType, &configJSON, &p.IsActive, &p.Priority)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(configJSON, &p.Config)
	return &p, nil
}

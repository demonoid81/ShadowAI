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

func (r *Repository) List(ctx context.Context, orgID string) ([]domain.PolicyRule, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if orgID != "" {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, name, rule_type, config, is_active, priority, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
			 FROM policy_rules WHERE org_id = $1 ORDER BY priority ASC`, orgID)
	} else {
		rows, err = r.db.QueryContext(ctx,
			`SELECT id, name, rule_type, config, is_active, priority, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
			 FROM policy_rules ORDER BY priority ASC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []domain.PolicyRule
	for rows.Next() {
		var p domain.PolicyRule
		var configJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.RuleType, &configJSON, &p.IsActive, &p.Priority, &p.OrgID); err != nil {
			return nil, err
		}
		json.Unmarshal(configJSON, &p.Config)
		rules = append(rules, p)
	}
	return rules, nil
}

func (r *Repository) Create(ctx context.Context, p *domain.PolicyRule) error {
	orgID := p.OrgID
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000001"
	}
	configJSON, _ := json.Marshal(p.Config)
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO policy_rules (id, name, rule_type, config, is_active, priority, org_id) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		p.ID, p.Name, p.RuleType, configJSON, p.IsActive, p.Priority, orgID)
	return err
}

func (r *Repository) Update(ctx context.Context, p *domain.PolicyRule) error {
	configJSON, _ := json.Marshal(p.Config)
	if p.OrgID != "" {
		_, err := r.db.ExecContext(ctx,
			`UPDATE policy_rules SET name=$1, rule_type=$2, config=$3, is_active=$4, priority=$5 WHERE id=$6 AND org_id=$7`,
			p.Name, p.RuleType, configJSON, p.IsActive, p.Priority, p.ID, p.OrgID)
		return err
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE policy_rules SET name=$1, rule_type=$2, config=$3, is_active=$4, priority=$5 WHERE id=$6`,
		p.Name, p.RuleType, configJSON, p.IsActive, p.Priority, p.ID)
	return err
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM policy_rules WHERE id=$1`, id)
	return err
}

// DeleteScoped deletes a policy rule with org ownership check.
func (r *Repository) DeleteScoped(ctx context.Context, id, orgID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM policy_rules WHERE id=$1 AND org_id=$2`, id, orgID)
	return err
}

func (r *Repository) GetByID(ctx context.Context, id string) (*domain.PolicyRule, error) {
	var p domain.PolicyRule
	var configJSON []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT id, name, rule_type, config, is_active, priority, COALESCE(org_id::text,'00000000-0000-0000-0000-000000000001')
		 FROM policy_rules WHERE id=$1`, id).
		Scan(&p.ID, &p.Name, &p.RuleType, &configJSON, &p.IsActive, &p.Priority, &p.OrgID)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(configJSON, &p.Config)
	return &p, nil
}

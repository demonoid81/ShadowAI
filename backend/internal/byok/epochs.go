package byok

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	EpochStatusPending  = "pending"
	EpochStatusActive   = "active"
	EpochStatusRetiring = "retiring"
	EpochStatusRetired  = "retired"
	EpochStatusRevoked  = "revoked"
	EpochStatusDisabled = "disabled"
)

var (
	ErrNoActiveEpoch  = errors.New("BYOK active DEK epoch not found")
	ErrUnknownEpoch   = errors.New("BYOK DEK epoch not found")
	ErrEpochNotUsable = errors.New("BYOK DEK epoch is not usable")
)

type Epoch struct {
	ID           string
	OrgID        string
	KID          string
	Provider     string
	ProviderKID  string
	Status       string
	CreatedAt    time.Time
	ActivatedAt  *time.Time
	RetiredAt    *time.Time
	RevokedAt    *time.Time
	DisabledAt   *time.Time
	CreatedBy    string
	MetadataJSON string
}

type EpochStore interface {
	ActiveEpoch(ctx context.Context, orgID string) (Epoch, error)
	EpochByKID(ctx context.Context, kid string) (Epoch, error)
}

type EpochOptions struct {
	RequireActive bool
}

type EpochEncryptor struct {
	inner Encryptor
	store EpochStore
	opts  EpochOptions
}

func NewEpochEncryptor(inner Encryptor, store EpochStore, opts EpochOptions) *EpochEncryptor {
	return &EpochEncryptor{inner: inner, store: store, opts: opts}
}

func (e *EpochEncryptor) EncryptField(ctx context.Context, orgID, field, plaintext string) (string, error) {
	if e == nil || e.inner == nil {
		return plaintext, nil
	}
	if e.store == nil {
		if e.opts.RequireActive {
			return "", ErrNoActiveEpoch
		}
		return e.inner.EncryptField(ctx, orgID, field, plaintext)
	}
	orgID = strings.TrimSpace(orgID)
	epoch, err := e.store.ActiveEpoch(ctx, orgID)
	if err != nil {
		if e.opts.RequireActive {
			return "", err
		}
		return e.inner.EncryptField(ctx, orgID, field, plaintext)
	}
	if !epochUsableForNewWrites(epoch.Status) {
		return "", fmt.Errorf("%w: status=%s", ErrEpochNotUsable, epoch.Status)
	}
	ciphertext, err := e.inner.EncryptField(ctx, orgID, field, plaintext)
	if err != nil {
		return "", err
	}
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		return "", err
	}
	env.ProviderKID = env.KID
	env.KID = epoch.KID
	env.OrgID = epoch.OrgID
	return EncodeEnvelope(env)
}

func (e *EpochEncryptor) DecryptField(ctx context.Context, ciphertext string) (string, error) {
	if e == nil || e.inner == nil {
		return ciphertext, nil
	}
	env, err := DecodeEnvelope(ciphertext)
	if err != nil {
		return "", err
	}
	if env.ProviderKID == "" || env.OrgID == "" {
		return e.inner.DecryptField(ctx, ciphertext)
	}
	if e.store == nil {
		return "", ErrUnknownEpoch
	}
	epoch, err := e.store.EpochByKID(ctx, env.KID)
	if err != nil {
		return "", err
	}
	if epoch.OrgID != env.OrgID {
		return "", fmt.Errorf("BYOK cross-tenant envelope rejected: envelope_org=%s epoch_org=%s", env.OrgID, epoch.OrgID)
	}
	if !epochUsableForDecrypt(epoch.Status) {
		return "", fmt.Errorf("%w: status=%s", ErrEpochNotUsable, epoch.Status)
	}
	env.KID = env.ProviderKID
	env.ProviderKID = ""
	legacy, err := EncodeEnvelope(env)
	if err != nil {
		return "", err
	}
	return e.inner.DecryptField(ctx, legacy)
}

func epochUsableForNewWrites(status string) bool {
	return status == EpochStatusActive
}

func epochUsableForDecrypt(status string) bool {
	switch status {
	case EpochStatusActive, EpochStatusRetiring, EpochStatusRetired:
		return true
	default:
		return false
	}
}

func validateEpochStatus(status string) error {
	switch status {
	case EpochStatusPending, EpochStatusActive, EpochStatusRetiring, EpochStatusRetired, EpochStatusRevoked, EpochStatusDisabled:
		return nil
	default:
		return fmt.Errorf("invalid BYOK epoch status %q", status)
	}
}

type EpochRepository struct {
	db *sql.DB
}

func NewEpochRepository(db *sql.DB) *EpochRepository {
	return &EpochRepository{db: db}
}

func (r *EpochRepository) ActiveEpoch(ctx context.Context, orgID string) (Epoch, error) {
	if r == nil || r.db == nil {
		return Epoch{}, ErrNoActiveEpoch
	}
	orgID = strings.TrimSpace(orgID)
	var e Epoch
	err := r.db.QueryRowContext(ctx, `SELECT id::text, org_id::text, kid, provider, provider_kid, status, created_at,
		activated_at, retired_at, revoked_at, disabled_at, COALESCE(created_by::text,''), COALESCE(metadata_json::text,'')
		FROM byok_key_epochs
		WHERE org_id = $1 AND status = 'active'
		ORDER BY activated_at DESC NULLS LAST, created_at DESC
		LIMIT 1`, orgID).Scan(
		&e.ID, &e.OrgID, &e.KID, &e.Provider, &e.ProviderKID, &e.Status, &e.CreatedAt,
		&e.ActivatedAt, &e.RetiredAt, &e.RevokedAt, &e.DisabledAt, &e.CreatedBy, &e.MetadataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Epoch{}, ErrNoActiveEpoch
	}
	if err != nil {
		return Epoch{}, fmt.Errorf("BYOK active epoch lookup: %w", err)
	}
	return e, nil
}

func (r *EpochRepository) EpochByKID(ctx context.Context, kid string) (Epoch, error) {
	if r == nil || r.db == nil {
		return Epoch{}, ErrUnknownEpoch
	}
	var e Epoch
	err := r.db.QueryRowContext(ctx, `SELECT id::text, org_id::text, kid, provider, provider_kid, status, created_at,
		activated_at, retired_at, revoked_at, disabled_at, COALESCE(created_by::text,''), COALESCE(metadata_json::text,'')
		FROM byok_key_epochs
		WHERE kid = $1`, strings.TrimSpace(kid)).Scan(
		&e.ID, &e.OrgID, &e.KID, &e.Provider, &e.ProviderKID, &e.Status, &e.CreatedAt,
		&e.ActivatedAt, &e.RetiredAt, &e.RevokedAt, &e.DisabledAt, &e.CreatedBy, &e.MetadataJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return Epoch{}, ErrUnknownEpoch
	}
	if err != nil {
		return Epoch{}, fmt.Errorf("BYOK epoch lookup: %w", err)
	}
	return e, nil
}

func (r *EpochRepository) ListEpochs(ctx context.Context, orgID string) ([]Epoch, error) {
	where := ""
	args := []any{}
	if strings.TrimSpace(orgID) != "" {
		where = "WHERE org_id = $1"
		args = append(args, strings.TrimSpace(orgID))
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id::text, org_id::text, kid, provider, provider_kid, status, created_at,
		activated_at, retired_at, revoked_at, disabled_at, COALESCE(created_by::text,''), COALESCE(metadata_json::text,'')
		FROM byok_key_epochs `+where+`
		ORDER BY org_id, created_at DESC`, args...)
	if err != nil {
		return nil, fmt.Errorf("BYOK list epochs: %w", err)
	}
	defer rows.Close()
	var out []Epoch
	for rows.Next() {
		var e Epoch
		if err := rows.Scan(&e.ID, &e.OrgID, &e.KID, &e.Provider, &e.ProviderKID, &e.Status, &e.CreatedAt,
			&e.ActivatedAt, &e.RetiredAt, &e.RevokedAt, &e.DisabledAt, &e.CreatedBy, &e.MetadataJSON); err != nil {
			return nil, fmt.Errorf("BYOK scan epoch: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("BYOK iterate epochs: %w", err)
	}
	return out, nil
}

func (r *EpochRepository) CreateEpoch(ctx context.Context, e Epoch) (Epoch, error) {
	if err := validateEpochStatus(e.Status); err != nil {
		return Epoch{}, err
	}
	if strings.TrimSpace(e.OrgID) == "" {
		return Epoch{}, errors.New("org_id is required")
	}
	if strings.TrimSpace(e.KID) == "" {
		return Epoch{}, errors.New("kid is required")
	}
	if strings.TrimSpace(e.Provider) == "" {
		return Epoch{}, errors.New("provider is required")
	}
	if strings.TrimSpace(e.ProviderKID) == "" {
		return Epoch{}, errors.New("provider_kid is required")
	}
	if strings.TrimSpace(e.MetadataJSON) == "" {
		e.MetadataJSON = "{}"
	}
	now := time.Now().UTC()
	var activatedAt any
	if e.Status == EpochStatusActive {
		activatedAt = now
	}
	err := r.db.QueryRowContext(ctx, `INSERT INTO byok_key_epochs
		(org_id, kid, provider, provider_kid, status, activated_at, created_by, metadata_json)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,'')::uuid, $8::jsonb)
		RETURNING id::text, org_id::text, kid, provider, provider_kid, status, created_at,
			activated_at, retired_at, revoked_at, disabled_at, COALESCE(created_by::text,''), COALESCE(metadata_json::text,'')`,
		strings.TrimSpace(e.OrgID), strings.TrimSpace(e.KID), strings.TrimSpace(e.Provider),
		strings.TrimSpace(e.ProviderKID), e.Status, activatedAt, strings.TrimSpace(e.CreatedBy), e.MetadataJSON).Scan(
		&e.ID, &e.OrgID, &e.KID, &e.Provider, &e.ProviderKID, &e.Status, &e.CreatedAt,
		&e.ActivatedAt, &e.RetiredAt, &e.RevokedAt, &e.DisabledAt, &e.CreatedBy, &e.MetadataJSON)
	if err != nil {
		return Epoch{}, fmt.Errorf("BYOK create epoch: %w", err)
	}
	if err := r.recordEvent(ctx, e, "create", "", e.Status); err != nil {
		return Epoch{}, err
	}
	return e, nil
}

func (r *EpochRepository) ActivateEpoch(ctx context.Context, orgID, kid, actor string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BYOK activate epoch begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE byok_key_epochs
		SET status = 'retired', retired_at = COALESCE(retired_at, $3)
		WHERE org_id = $1 AND status = 'active' AND kid <> $2`, orgID, kid, now); err != nil {
		return fmt.Errorf("BYOK retire previous active epoch: %w", err)
	}
	res, err := tx.ExecContext(ctx, `UPDATE byok_key_epochs
		SET status = 'active', activated_at = COALESCE(activated_at, $3), retired_at = NULL, revoked_at = NULL, disabled_at = NULL
		WHERE org_id = $1 AND kid = $2 AND status IN ('pending','retiring','retired')
	`, orgID, kid, now)
	if err != nil {
		return fmt.Errorf("BYOK activate epoch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("BYOK activate epoch RowsAffected: %w", err)
	}
	if n != 1 {
		return ErrUnknownEpoch
	}
	if err := insertEpochEventTx(ctx, tx, orgID, kid, actor, "activate", "", EpochStatusActive); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *EpochRepository) UpdateEpochStatus(ctx context.Context, orgID, kid, status, actor string) error {
	if status == EpochStatusActive {
		return r.ActivateEpoch(ctx, orgID, kid, actor)
	}
	if err := validateEpochStatus(status); err != nil {
		return err
	}
	var tsCol string
	switch status {
	case EpochStatusRetiring:
		tsCol = ""
	case EpochStatusRetired:
		tsCol = "retired_at"
	case EpochStatusRevoked:
		tsCol = "revoked_at"
	case EpochStatusDisabled:
		tsCol = "disabled_at"
	default:
		tsCol = ""
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("BYOK update epoch begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	query := `UPDATE byok_key_epochs SET status = $3 WHERE org_id = $1 AND kid = $2`
	args := []any{orgID, kid, status}
	if tsCol != "" {
		query = fmt.Sprintf(`UPDATE byok_key_epochs SET status = $3, %s = COALESCE(%s, $4) WHERE org_id = $1 AND kid = $2`, tsCol, tsCol)
		args = append(args, time.Now().UTC())
	}
	res, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("BYOK update epoch status: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("BYOK update epoch status RowsAffected: %w", err)
	}
	if n != 1 {
		return ErrUnknownEpoch
	}
	if err := insertEpochEventTx(ctx, tx, orgID, kid, actor, "status_update", "", status); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *EpochRepository) recordEvent(ctx context.Context, e Epoch, action, oldStatus, newStatus string) error {
	return insertEpochEvent(ctx, r.db, e.OrgID, e.KID, e.CreatedBy, action, oldStatus, newStatus)
}

func insertEpochEvent(ctx context.Context, db *sql.DB, orgID, kid, actor, action, oldStatus, newStatus string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO byok_key_epoch_events
		(org_id, kid, actor_user_id, action, old_status, new_status)
		VALUES ($1, $2, NULLIF($3,'')::uuid, $4, NULLIF($5,''), NULLIF($6,''))`,
		orgID, kid, strings.TrimSpace(actor), action, oldStatus, newStatus)
	if err != nil {
		return fmt.Errorf("BYOK epoch event insert: %w", err)
	}
	return nil
}

func insertEpochEventTx(ctx context.Context, tx *sql.Tx, orgID, kid, actor, action, oldStatus, newStatus string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO byok_key_epoch_events
		(org_id, kid, actor_user_id, action, old_status, new_status)
		VALUES ($1, $2, NULLIF($3,'')::uuid, $4, NULLIF($5,''), NULLIF($6,''))`,
		orgID, kid, strings.TrimSpace(actor), action, oldStatus, newStatus)
	if err != nil {
		return fmt.Errorf("BYOK epoch event insert: %w", err)
	}
	return nil
}

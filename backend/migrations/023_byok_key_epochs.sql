-- PR-BYOK3: tenant-scoped DEK epoch lifecycle metadata.
--
-- Payload ciphertext stays in audit_logs.request_body/response_body as BYOK
-- envelopes. This table stores the non-secret lifecycle metadata needed to
-- select active tenant epochs for new writes and decrypt historical envelopes
-- by kid. It does NOT store plaintext DEKs, wrapped DEKs, Vault tokens or KMS
-- credentials.
CREATE TABLE IF NOT EXISTS byok_key_epochs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    kid VARCHAR(255) NOT NULL UNIQUE,
    provider VARCHAR(64) NOT NULL,
    provider_kid VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    activated_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}',
    CHECK (status IN ('pending','active','retiring','retired','revoked','disabled'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_byok_key_epochs_one_active_per_org
    ON byok_key_epochs(org_id)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS idx_byok_key_epochs_org_created
    ON byok_key_epochs(org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS byok_key_epoch_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    kid VARCHAR(255) NOT NULL,
    actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(64) NOT NULL,
    old_status VARCHAR(32),
    new_status VARCHAR(32),
    metadata_json JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_byok_key_epoch_events_org_created
    ON byok_key_epoch_events(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_byok_key_epoch_events_kid_created
    ON byok_key_epoch_events(kid, created_at DESC);

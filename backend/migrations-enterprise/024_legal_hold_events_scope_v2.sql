-- PR-L8.1b: legal_hold_events WORM canonical v2 scope fields.
--
-- legal_holds stores mutable current state. legal_hold_events is the
-- append-only evidence log, so query_scope selector identity must be copied
-- into each transition event and included in CanonicalLegalHoldEventV2.
--
-- Existing rows remain canonical_version='v1' with NULL scope fields.
-- New rows are written as canonical_version='v2' by the Go repository.

ALTER TABLE legal_hold_events
    ADD COLUMN IF NOT EXISTS scope_type VARCHAR(16),
    ADD COLUMN IF NOT EXISTS scope_query_hash CHAR(64),
    ADD COLUMN IF NOT EXISTS scope_query_version SMALLINT,
    ADD COLUMN IF NOT EXISTS scope_date_from TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS scope_date_to   TIMESTAMPTZ;

ALTER TABLE legal_hold_events
    DROP CONSTRAINT IF EXISTS legal_hold_events_scope_type_check,
    DROP CONSTRAINT IF EXISTS legal_hold_events_scope_query_hash_check,
    DROP CONSTRAINT IF EXISTS legal_hold_events_scope_query_version_check;

ALTER TABLE legal_hold_events
    ADD CONSTRAINT legal_hold_events_scope_type_check
        CHECK (scope_type IS NULL OR scope_type IN ('whole_user', 'date_range', 'query_scope')),
    ADD CONSTRAINT legal_hold_events_scope_query_hash_check
        CHECK (scope_query_hash IS NULL OR scope_query_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT legal_hold_events_scope_query_version_check
        CHECK (scope_query_version IS NULL OR scope_query_version = 1);

CREATE INDEX IF NOT EXISTS idx_legal_hold_events_scope_query_hash
    ON legal_hold_events (scope_query_hash)
    WHERE scope_query_hash IS NOT NULL;

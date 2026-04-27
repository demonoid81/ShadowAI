-- PR-L8.1a: legal hold query_scope selector foundation.
--
-- This migration only prepares storage/constraints for query-scoped holds.
-- Create/purge enforcement remains fail-closed until the later L8.1b/WORM
-- integration step. Preview uses the selector compiler without writing holds.

ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS scope_query_json JSONB,
    ADD COLUMN IF NOT EXISTS scope_query_hash CHAR(64),
    ADD COLUMN IF NOT EXISTS scope_query_version SMALLINT NOT NULL DEFAULT 1;

ALTER TABLE legal_holds
    DROP CONSTRAINT IF EXISTS legal_holds_scope_type_check;

ALTER TABLE legal_holds
    ADD CONSTRAINT legal_holds_scope_type_check
    CHECK (scope_type IN ('whole_user', 'date_range', 'query_scope'));

ALTER TABLE legal_holds
    DROP CONSTRAINT IF EXISTS legal_holds_scope_range_check;

ALTER TABLE legal_holds
    ADD CONSTRAINT legal_holds_scope_range_check
    CHECK (
        (
            scope_type = 'whole_user'
            AND scope_date_from IS NULL
            AND scope_date_to IS NULL
            AND scope_query_json IS NULL
            AND scope_query_hash IS NULL
        )
        OR (
            scope_type = 'date_range'
            AND scope_date_from IS NOT NULL
            AND scope_date_to IS NOT NULL
            AND scope_date_from <= scope_date_to
            AND scope_query_json IS NULL
            AND scope_query_hash IS NULL
        )
        OR (
            scope_type = 'query_scope'
            AND scope_date_from IS NULL
            AND scope_date_to IS NULL
            AND scope_query_json IS NOT NULL
            AND scope_query_hash IS NOT NULL
            AND scope_query_hash ~ '^[0-9a-f]{64}$'
            AND scope_query_version = 1
        )
    );

CREATE INDEX IF NOT EXISTS idx_legal_holds_scope_query_blocking
    ON legal_holds (target_user_id, scope_query_hash)
    WHERE status IN ('active', 'release_pending') AND scope_type = 'query_scope';

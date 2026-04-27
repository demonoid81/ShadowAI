-- PR-L6: legal hold scoped enforcement constraints.
--
-- 020 добавила scope_type/scope_date_from/scope_date_to как модель.
-- L6 начинает использовать эти поля для retention purge enforcement, поэтому
-- некорректный date_range должен быть невозможен на уровне БД.

ALTER TABLE legal_holds
    DROP CONSTRAINT IF EXISTS legal_holds_scope_range_check;

ALTER TABLE legal_holds
    ADD CONSTRAINT legal_holds_scope_range_check
    CHECK (
        (
            scope_type = 'whole_user'
            AND scope_date_from IS NULL
            AND scope_date_to IS NULL
        )
        OR (
            scope_type = 'date_range'
            AND scope_date_from IS NOT NULL
            AND scope_date_to IS NOT NULL
            AND scope_date_from <= scope_date_to
        )
    );

CREATE INDEX IF NOT EXISTS idx_legal_holds_scope_range_blocking
    ON legal_holds (target_user_id, scope_date_from, scope_date_to)
    WHERE status IN ('active', 'release_pending') AND scope_type = 'date_range';

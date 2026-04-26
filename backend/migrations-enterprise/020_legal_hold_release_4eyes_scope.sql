-- PR-L5: Legal Hold Advanced Workflow.
--
-- Changes:
--   1. New status: 'release_pending' — hold is actively blocking but release
--      has been requested. DSAR and purge protection remain in effect until
--      ApproveRelease (4-eyes) completes.
--
--   2. Release 4-eyes: active → release_pending (RequestRelease by any admin),
--      then release_pending → released (ApproveRelease by a DIFFERENT admin)
--      or release_pending → active (RejectRelease).
--
--   3. Scope model: scope_type='whole_user' (default, backward-compatible) or
--      'date_range' (optional date boundaries for the hold scope).
--
--   4. Release-request audit columns: release_requested_by / release_requested_at.
--
-- BREAKING CHANGE (documented):
--   The Release endpoint (POST /api/legal-holds/{id}/release) previously did
--   immediate release (active → released). It now performs RequestRelease
--   (active → release_pending). A second admin must call
--   POST /api/legal-holds/{id}/approve-release for final release.
--   Migration path: update SIEM rules and runbooks to expect the two-step flow.

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Drop existing status check constraint and add release_pending.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE legal_holds
    DROP CONSTRAINT IF EXISTS legal_holds_status_check;

ALTER TABLE legal_holds
    ADD CONSTRAINT legal_holds_status_check
    CHECK (status IN ('pending', 'active', 'release_pending', 'released'));

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Extend blocking unique index to include release_pending.
--    A user can have at most one blocking (pending/active/release_pending) hold.
-- ─────────────────────────────────────────────────────────────────────────────
DROP INDEX IF EXISTS idx_legal_holds_blocking_per_user;
CREATE UNIQUE INDEX IF NOT EXISTS idx_legal_holds_blocking_per_user
    ON legal_holds (target_user_id)
    WHERE status IN ('pending', 'active', 'release_pending');

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Update HasActiveHold hot-path index to include release_pending.
--    DSAR and purge protection must block for both active and release_pending.
-- ─────────────────────────────────────────────────────────────────────────────
DROP INDEX IF EXISTS idx_legal_holds_status_active;
CREATE INDEX IF NOT EXISTS idx_legal_holds_status_blocking
    ON legal_holds (target_user_id)
    WHERE status IN ('active', 'release_pending');

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Release-request audit columns.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS release_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS release_requested_by UUID REFERENCES users(id) ON DELETE SET NULL;

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Scope model. Default 'whole_user' preserves existing hold behavior.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS scope_type VARCHAR(16) NOT NULL DEFAULT 'whole_user';

ALTER TABLE legal_holds
    ADD CONSTRAINT IF NOT EXISTS legal_holds_scope_type_check
    CHECK (scope_type IN ('whole_user', 'date_range'));

ALTER TABLE legal_holds
    ADD COLUMN IF NOT EXISTS scope_date_from TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS scope_date_to   TIMESTAMPTZ;

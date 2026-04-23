-- PR-W2: tamper-evident chain для admin_event_logs + legal_hold_events.
-- Enterprise-only (legacy build не требует chain_secret, enterprise prod требует).
--
-- 1. Добавляем chain fields в admin_event_logs (enterprise table, migration 010ent).
-- 2. Создаём legal_hold_events — append-only history для hold state transitions.
--    Each transition (create/approve/reject/release) = одна INSERT-only row.
--    Сама legal_holds table остаётся mutable current-state store.
--
-- Advisory lock namespace для chain writes: 4202 (distinct от legalholdcoord 4201).
-- TableID mapping:
--   1 = audit_logs (core migration 010)
--   2 = admin_event_logs (this migration)
--   3 = legal_hold_events (this migration)
-- RFC: docs/rfcs/2026-04-pr-w1-worm-evidence-architecture.md §7.2, §7.4

-- Part 1: admin_event_logs chain fields.
ALTER TABLE admin_event_logs
    ADD COLUMN IF NOT EXISTS seq_no   BIGINT,
    ADD COLUMN IF NOT EXISTS row_hash BYTEA;

CREATE SEQUENCE IF NOT EXISTS admin_event_logs_chain_seq;

CREATE INDEX IF NOT EXISTS idx_admin_event_logs_chain_seq
    ON admin_event_logs (seq_no)
    WHERE seq_no IS NOT NULL;

-- Part 2: legal_hold_events — append-only hold state transition log.
--
-- Каждый INSERT соответствует одному state transition hold'а. UPDATEs
-- в legal_holds (current state table) не chained напрямую; этот log является
-- tamper-evident history. ON DELETE RESTRICT гарантирует что hold нельзя
-- удалить из legal_holds пока есть events.
CREATE TABLE IF NOT EXISTS legal_hold_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hold_id     UUID NOT NULL REFERENCES legal_holds(id) ON DELETE RESTRICT,
    -- action: 'create' | 'approve' | 'reject' | 'release'
    action      VARCHAR(16) NOT NULL,
    -- new_status после этого transition: 'pending' | 'active' | 'released'
    new_status  VARCHAR(16) NOT NULL,
    -- actor_id: admin выполнивший действие. NULL для системных операций.
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    -- metadata_json: дополнительный контекст (case_ref_hash, reason_hash).
    -- НЕ включается в canonical hash (advisory; не core evidence fields).
    metadata_json JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- chain fields:
    seq_no      BIGINT,      -- nullable для backward compat; non-null после W2 deploy
    row_hash    BYTEA        -- HMAC-SHA256(prev_hash || canonical(row), secret)
);

-- Index для verifier (ordered scan by seq_no) и для hold history lookup.
CREATE INDEX IF NOT EXISTS idx_legal_hold_events_hold_id_seq
    ON legal_hold_events (hold_id, seq_no);
CREATE INDEX IF NOT EXISTS idx_legal_hold_events_chain_seq
    ON legal_hold_events (seq_no)
    WHERE seq_no IS NOT NULL;

CREATE SEQUENCE IF NOT EXISTS legal_hold_events_chain_seq;

-- Check constraints для action и new_status.
ALTER TABLE legal_hold_events
    ADD CONSTRAINT legal_hold_events_action_check
    CHECK (action IN ('create', 'approve', 'reject', 'release')),
    ADD CONSTRAINT legal_hold_events_new_status_check
    CHECK (new_status IN ('pending', 'active', 'released'));

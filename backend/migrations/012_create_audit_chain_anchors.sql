-- PR-W3: periodic Merkle anchor для tamper-evident audit trail.
--
-- Каждая anchor row содержит:
--   - Merkle root над row_hash'ами chained rows в диапазоне [seq_lo, seq_hi]
--   - ссылку на external sink (file:// NDJSON baseline, W3)
--
-- Verifier без chain_secret может детектировать удалённые rows:
--   пересчитать Merkle root из stored row_hashes → сравнить с merkle_root.
--   Нет совпадения → gap (deletion). С chain_secret — полная chain verification.
--
-- Per-table: каждый anchor относится к одной таблице, у которой свой
-- seq_no namespace (audit_logs, admin_event_logs, legal_hold_events,
-- audit_purge_runs). seq_lo/seq_hi — инклюзивный диапазон seq_no.
--
-- Anchors пишутся только когда есть новые chained rows (seq_hi > last_anchor.seq_hi).
-- Пустые периоды не генерируют anchor rows.
--
-- sink_name: "file://" (W3), "siem://" (W4+), "immudb://" (W4+).
-- sink_ref: sink-specific reference (filepath, block_hash, etc.).
-- sink_ok: false если sink write провалился (anchor в PG есть, но без external witness).
CREATE TABLE IF NOT EXISTS audit_chain_anchors (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name   VARCHAR(64)  NOT NULL,
    anchor_seq_lo BIGINT      NOT NULL,
    anchor_seq_hi BIGINT      NOT NULL,
    row_count    INT          NOT NULL,
    merkle_root  BYTEA        NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- sink fields
    sink_name    VARCHAR(64)  NOT NULL DEFAULT '',
    sink_ref     TEXT         NOT NULL DEFAULT '',
    sink_ok      BOOLEAN      NOT NULL DEFAULT false,
    -- invariant: seq_lo <= seq_hi, row_count > 0
    CONSTRAINT audit_chain_anchors_seq_check CHECK (anchor_seq_lo <= anchor_seq_hi),
    CONSTRAINT audit_chain_anchors_count_check CHECK (row_count > 0)
);

-- Verifier и scheduler lookup по last anchor per table.
CREATE INDEX IF NOT EXISTS idx_audit_chain_anchors_table_seq
    ON audit_chain_anchors (table_name, anchor_seq_hi DESC);

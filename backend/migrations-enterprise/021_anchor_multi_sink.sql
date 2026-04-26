-- PR-W8: Second Independent Anchor Sink — per-sink publication records.
--
-- Design decision:
--   Primary anchor row (audit_chain_anchors) retains existing sink_name/sink_ref/sink_ok
--   for backward compatibility with single-sink deployments. For multi-sink anchors,
--   sink_name='multi' and sink_ref='' in the primary row.
--
--   audit_chain_anchor_sinks records per-sink write status for ADDITIONAL sinks.
--   Both the primary and all additional sinks store the SAME signed manifest bytes,
--   ensuring one canonical Ed25519-signed manifest is the single source of truth.
--
-- Partial sink failure: if sink B fails, sink_ok=false in anchor_sinks with error_msg.
-- The operator must see this through metrics/logs AND can query this table.
--
-- Backward compatibility: anchors written before W8 have no rows here. Verifier
-- treats missing rows as legacy (single-sink) and verifies via sink_ref in primary row.

CREATE TABLE IF NOT EXISTS audit_chain_anchor_sinks (
    anchor_id   UUID         NOT NULL,
    sink_name   VARCHAR(64)  NOT NULL,
    sink_ref    TEXT         NOT NULL DEFAULT '',
    sink_ok     BOOLEAN      NOT NULL DEFAULT false,
    error_msg   TEXT,                           -- populated when sink_ok=false
    written_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (anchor_id, sink_name),
    FOREIGN KEY (anchor_id) REFERENCES audit_chain_anchors(id) ON DELETE CASCADE
);

-- Index for fast per-anchor lookup during verification.
CREATE INDEX IF NOT EXISTS idx_anchor_sinks_anchor_id
    ON audit_chain_anchor_sinks(anchor_id);

-- Operator monitoring: query partially-failed anchors.
-- SELECT a.table_name, a.anchor_seq_lo, a.anchor_seq_hi, s.sink_name, s.error_msg
-- FROM audit_chain_anchors a JOIN audit_chain_anchor_sinks s ON s.anchor_id = a.id
-- WHERE s.sink_ok = false ORDER BY a.created_at DESC LIMIT 20;

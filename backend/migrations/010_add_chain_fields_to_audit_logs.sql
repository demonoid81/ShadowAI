-- PR-W2: tamper-evident chain для audit_logs (Layer 1 WORM, RFC §7.2).
--
-- Добавляет два поля для hash chain:
--   seq_no BIGINT  — монотонный счётчик из PostgreSQL SEQUENCE.
--                    Gap в seq_no = детектируемое удаление.
--                    NULL для legacy rows до миграции (не chained).
--   row_hash BYTEA — HMAC-SHA256(prev_row_hash || canonical(row), secret).
--                    chain break (mismatch) = детектируемая модификация.
--                    NULL для legacy rows.
--
-- Chain записи выполняются через pg_advisory_xact_lock(4202, 1) в рамках
-- INSERT tx — атомарность guaranteed (RFC §7.2). AUDIT_CHAIN_SECRET env var.
-- Nullable: backward compat с существующими rows. Core build без
-- AUDIT_CHAIN_SECRET = chain disabled (явный warning; enterprise build
-- требует chain_secret в prod через ValidateStartupConfig).

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS seq_no   BIGINT,
    ADD COLUMN IF NOT EXISTS row_hash BYTEA;

-- Sequence для chain seq_no. Not associated with column напрямую, чтобы
-- application полностью контролировала acquire moment (внутри advisory lock).
CREATE SEQUENCE IF NOT EXISTS audit_logs_chain_seq;

-- Индекс для verifier CLI (scan by seq_no) и tip lookup (max(seq_no)).
CREATE INDEX IF NOT EXISTS idx_audit_logs_chain_seq
    ON audit_logs (seq_no)
    WHERE seq_no IS NOT NULL;

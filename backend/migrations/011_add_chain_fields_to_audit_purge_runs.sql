-- PR-W2: tamper-evident chain для audit_purge_runs.
--
-- Перед каждой purge-операцией пишется chain-anchored record:
-- это доказывает что purge был авторизован и залогирован ПРЕЖДЕ
-- чем данные были удалены.
--
-- DBA не может удалить audit_logs без этой записи в chain —
-- она появляется в Merkle anchor (W3) как доказательство факта purge.
--
-- chain fields: аналогичны audit_logs (migration 010).
-- TableID = 4 (chain namespace 4202, отдельный от других таблиц).
ALTER TABLE audit_purge_runs
    ADD COLUMN IF NOT EXISTS seq_no   BIGINT,
    ADD COLUMN IF NOT EXISTS row_hash BYTEA;

CREATE SEQUENCE IF NOT EXISTS audit_purge_runs_chain_seq;

CREATE INDEX IF NOT EXISTS idx_audit_purge_runs_chain_seq
    ON audit_purge_runs (seq_no)
    WHERE seq_no IS NOT NULL;

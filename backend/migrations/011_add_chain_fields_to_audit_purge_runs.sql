-- PR-W2: tamper-evident chain для audit_purge_runs.
--
-- После каждой purge-операции пишется ONE chained record с реальным
-- rows_deleted — это доказывает что purge был залогирован и не был
-- retroactively удалён или модифицирован.
--
-- Запись пишется ВНУТРИ той же транзакции что и DELETE (для coordinated
-- path) или в короткой tx сразу после DELETE (для non-coordinated path),
-- что обеспечивает атомарность: либо purge и record оба commit'ятся,
-- либо оба rollback'ятся.
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

-- PR-W4.1: Ed25519 signed anchor manifests.
--
-- Каждая anchor row получает:
--   pubkey_id  — идентификатор ключа (e.g. "ed25519-k1"). Позволяет
--                verifier'у выбрать правильный публичный ключ при
--                multi-key deployment и при rotation.
--   signature  — Ed25519 подпись над canonical manifest payload:
--                v1|table|seq_lo|seq_hi|row_count|merkle_root_hex|
--                created_at_epoch|sink_name|sink_ref|pubkey_id
--
-- NULL = anchor записан без подписи (pre-W4.1 rows или signing
-- key не был сконфигурирован — допустимо для dev/core builds).
-- Verifier различает unsigned (NULL) и signature-mismatch (bad sig).
--
-- Публичный ключ НЕ хранится в DB (это поломает threat model: DBA мог
-- бы заменить ключ и re-sign). Публичный ключ передаётся verifier'у
-- через --pubkey или --pubkey-file.
ALTER TABLE audit_chain_anchors
    ADD COLUMN IF NOT EXISTS pubkey_id  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS signature  BYTEA;

-- PR-E1.1: Admin MFA / break-glass policy.
--
-- totp_secret   — XOR-obfuscated TOTP secret (HMAC-derived key stream, hex-encoded).
--                 This is obfuscation, not AES encryption. For stronger at-rest
--                 protection, add pgcrypto column encryption or KMS envelope encryption.
--                 NULL = MFA not configured.
-- mfa_required  — if true, login requires TOTP code after password check.
--                 Defaults to false; set to true for all admin accounts in prod.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS totp_secret   VARCHAR(512),
  ADD COLUMN IF NOT EXISTS mfa_required  BOOLEAN NOT NULL DEFAULT false;

-- Index for quick MFA check during login (hot path).
CREATE INDEX IF NOT EXISTS idx_users_mfa_required
  ON users (mfa_required)
  WHERE mfa_required = true;

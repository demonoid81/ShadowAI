-- PR-E1.1: Admin MFA / break-glass policy.
--
-- totp_secret   — AES-encrypted TOTP seed (32 bytes base32-encoded).
--                 NULL = MFA not configured. Never store plain-text.
-- mfa_required  — if true, login requires TOTP code after password check.
--                 Defaults to false; set to true for all admin accounts in prod.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS totp_secret   VARCHAR(512),
  ADD COLUMN IF NOT EXISTS mfa_required  BOOLEAN NOT NULL DEFAULT false;

-- Index for quick MFA check during login (hot path).
CREATE INDEX IF NOT EXISTS idx_users_mfa_required
  ON users (mfa_required)
  WHERE mfa_required = true;

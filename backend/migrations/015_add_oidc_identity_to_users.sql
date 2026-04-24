-- PR-E1: OIDC Enterprise Auth v1.
--
-- Adds OIDC identity fields to users. Linking by (oidc_issuer, oidc_subject)
-- is safer than email-only: the same email can exist at two issuers, and IdPs
-- can reuse email addresses after account deletion.
--
-- Fields:
--   oidc_issuer       — IdP URL (e.g. https://accounts.google.com).
--   oidc_subject      — IdP-assigned subject identifier (opaque, unique per issuer).
--   last_oidc_login_at — timestamp of last successful OIDC authentication.
--
-- Unique index on (oidc_issuer, oidc_subject) prevents two accounts from
-- claiming the same IdP identity.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS oidc_issuer       VARCHAR(512),
  ADD COLUMN IF NOT EXISTS oidc_subject      VARCHAR(512),
  ADD COLUMN IF NOT EXISTS last_oidc_login_at TIMESTAMPTZ;

-- Unique constraint: one user per (issuer, subject) pair.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_identity
  ON users (oidc_issuer, oidc_subject)
  WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;

-- Fast lookup during callback (O(1) subject resolution).
CREATE INDEX IF NOT EXISTS idx_users_oidc_issuer_subject
  ON users (oidc_issuer, oidc_subject)
  WHERE oidc_issuer IS NOT NULL;

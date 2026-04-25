-- PR-E2: SCIM 2.0 user provisioning.
--
-- scim_external_id — IdP-assigned user identifier from SCIM externalId.
-- Separate from oidc_subject: SCIM provisioning happens independently of
-- OIDC login. The same user may have both (SCIM for lifecycle management,
-- OIDC for authentication).
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS scim_external_id VARCHAR(512);

-- Unique index: one user per IdP-assigned externalId.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_external_id
  ON users (scim_external_id)
  WHERE scim_external_id IS NOT NULL;

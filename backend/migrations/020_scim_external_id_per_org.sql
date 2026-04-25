-- PR-T2.3.2: Make scim_external_id unique per org instead of globally.
--
-- The old global uniqueness prevents the same IdP-assigned externalId from
-- being used in two different orgs. In a multi-tenant setup each org
-- manages its own IdP identity namespace, so uniqueness must be scoped.
--
-- Idempotent: IF NOT EXISTS guards both the DROP (which fails silently when
-- the index doesn't exist) and the CREATE UNIQUE INDEX.
--
-- Pre-condition: migration 018 added users.org_id.

DROP INDEX IF EXISTS idx_users_scim_external_id;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_scim_external_id_per_org
    ON users (org_id, scim_external_id)
    WHERE scim_external_id IS NOT NULL;

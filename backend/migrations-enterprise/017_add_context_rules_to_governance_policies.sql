-- PR-G3: context-scoped governance — add context_rules_json column.
--
-- context_rules_json stores []ContextRule: per-(department, role, sensitivity)
-- provider/model allowlists. Used when mode='context_scoped'.
-- Existing policies have '[]' which means deny-all in context_scoped mode
-- (no rules → no context matches → unknown_department/unknown_context).
ALTER TABLE provider_governance_policies
  ADD COLUMN IF NOT EXISTS context_rules_json JSONB NOT NULL DEFAULT '[]'::jsonb;

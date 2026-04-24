-- PR-G3: add department to users for context-scoped governance routing.
--
-- Nullable — existing users start without a department assignment.
-- Admin sets department via PUT /admin/users/{id} or external IdP sync.
-- Empty/NULL department maps to CodeUnknownDepartment deny in context_scoped mode.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS department VARCHAR(128);

-- Index for admin listing by department (dashboard / bulk policy assignment).
CREATE INDEX IF NOT EXISTS idx_users_department
  ON users (department)
  WHERE department IS NOT NULL;

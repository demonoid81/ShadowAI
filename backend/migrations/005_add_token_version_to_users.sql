ALTER TABLE users
    ADD COLUMN IF NOT EXISTS token_version INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_users_token_version ON users(token_version);

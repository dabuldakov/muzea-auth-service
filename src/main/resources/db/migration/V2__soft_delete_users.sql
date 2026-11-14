-- Удаление аккаунта в IdP теперь мягкое: строка, email и username остаются,
-- вход закрыт до реактивации поддержкой.
ALTER TABLE users ADD COLUMN is_deleted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN deleted_at TIMESTAMPTZ;

CREATE INDEX idx_users_is_deleted ON users (is_deleted) WHERE is_deleted;

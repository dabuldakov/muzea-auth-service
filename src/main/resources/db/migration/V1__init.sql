-- F1: единый IdP. Пользователи без пароля, email-OTP коды и refresh-сессии.

CREATE TABLE users (
    id             UUID         PRIMARY KEY,
    email          VARCHAR(255) NOT NULL UNIQUE,
    username       VARCHAR(64)  NOT NULL UNIQUE,
    display_name   VARCHAR(128),
    email_verified BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ  NOT NULL,
    updated_at     TIMESTAMPTZ  NOT NULL
);

CREATE TABLE email_codes (
    id          UUID         PRIMARY KEY,
    email       VARCHAR(255) NOT NULL,
    purpose     VARCHAR(16)  NOT NULL,
    code_hash   VARCHAR(128) NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    attempts    INTEGER      NOT NULL DEFAULT 0,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL
);

CREATE INDEX idx_email_codes_email_purpose ON email_codes (email, purpose);

CREATE TABLE refresh_tokens (
    id           UUID         PRIMARY KEY,
    user_id      UUID         NOT NULL,
    family_id    UUID         NOT NULL,
    device_id    VARCHAR(128),
    token_hash   VARCHAR(64)  NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ  NOT NULL,
    revoked      BOOLEAN      NOT NULL DEFAULT FALSE,
    rotated_from UUID,
    user_agent   VARCHAR(512),
    ip           VARCHAR(64),
    created_at   TIMESTAMPTZ  NOT NULL,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_family_id ON refresh_tokens (family_id);

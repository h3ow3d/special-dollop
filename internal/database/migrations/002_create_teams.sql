CREATE TABLE IF NOT EXISTS teams (
    id          BIGSERIAL    PRIMARY KEY,
    name        VARCHAR(128) NOT NULL UNIQUE,
    description TEXT         NOT NULL DEFAULT '',
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

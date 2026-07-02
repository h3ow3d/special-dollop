CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL    PRIMARY KEY,
    github_user_id  BIGINT       NOT NULL UNIQUE,
    github_username VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL DEFAULT '',
    email           VARCHAR(255) NOT NULL DEFAULT '',
    avatar_url      VARCHAR(512) NOT NULL DEFAULT '',
    role_id         BIGINT       NOT NULL REFERENCES roles(id),
    team_id         BIGINT       REFERENCES teams(id),
    active          BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_login_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_github_user_id  ON users(github_user_id);
CREATE INDEX IF NOT EXISTS idx_users_github_username ON users(github_username);

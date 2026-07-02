CREATE TABLE IF NOT EXISTS inventory_items (
    id             BIGSERIAL    PRIMARY KEY,
    name           VARCHAR(128) NOT NULL,
    description    TEXT         NOT NULL DEFAULT '',
    team_id        BIGINT       NOT NULL REFERENCES teams(id),
    registry       VARCHAR(256) NOT NULL DEFAULT '',
    package_url    TEXT         NOT NULL DEFAULT '',
    package_name   VARCHAR(256) NOT NULL DEFAULT '',
    repository_url TEXT         NOT NULL DEFAULT '',
    active         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inventory_items_team_id  ON inventory_items(team_id);
CREATE INDEX IF NOT EXISTS idx_inventory_items_active   ON inventory_items(active);

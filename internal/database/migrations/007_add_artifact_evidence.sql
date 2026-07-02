ALTER TABLE inventory_items
    ADD COLUMN IF NOT EXISTS reference VARCHAR(256) NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS artifact_metadata (
    id                 BIGSERIAL PRIMARY KEY,
    inventory_item_id  BIGINT      NOT NULL UNIQUE REFERENCES inventory_items(id) ON DELETE CASCADE,
    registry           VARCHAR(256) NOT NULL DEFAULT '',
    repository         VARCHAR(256) NOT NULL DEFAULT '',
    reference          VARCHAR(256) NOT NULL DEFAULT '',
    resolved_reference TEXT         NOT NULL DEFAULT '',
    digest             VARCHAR(256) NOT NULL DEFAULT '',
    media_type         VARCHAR(256) NOT NULL DEFAULT '',
    artifact_type      VARCHAR(256) NOT NULL DEFAULT '',
    size_bytes         BIGINT       NOT NULL DEFAULT 0,
    discovery_status   VARCHAR(32)  NOT NULL DEFAULT 'pending',
    discovery_error    TEXT         NOT NULL DEFAULT '',
    last_discovered_at TIMESTAMPTZ,
    last_refresh_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_artifact_metadata_inventory_item_id
    ON artifact_metadata(inventory_item_id);
CREATE INDEX IF NOT EXISTS idx_artifact_metadata_discovery_status
    ON artifact_metadata(discovery_status);

CREATE TABLE IF NOT EXISTS artifact_evidence (
    id                   BIGSERIAL PRIMARY KEY,
    artifact_metadata_id BIGINT       NOT NULL REFERENCES artifact_metadata(id) ON DELETE CASCADE,
    type                 VARCHAR(32)  NOT NULL,
    name                 VARCHAR(256) NOT NULL DEFAULT '',
    digest               VARCHAR(256) NOT NULL DEFAULT '',
    media_type           VARCHAR(256) NOT NULL DEFAULT '',
    artifact_type        VARCHAR(256) NOT NULL DEFAULT '',
    annotations          JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_artifact_evidence_metadata_id
    ON artifact_evidence(artifact_metadata_id);
CREATE INDEX IF NOT EXISTS idx_artifact_evidence_type
    ON artifact_evidence(type);

-- Migration 008: repository-scoped evidence discovery
--
-- Replaces the single-tag artifact_metadata / artifact_evidence model with a
-- three-tier hierarchy: inventory_items → artifact_digests → digest_evidence,
-- with a repository_tags table linking mutable tags to immutable digests.

-- Drop old tables (data is not migrated; discovery re-runs on next refresh).
DROP TABLE IF EXISTS artifact_evidence;
DROP TABLE IF EXISTS artifact_metadata;

-- Remove the single-tag reference column from inventory_items.
ALTER TABLE inventory_items DROP COLUMN IF EXISTS reference;

-- artifact_digests: one row per unique immutable digest per inventory item.
-- Rows are never deleted so that assessment records referencing them remain valid.
CREATE TABLE IF NOT EXISTS artifact_digests (
    id                 BIGSERIAL    PRIMARY KEY,
    inventory_item_id  BIGINT       NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
    digest             VARCHAR(256) NOT NULL,
    media_type         VARCHAR(256) NOT NULL DEFAULT '',
    artifact_type      VARCHAR(256) NOT NULL DEFAULT '',
    size_bytes         BIGINT       NOT NULL DEFAULT 0,
    discovery_status   VARCHAR(32)  NOT NULL DEFAULT 'pending',
    discovery_error    TEXT         NOT NULL DEFAULT '',
    last_discovered_at TIMESTAMPTZ,
    last_refresh_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (inventory_item_id, digest)
);

-- repository_tags: mutable tag → immutable digest pointer.
-- Updated on every discovery run; historical digest rows are preserved.
CREATE TABLE IF NOT EXISTS repository_tags (
    id                  BIGSERIAL    PRIMARY KEY,
    inventory_item_id   BIGINT       NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
    tag                 VARCHAR(256) NOT NULL,
    artifact_digest_id  BIGINT       REFERENCES artifact_digests(id) ON DELETE SET NULL,
    first_seen_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (inventory_item_id, tag)
);

-- digest_evidence: OCI referrers (signatures, SBOMs, provenance, attestations)
-- discovered for a specific immutable digest.  Replaced in full on each refresh.
CREATE TABLE IF NOT EXISTS digest_evidence (
    id                 BIGSERIAL    PRIMARY KEY,
    artifact_digest_id BIGINT       NOT NULL REFERENCES artifact_digests(id) ON DELETE CASCADE,
    type               VARCHAR(32)  NOT NULL,
    name               VARCHAR(256) NOT NULL DEFAULT '',
    digest             VARCHAR(256) NOT NULL DEFAULT '',
    media_type         VARCHAR(256) NOT NULL DEFAULT '',
    artifact_type      VARCHAR(256) NOT NULL DEFAULT '',
    annotations        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (artifact_digest_id, digest)
);

CREATE INDEX IF NOT EXISTS idx_artifact_digests_inventory_item_id  ON artifact_digests(inventory_item_id);
CREATE INDEX IF NOT EXISTS idx_artifact_digests_discovery_status   ON artifact_digests(discovery_status);
CREATE INDEX IF NOT EXISTS idx_repository_tags_inventory_item_id   ON repository_tags(inventory_item_id);
CREATE INDEX IF NOT EXISTS idx_repository_tags_artifact_digest_id  ON repository_tags(artifact_digest_id);
CREATE INDEX IF NOT EXISTS idx_digest_evidence_artifact_digest_id  ON digest_evidence(artifact_digest_id);
CREATE INDEX IF NOT EXISTS idx_digest_evidence_type                ON digest_evidence(type);

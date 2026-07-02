package evidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Repository persists artifact metadata and evidence records.
type Repository interface {
	Save(ctx context.Context, metadata *ArtifactMetadata, evidence []*ArtifactEvidence) error
	GetByInventoryItemID(ctx context.Context, inventoryItemID int64) (*ArtifactMetadata, error)
}

type pgRepository struct{ db *sql.DB }

// NewRepository returns a PostgreSQL-backed evidence repository.
func NewRepository(db *sql.DB) Repository { return &pgRepository{db: db} }

func (r *pgRepository) Save(ctx context.Context, metadata *ArtifactMetadata, evidence []*ArtifactEvidence) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin evidence save: %w", err)
	}
	defer tx.Rollback()

	const upsert = `
		INSERT INTO artifact_metadata
		    (inventory_item_id, registry, repository, reference, resolved_reference, digest,
		     media_type, artifact_type, size_bytes, discovery_status, discovery_error,
		     last_discovered_at, last_refresh_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (inventory_item_id) DO UPDATE
		SET registry = EXCLUDED.registry,
		    repository = EXCLUDED.repository,
		    reference = EXCLUDED.reference,
		    resolved_reference = EXCLUDED.resolved_reference,
		    digest = EXCLUDED.digest,
		    media_type = EXCLUDED.media_type,
		    artifact_type = EXCLUDED.artifact_type,
		    size_bytes = EXCLUDED.size_bytes,
		    discovery_status = EXCLUDED.discovery_status,
		    discovery_error = EXCLUDED.discovery_error,
		    last_discovered_at = EXCLUDED.last_discovered_at,
		    last_refresh_at = EXCLUDED.last_refresh_at,
		    updated_at = NOW()
		RETURNING id, created_at, updated_at`

	err = tx.QueryRowContext(ctx, upsert,
		metadata.InventoryItemID,
		metadata.Registry,
		metadata.Repository,
		metadata.Reference,
		metadata.ResolvedReference,
		metadata.Digest,
		metadata.MediaType,
		metadata.ArtifactType,
		metadata.SizeBytes,
		string(metadata.DiscoveryStatus),
		metadata.DiscoveryError,
		nullableTime(metadata.LastDiscoveredAt),
		metadata.LastRefreshAt,
	).Scan(&metadata.ID, &metadata.CreatedAt, &metadata.UpdatedAt)
	if err != nil {
		return fmt.Errorf("upsert artifact metadata: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM artifact_evidence WHERE artifact_metadata_id = $1`, metadata.ID); err != nil {
		return fmt.Errorf("delete artifact evidence: %w", err)
	}

	const insertEvidence = `
		INSERT INTO artifact_evidence
		    (artifact_metadata_id, type, name, digest, media_type, artifact_type, annotations)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at`
	for _, item := range evidence {
		annotations, err := json.Marshal(item.Annotations)
		if err != nil {
			return fmt.Errorf("marshal evidence annotations: %w", err)
		}
		if err := tx.QueryRowContext(ctx, insertEvidence,
			metadata.ID,
			string(item.Type),
			item.Name,
			item.Digest,
			item.MediaType,
			item.ArtifactType,
			annotations,
		).Scan(&item.ID, &item.CreatedAt); err != nil {
			return fmt.Errorf("insert artifact evidence: %w", err)
		}
		item.ArtifactMetadataID = metadata.ID
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit evidence save: %w", err)
	}

	metadata.Evidence = evidence
	return nil
}

func (r *pgRepository) GetByInventoryItemID(ctx context.Context, inventoryItemID int64) (*ArtifactMetadata, error) {
	const metadataQuery = `
		SELECT id, inventory_item_id, registry, repository, reference, resolved_reference,
		       digest, media_type, artifact_type, size_bytes, discovery_status,
		       discovery_error, COALESCE(last_discovered_at, '0001-01-01T00:00:00Z'::timestamptz),
		       last_refresh_at, created_at, updated_at
		FROM artifact_metadata
		WHERE inventory_item_id = $1`

	metadata := &ArtifactMetadata{}
	var status string
	err := r.db.QueryRowContext(ctx, metadataQuery, inventoryItemID).Scan(
		&metadata.ID,
		&metadata.InventoryItemID,
		&metadata.Registry,
		&metadata.Repository,
		&metadata.Reference,
		&metadata.ResolvedReference,
		&metadata.Digest,
		&metadata.MediaType,
		&metadata.ArtifactType,
		&metadata.SizeBytes,
		&status,
		&metadata.DiscoveryError,
		&metadata.LastDiscoveredAt,
		&metadata.LastRefreshAt,
		&metadata.CreatedAt,
		&metadata.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get artifact metadata: %w", err)
	}
	metadata.DiscoveryStatus = DiscoveryStatus(status)

	const evidenceQuery = `
		SELECT id, artifact_metadata_id, type, name, digest, media_type, artifact_type, annotations, created_at
		FROM artifact_evidence
		WHERE artifact_metadata_id = $1
		ORDER BY type, name, digest`
	rows, err := r.db.QueryContext(ctx, evidenceQuery, metadata.ID)
	if err != nil {
		return nil, fmt.Errorf("list artifact evidence: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		item := &ArtifactEvidence{}
		var evidenceType string
		var annotations []byte
		if err := rows.Scan(
			&item.ID,
			&item.ArtifactMetadataID,
			&evidenceType,
			&item.Name,
			&item.Digest,
			&item.MediaType,
			&item.ArtifactType,
			&annotations,
			&item.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan artifact evidence: %w", err)
		}
		item.Type = EvidenceType(evidenceType)
		if len(annotations) > 0 {
			if err := json.Unmarshal(annotations, &item.Annotations); err != nil {
				return nil, fmt.Errorf("unmarshal artifact evidence annotations: %w", err)
			}
		}
		metadata.Evidence = append(metadata.Evidence, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact evidence: %w", err)
	}

	return metadata, nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

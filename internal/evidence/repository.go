package evidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Repository persists artifact digests, repository tags, and evidence records.
type Repository interface {
	// Digest operations
	UpsertDigest(ctx context.Context, d *ArtifactDigest) error
	UpdateDigestStatus(ctx context.Context, id int64, status DiscoveryStatus, errMsg string, discoveredAt time.Time) error
	GetDigestByID(ctx context.Context, id int64) (*ArtifactDigest, error)
	ListDigestsByItem(ctx context.Context, inventoryItemID int64) ([]*ArtifactDigest, error)

	// Tag operations
	UpsertTag(ctx context.Context, tag *RepositoryTag) error
	ListTagsByItem(ctx context.Context, inventoryItemID int64) ([]*RepositoryTag, error)

	// Evidence operations
	ReplaceEvidence(ctx context.Context, artifactDigestID int64, evidence []*DigestEvidence) error

	// Summary operations for list views
	GetSummaries(ctx context.Context) (map[int64]*RepositorySummary, error)
}

type pgRepository struct{ db *sql.DB }

// NewRepository returns a PostgreSQL-backed evidence repository.
func NewRepository(db *sql.DB) Repository { return &pgRepository{db: db} }

func (r *pgRepository) UpsertDigest(ctx context.Context, d *ArtifactDigest) error {
	const q = `
		INSERT INTO artifact_digests
		    (inventory_item_id, digest, media_type, artifact_type, size_bytes,
		     discovery_status, discovery_error, last_refresh_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (inventory_item_id, digest) DO UPDATE
		SET media_type        = EXCLUDED.media_type,
		    artifact_type     = EXCLUDED.artifact_type,
		    size_bytes        = EXCLUDED.size_bytes,
		    discovery_status  = EXCLUDED.discovery_status,
		    discovery_error   = EXCLUDED.discovery_error,
		    last_refresh_at   = EXCLUDED.last_refresh_at
		RETURNING id, created_at`
	return r.db.QueryRowContext(ctx, q,
		d.InventoryItemID, d.Digest, d.MediaType, d.ArtifactType, d.SizeBytes,
		string(d.DiscoveryStatus), d.DiscoveryError, d.LastRefreshAt,
	).Scan(&d.ID, &d.CreatedAt)
}

func (r *pgRepository) UpdateDigestStatus(ctx context.Context, id int64, status DiscoveryStatus, errMsg string, discoveredAt time.Time) error {
	const q = `
		UPDATE artifact_digests
		SET discovery_status = $1, discovery_error = $2, last_discovered_at = $3
		WHERE id = $4`
	_, err := r.db.ExecContext(ctx, q, string(status), errMsg, nullableTime(discoveredAt), id)
	return err
}

func (r *pgRepository) GetDigestByID(ctx context.Context, id int64) (*ArtifactDigest, error) {
	const q = `
		SELECT id, inventory_item_id, digest, media_type, artifact_type, size_bytes,
		       discovery_status, discovery_error,
		       COALESCE(last_discovered_at, '0001-01-01T00:00:00Z'::timestamptz),
		       last_refresh_at, created_at
		FROM artifact_digests
		WHERE id = $1`
	d := &ArtifactDigest{}
	var status string
	err := r.db.QueryRowContext(ctx, q, id).Scan(
		&d.ID, &d.InventoryItemID, &d.Digest, &d.MediaType, &d.ArtifactType,
		&d.SizeBytes, &status, &d.DiscoveryError,
		&d.LastDiscoveredAt, &d.LastRefreshAt, &d.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get artifact digest: %w", err)
	}
	d.DiscoveryStatus = DiscoveryStatus(status)

	ev, err := r.loadEvidenceForDigestIDs(ctx, []int64{id})
	if err != nil {
		return nil, err
	}
	d.Evidence = ev[id]

	tags, err := r.loadTagNamesForDigestIDs(ctx, d.InventoryItemID, []int64{id})
	if err != nil {
		return nil, err
	}
	d.Tags = tags[id]

	return d, nil
}

func (r *pgRepository) ListDigestsByItem(ctx context.Context, inventoryItemID int64) ([]*ArtifactDigest, error) {
	const q = `
		SELECT id, inventory_item_id, digest, media_type, artifact_type, size_bytes,
		       discovery_status, discovery_error,
		       COALESCE(last_discovered_at, '0001-01-01T00:00:00Z'::timestamptz),
		       last_refresh_at, created_at
		FROM artifact_digests
		WHERE inventory_item_id = $1
		ORDER BY last_refresh_at DESC, created_at DESC`
	rows, err := r.db.QueryContext(ctx, q, inventoryItemID)
	if err != nil {
		return nil, fmt.Errorf("list artifact digests: %w", err)
	}
	defer rows.Close()

	var digests []*ArtifactDigest
	var ids []int64
	for rows.Next() {
		d := &ArtifactDigest{}
		var status string
		if err := rows.Scan(
			&d.ID, &d.InventoryItemID, &d.Digest, &d.MediaType, &d.ArtifactType,
			&d.SizeBytes, &status, &d.DiscoveryError,
			&d.LastDiscoveredAt, &d.LastRefreshAt, &d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan artifact digest: %w", err)
		}
		d.DiscoveryStatus = DiscoveryStatus(status)
		digests = append(digests, d)
		ids = append(ids, d.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact digests: %w", err)
	}
	if len(digests) == 0 {
		return digests, nil
	}

	ev, err := r.loadEvidenceForDigestIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	tagNames, err := r.loadTagNamesForDigestIDs(ctx, inventoryItemID, ids)
	if err != nil {
		return nil, err
	}
	for _, d := range digests {
		d.Evidence = ev[d.ID]
		d.Tags = tagNames[d.ID]
	}
	return digests, nil
}

// loadEvidenceForDigestIDs fetches evidence for the given digest IDs via a JOIN
// on inventory_item_id to avoid needing a pq.Array binding.
func (r *pgRepository) loadEvidenceForDigestIDs(ctx context.Context, digestIDs []int64) (map[int64][]*DigestEvidence, error) {
	if len(digestIDs) == 0 {
		return nil, nil
	}
	// Build an ad-hoc VALUES list: (1),(2),(3)…
	q := `
		SELECT de.id, de.artifact_digest_id, de.type, de.name, de.digest,
		       de.media_type, de.artifact_type, de.annotations, de.created_at
		FROM digest_evidence de
		WHERE de.artifact_digest_id IN (` + inClause(len(digestIDs)) + `)
		ORDER BY de.artifact_digest_id, de.type, de.name`
	args := int64Slice(digestIDs)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list digest evidence: %w", err)
	}
	defer rows.Close()

	result := make(map[int64][]*DigestEvidence)
	for rows.Next() {
		ev := &DigestEvidence{}
		var evType string
		var annotations []byte
		if err := rows.Scan(
			&ev.ID, &ev.ArtifactDigestID, &evType, &ev.Name, &ev.Digest,
			&ev.MediaType, &ev.ArtifactType, &annotations, &ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan digest evidence: %w", err)
		}
		ev.Type = EvidenceType(evType)
		if len(annotations) > 0 {
			if err := json.Unmarshal(annotations, &ev.Annotations); err != nil {
				return nil, fmt.Errorf("unmarshal evidence annotations: %w", err)
			}
		}
		result[ev.ArtifactDigestID] = append(result[ev.ArtifactDigestID], ev)
	}
	return result, rows.Err()
}

// loadTagNamesForDigestIDs fetches the tag strings that point to the given
// digest IDs within a specific inventory item.
func (r *pgRepository) loadTagNamesForDigestIDs(ctx context.Context, inventoryItemID int64, digestIDs []int64) (map[int64][]string, error) {
	if len(digestIDs) == 0 {
		return nil, nil
	}
	q := `
		SELECT artifact_digest_id, tag
		FROM repository_tags
		WHERE inventory_item_id = $1
		  AND artifact_digest_id IN (` + inClause(len(digestIDs)) + `)
		ORDER BY tag`
	args := append([]any{inventoryItemID}, int64Slice(digestIDs)...)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list tag names for digests: %w", err)
	}
	defer rows.Close()

	result := make(map[int64][]string)
	for rows.Next() {
		var digestID int64
		var tag string
		if err := rows.Scan(&digestID, &tag); err != nil {
			return nil, fmt.Errorf("scan tag name: %w", err)
		}
		result[digestID] = append(result[digestID], tag)
	}
	return result, rows.Err()
}

func (r *pgRepository) UpsertTag(ctx context.Context, tag *RepositoryTag) error {
	const q = `
		INSERT INTO repository_tags (inventory_item_id, tag, artifact_digest_id, last_seen_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (inventory_item_id, tag) DO UPDATE
		SET artifact_digest_id = EXCLUDED.artifact_digest_id,
		    last_seen_at        = EXCLUDED.last_seen_at
		RETURNING id, first_seen_at`
	return r.db.QueryRowContext(ctx, q,
		tag.InventoryItemID, tag.Tag, tag.ArtifactDigestID, tag.LastSeenAt,
	).Scan(&tag.ID, &tag.FirstSeenAt)
}

func (r *pgRepository) ListTagsByItem(ctx context.Context, inventoryItemID int64) ([]*RepositoryTag, error) {
	const q = `
		SELECT rt.id, rt.inventory_item_id, rt.tag, rt.artifact_digest_id,
		       rt.first_seen_at, rt.last_seen_at,
		       COALESCE(ad.digest, '') AS digest
		FROM repository_tags rt
		LEFT JOIN artifact_digests ad ON ad.id = rt.artifact_digest_id
		WHERE rt.inventory_item_id = $1
		ORDER BY rt.tag`
	rows, err := r.db.QueryContext(ctx, q, inventoryItemID)
	if err != nil {
		return nil, fmt.Errorf("list repository tags: %w", err)
	}
	defer rows.Close()

	var tags []*RepositoryTag
	for rows.Next() {
		t := &RepositoryTag{}
		if err := rows.Scan(
			&t.ID, &t.InventoryItemID, &t.Tag, &t.ArtifactDigestID,
			&t.FirstSeenAt, &t.LastSeenAt, &t.Digest,
		); err != nil {
			return nil, fmt.Errorf("scan repository tag: %w", err)
		}
		tags = append(tags, t)
	}
	return tags, rows.Err()
}

func (r *pgRepository) ReplaceEvidence(ctx context.Context, artifactDigestID int64, evidence []*DigestEvidence) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin replace evidence: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM digest_evidence WHERE artifact_digest_id = $1`, artifactDigestID); err != nil {
		return fmt.Errorf("delete digest evidence: %w", err)
	}

	const ins = `
		INSERT INTO digest_evidence
		    (artifact_digest_id, type, name, digest, media_type, artifact_type, annotations)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (artifact_digest_id, digest) DO NOTHING
		RETURNING id, created_at`
	for _, ev := range evidence {
		annotations, err := json.Marshal(ev.Annotations)
		if err != nil {
			return fmt.Errorf("marshal evidence annotations: %w", err)
		}
		if err := tx.QueryRowContext(ctx, ins,
			artifactDigestID, string(ev.Type), ev.Name, ev.Digest,
			ev.MediaType, ev.ArtifactType, annotations,
		).Scan(&ev.ID, &ev.CreatedAt); err != nil {
			return fmt.Errorf("insert digest evidence: %w", err)
		}
		ev.ArtifactDigestID = artifactDigestID
	}

	return tx.Commit()
}

func (r *pgRepository) GetSummaries(ctx context.Context) (map[int64]*RepositorySummary, error) {
	result := make(map[int64]*RepositorySummary)

	// Load digest counts and discovery status per item.
	const digestQ = `
		SELECT inventory_item_id,
		       COUNT(*) AS digest_count,
		       COALESCE(MAX(last_discovered_at), '0001-01-01T00:00:00Z'::timestamptz) AS last_discovered_at,
		       CASE
		           WHEN bool_or(discovery_status = 'failed')  THEN 'failed'
		           WHEN bool_or(discovery_status = 'warning') THEN 'warning'
		           WHEN bool_or(discovery_status = 'success') THEN 'success'
		           ELSE 'pending'
		       END AS overall_status
		FROM artifact_digests
		GROUP BY inventory_item_id`
	rows, err := r.db.QueryContext(ctx, digestQ)
	if err != nil {
		return nil, fmt.Errorf("get digest summaries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		s := &RepositorySummary{}
		var status string
		if err := rows.Scan(&s.InventoryItemID, &s.DigestCount, &s.LastDiscoveredAt, &status); err != nil {
			return nil, fmt.Errorf("scan digest summary: %w", err)
		}
		s.OverallStatus = DiscoveryStatus(status)
		result[s.InventoryItemID] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load tag counts per item.
	const tagQ = `SELECT inventory_item_id, COUNT(*) FROM repository_tags GROUP BY inventory_item_id`
	tagRows, err := r.db.QueryContext(ctx, tagQ)
	if err != nil {
		return nil, fmt.Errorf("get tag summaries: %w", err)
	}
	defer tagRows.Close()
	for tagRows.Next() {
		var itemID int64
		var count int
		if err := tagRows.Scan(&itemID, &count); err != nil {
			return nil, fmt.Errorf("scan tag summary: %w", err)
		}
		if s, ok := result[itemID]; ok {
			s.TagCount = count
		} else {
			result[itemID] = &RepositorySummary{InventoryItemID: itemID, TagCount: count}
		}
	}
	return result, tagRows.Err()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// inClause builds "$1,$2,$3,…" for n positional parameters starting at $1.
func inClause(n int) string {
	if n == 0 {
		return ""
	}
	b := make([]byte, 0, n*4)
	for i := 1; i <= n; i++ {
		if i > 1 {
			b = append(b, ',')
		}
		b = append(b, '$')
		b = appendInt(b, i)
	}
	return string(b)
}

func appendInt(b []byte, n int) []byte {
	if n < 10 {
		return append(b, byte('0'+n))
	}
	b = appendInt(b, n/10)
	return append(b, byte('0'+n%10))
}

func int64Slice(ids []int64) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}


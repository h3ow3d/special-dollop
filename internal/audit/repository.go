package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Repository defines persistence for audit entries.
type Repository interface {
	Record(ctx context.Context, e *Entry) error
	ListByUser(ctx context.Context, userID int64, limit int) ([]*Entry, error)
}

type pgRepository struct{ db *sql.DB }

// NewRepository returns a PostgreSQL-backed Repository.
func NewRepository(db *sql.DB) Repository { return &pgRepository{db: db} }

func (r *pgRepository) Record(ctx context.Context, e *Entry) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("marshal detail: %w", err)
	}
	const q = `
		INSERT INTO audit_log (user_id, action, detail, ip_address)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`
	return r.db.QueryRowContext(ctx, q, e.UserID, string(e.Action), string(detail), e.IPAddress).
		Scan(&e.ID, &e.CreatedAt)
}

func (r *pgRepository) ListByUser(ctx context.Context, userID int64, limit int) ([]*Entry, error) {
	const q = `
		SELECT id, user_id, action, detail, ip_address, created_at
		FROM audit_log WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`
	rows, err := r.db.QueryContext(ctx, q, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit: %w", err)
	}
	defer rows.Close()
	var entries []*Entry
	for rows.Next() {
		e := &Entry{}
		var detailJSON []byte
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &detailJSON, &e.IPAddress, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		_ = json.Unmarshal(detailJSON, &e.Detail)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

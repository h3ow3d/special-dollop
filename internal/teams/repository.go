package teams

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotFound is returned when the requested team does not exist.
var ErrNotFound = errors.New("team not found")

// Repository defines persistence operations for Team.
type Repository interface {
	Create(ctx context.Context, t *Team) error
	GetByID(ctx context.Context, id int64) (*Team, error)
	List(ctx context.Context) ([]*Team, error)
	SetActive(ctx context.Context, id int64, active bool) error
}

type pgRepository struct{ db *sql.DB }

// NewRepository returns a PostgreSQL-backed Repository.
func NewRepository(db *sql.DB) Repository { return &pgRepository{db: db} }

func (r *pgRepository) Create(ctx context.Context, t *Team) error {
	const q = `
		INSERT INTO teams (name, description, active)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at`
	return r.db.QueryRowContext(ctx, q, t.Name, t.Description, t.Active).
		Scan(&t.ID, &t.CreatedAt, &t.UpdatedAt)
}

func (r *pgRepository) GetByID(ctx context.Context, id int64) (*Team, error) {
	const q = `
		SELECT id, name, description, active, created_at, updated_at
		FROM teams WHERE id = $1`
	t := &Team{}
	err := r.db.QueryRowContext(ctx, q, id).
		Scan(&t.ID, &t.Name, &t.Description, &t.Active, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get team: %w", err)
	}
	return t, nil
}

func (r *pgRepository) List(ctx context.Context) ([]*Team, error) {
	const q = `
		SELECT id, name, description, active, created_at, updated_at
		FROM teams ORDER BY name`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	defer rows.Close()
	var ts []*Team
	for rows.Next() {
		t := &Team{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Active, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		ts = append(ts, t)
	}
	return ts, rows.Err()
}

func (r *pgRepository) SetActive(ctx context.Context, id int64, active bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE teams SET active=$1, updated_at=NOW() WHERE id=$2`, active, id)
	if err != nil {
		return fmt.Errorf("set team active: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

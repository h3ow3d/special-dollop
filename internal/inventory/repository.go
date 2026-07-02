package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotFound is returned when the requested inventory item does not exist.
var ErrNotFound = errors.New("inventory item not found")

// Repository defines persistence operations for InventoryItem.
type Repository interface {
	Create(ctx context.Context, item *InventoryItem) error
	GetByID(ctx context.Context, id int64) (*InventoryItem, error)
	Update(ctx context.Context, item *InventoryItem) error
	SetActive(ctx context.Context, id int64, active bool) error
	List(ctx context.Context) ([]*InventoryItemWithTeam, error)
	ListByTeam(ctx context.Context, teamID int64) ([]*InventoryItemWithTeam, error)
	CountByTeam(ctx context.Context) (map[int64]int, error)
}

type pgRepository struct{ db *sql.DB }

// NewRepository returns a PostgreSQL-backed Repository.
func NewRepository(db *sql.DB) Repository { return &pgRepository{db: db} }

func (r *pgRepository) Create(ctx context.Context, item *InventoryItem) error {
	const q = `
		INSERT INTO inventory_items
		    (name, description, team_id, registry, package_url, package_name, repository_url, active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at, updated_at`
	return r.db.QueryRowContext(ctx, q,
		item.Name, item.Description, item.TeamID,
		item.Registry, item.PackageURL, item.PackageName, item.RepositoryURL,
		item.Active,
	).Scan(&item.ID, &item.CreatedAt, &item.UpdatedAt)
}

func (r *pgRepository) GetByID(ctx context.Context, id int64) (*InventoryItem, error) {
	const q = `
		SELECT id, name, description, team_id, registry, package_url, package_name,
		       repository_url, active, created_at, updated_at
		FROM inventory_items WHERE id = $1`
	item := &InventoryItem{}
	err := r.db.QueryRowContext(ctx, q, id).Scan(
		&item.ID, &item.Name, &item.Description, &item.TeamID,
		&item.Registry, &item.PackageURL, &item.PackageName, &item.RepositoryURL,
		&item.Active, &item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get inventory item: %w", err)
	}
	return item, nil
}

func (r *pgRepository) Update(ctx context.Context, item *InventoryItem) error {
	const q = `
		UPDATE inventory_items
		SET name=$1, description=$2, registry=$3, package_url=$4,
		    package_name=$5, repository_url=$6, updated_at=NOW()
		WHERE id=$7
		RETURNING updated_at`
	err := r.db.QueryRowContext(ctx, q,
		item.Name, item.Description, item.Registry,
		item.PackageURL, item.PackageName, item.RepositoryURL, item.ID,
	).Scan(&item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (r *pgRepository) SetActive(ctx context.Context, id int64, active bool) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE inventory_items SET active=$1, updated_at=NOW() WHERE id=$2`, active, id)
	if err != nil {
		return fmt.Errorf("set inventory item active: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const itemColumns = `
	i.id, i.name, i.description, i.team_id, i.registry, i.package_url,
	i.package_name, i.repository_url, i.active, i.created_at, i.updated_at,
	COALESCE(t.name, '')`

func scanItemWithTeam(row interface {
	Scan(dest ...any) error
}) (*InventoryItemWithTeam, error) {
	item := &InventoryItemWithTeam{}
	err := row.Scan(
		&item.ID, &item.Name, &item.Description, &item.TeamID,
		&item.Registry, &item.PackageURL, &item.PackageName, &item.RepositoryURL,
		&item.Active, &item.CreatedAt, &item.UpdatedAt,
		&item.TeamName,
	)
	return item, err
}

func (r *pgRepository) List(ctx context.Context) ([]*InventoryItemWithTeam, error) {
	q := `SELECT ` + itemColumns + `
		FROM inventory_items i
		LEFT JOIN teams t ON t.id = i.team_id
		ORDER BY t.name, i.name`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list inventory items: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

func (r *pgRepository) ListByTeam(ctx context.Context, teamID int64) ([]*InventoryItemWithTeam, error) {
	q := `SELECT ` + itemColumns + `
		FROM inventory_items i
		LEFT JOIN teams t ON t.id = i.team_id
		WHERE i.team_id = $1
		ORDER BY i.name`
	rows, err := r.db.QueryContext(ctx, q, teamID)
	if err != nil {
		return nil, fmt.Errorf("list inventory items by team: %w", err)
	}
	defer rows.Close()
	return scanRows(rows)
}

func (r *pgRepository) CountByTeam(ctx context.Context) (map[int64]int, error) {
	const q = `
		SELECT team_id, COUNT(*) FROM inventory_items WHERE active = TRUE GROUP BY team_id`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("count inventory by team: %w", err)
	}
	defer rows.Close()
	counts := make(map[int64]int)
	for rows.Next() {
		var teamID int64
		var count int
		if err := rows.Scan(&teamID, &count); err != nil {
			return nil, fmt.Errorf("scan inventory count: %w", err)
		}
		counts[teamID] = count
	}
	return counts, rows.Err()
}

func scanRows(rows *sql.Rows) ([]*InventoryItemWithTeam, error) {
	var items []*InventoryItemWithTeam
	for rows.Next() {
		item, err := scanItemWithTeam(rows)
		if err != nil {
			return nil, fmt.Errorf("scan inventory item: %w", err)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

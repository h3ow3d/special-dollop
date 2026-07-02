package users

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a requested entity does not exist.
var ErrNotFound = errors.New("not found")

// UserRepository defines persistence operations for User.
type UserRepository interface {
	Upsert(ctx context.Context, u *User) error
	GetByGitHubUserID(ctx context.Context, githubUserID int64) (*User, error)
	GetByID(ctx context.Context, id int64) (*User, error)
	List(ctx context.Context) ([]*User, error)
	UpdateRoleAndTeam(ctx context.Context, userID, roleID int64, teamID *int64) error
	SetActive(ctx context.Context, userID int64, active bool) error
}

// RoleRepository defines read operations for Role.
type RoleRepository interface {
	GetBySlug(ctx context.Context, slug string) (*Role, error)
	List(ctx context.Context) ([]*Role, error)
}

// pgUserRepository is the PostgreSQL implementation of UserRepository.
type pgUserRepository struct{ db *sql.DB }

// NewUserRepository returns a PostgreSQL-backed UserRepository.
func NewUserRepository(db *sql.DB) UserRepository { return &pgUserRepository{db: db} }

func (r *pgUserRepository) Upsert(ctx context.Context, u *User) error {
	const q = `
		INSERT INTO users (github_user_id, github_username, display_name, email, avatar_url, role_id, team_id, active, last_login_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (github_user_id) DO UPDATE SET
			github_username = EXCLUDED.github_username,
			display_name    = EXCLUDED.display_name,
			email           = EXCLUDED.email,
			avatar_url      = EXCLUDED.avatar_url,
			last_login_at   = EXCLUDED.last_login_at,
			updated_at      = NOW()
		RETURNING id, created_at, updated_at, active, role_id, team_id`

	now := time.Now().UTC()
	u.LastLoginAt = &now

	return r.db.QueryRowContext(ctx, q,
		u.GitHubUserID, u.GitHubUsername, u.DisplayName, u.Email, u.AvatarURL,
		u.RoleID, u.TeamID, u.Active, u.LastLoginAt,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt, &u.Active, &u.RoleID, &u.TeamID)
}

func (r *pgUserRepository) GetByGitHubUserID(ctx context.Context, githubUserID int64) (*User, error) {
	const q = `
		SELECT id, github_user_id, github_username, display_name, email, avatar_url,
		       role_id, team_id, active, created_at, updated_at, last_login_at
		FROM users WHERE github_user_id = $1`
	return scanUser(r.db.QueryRowContext(ctx, q, githubUserID))
}

func (r *pgUserRepository) GetByID(ctx context.Context, id int64) (*User, error) {
	const q = `
		SELECT id, github_user_id, github_username, display_name, email, avatar_url,
		       role_id, team_id, active, created_at, updated_at, last_login_at
		FROM users WHERE id = $1`
	return scanUser(r.db.QueryRowContext(ctx, q, id))
}

func (r *pgUserRepository) List(ctx context.Context) ([]*User, error) {
	const q = `
		SELECT id, github_user_id, github_username, display_name, email, avatar_url,
		       role_id, team_id, active, created_at, updated_at, last_login_at
		FROM users ORDER BY display_name, github_username`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *pgUserRepository) UpdateRoleAndTeam(ctx context.Context, userID, roleID int64, teamID *int64) error {
	const q = `UPDATE users SET role_id=$1, team_id=$2, updated_at=NOW() WHERE id=$3`
	res, err := r.db.ExecContext(ctx, q, roleID, teamID, userID)
	if err != nil {
		return fmt.Errorf("update role/team: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *pgUserRepository) SetActive(ctx context.Context, userID int64, active bool) error {
	const q = `UPDATE users SET active=$1, updated_at=NOW() WHERE id=$2`
	res, err := r.db.ExecContext(ctx, q, active, userID)
	if err != nil {
		return fmt.Errorf("set active: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// row is a common interface for *sql.Row and *sql.Rows Scan.
type row interface {
	Scan(dest ...any) error
}

func scanUser(r row) (*User, error) {
	u := &User{}
	err := r.Scan(
		&u.ID, &u.GitHubUserID, &u.GitHubUsername, &u.DisplayName, &u.Email, &u.AvatarURL,
		&u.RoleID, &u.TeamID, &u.Active, &u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}

// pgRoleRepository is the PostgreSQL implementation of RoleRepository.
type pgRoleRepository struct{ db *sql.DB }

// NewRoleRepository returns a PostgreSQL-backed RoleRepository.
func NewRoleRepository(db *sql.DB) RoleRepository { return &pgRoleRepository{db: db} }

func (r *pgRoleRepository) GetBySlug(ctx context.Context, slug string) (*Role, error) {
	role := &Role{}
	err := r.db.QueryRowContext(ctx, `SELECT id, name, slug FROM roles WHERE slug=$1`, slug).
		Scan(&role.ID, &role.Name, &role.Slug)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get role by slug: %w", err)
	}
	return role, nil
}

func (r *pgRoleRepository) List(ctx context.Context) ([]*Role, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, slug FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	var roles []*Role
	for rows.Next() {
		role := &Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.Slug); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// Package database manages the PostgreSQL connection pool and schema migrations.
package database

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // registers "pgx" driver for database/sql
)

// Open opens a PostgreSQL connection pool via the pgx stdlib driver and verifies
// connectivity with a ping.
func Open(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("database open: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("database ping: %w", err)
	}
	return db, nil
}

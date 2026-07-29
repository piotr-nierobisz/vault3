package database

import (
	"context"
	"database/sql"
)

// DbTx is the minimum query interface satisfied by both *sql.DB and *sql.Tx.
// Database functions take this rather than *runtime.Runtime so the database
// package does not depend on runtime (which would create an import cycle:
// runtime → database → runtime). Callers pass rt.GetDb(), which returns the
// pooled connection normally and the active transaction inside
// runtime.WithTransaction.
type DbTx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// nullIfEmptyString maps "" to SQL NULL for optional text columns.
func nullIfEmptyString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

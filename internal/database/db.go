package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// ErrNoRowsAffected reports that a write matched no row.
//
// This package's convention is that handlers authorise and these functions
// then mutate by id (see the comments on SelectItemByID and friends). That
// keeps the SQL simple, but it means a forgotten authorisation check would
// otherwise produce a write that quietly changes nothing and still returns
// 200 — indistinguishable from success at every layer above. Treating "no row
// matched" as an error turns that class of mistake into a loud 500 instead of
// a silent lie, so it can never be mistaken for a completed mutation.
//
// Only for writes whose WHERE clause is pure identity, where matching nothing
// means the target does not exist. Several writes legitimately affect zero
// rows and must NOT use it:
//
//   - the revoke helpers (share link, vault invite) carry an "IS NULL" guard
//     precisely so a second revoke is a harmless no-op;
//   - DeleteOtherUserSessions matches nothing whenever the account has only
//     the current session, which is the common case;
//   - DeleteSessionByTokenHash / DeleteSessionByID keep logout and revocation
//     idempotent against an already-expired row;
//   - MarkNotificationRead(All) re-marks what is already read;
//   - TouchSessionLastSeen is best-effort and its row may expire mid-request;
//   - the scheduler's purges are bulk sweeps that normally find nothing.
//
// Adding the guard to one of those would turn an ordinary outcome into a 500.
var ErrNoRowsAffected = errors.New("no rows affected")

// execExpectingRow runs a write that must touch at least one row, wrapping
// both the driver error and the zero-row case with the operation name.
func execExpectingRow(ctx context.Context, db DbTx, sqlStr string, args []any, operation string) error {
	result, execErr := db.ExecContext(ctx, sqlStr, args...)
	if execErr != nil {
		return fmt.Errorf("%s: %w", operation, execErr)
	}
	affected, affectedErr := result.RowsAffected()
	if affectedErr != nil {
		return fmt.Errorf("%s: read rows affected: %w", operation, affectedErr)
	}
	if affected == 0 {
		return fmt.Errorf("%s: %w", operation, ErrNoRowsAffected)
	}
	return nil
}

// nullIfEmptyString maps "" to SQL NULL for optional text columns.
func nullIfEmptyString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

package runtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// WithTransaction executes fn inside a single database transaction.
//
// fn receives a shallow copy of rt with Runtime.TX set so that GetDb()
// returns the active *sql.Tx. The original rt is never mutated, which keeps
// concurrent callers isolated from each other.
//
// Use it every time more than one table must change in sequence. Do not pass
// *sql.Tx through signatures, do not set/clear Runtime.TX outside this
// helper, and keep transactions short — no slow external calls inside them.
//
// Lives in the runtime package (rather than database) because it is the only
// helper that must take and copy a concrete *Runtime — keeping it here lets
// database/* stay free of the runtime import.
func WithTransaction(
	rt *Runtime,
	ctx context.Context,
	fn func(txRt *Runtime) error,
) error {
	tx, beginErr := rt.DB.BeginTx(ctx, nil)
	if beginErr != nil {
		return fmt.Errorf("begin transaction: %w", beginErr)
	}

	txRt := *rt
	txRt.TX = tx

	if fnErr := fn(&txRt); fnErr != nil {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			rt.Log.Error("transaction rollback failed", zap.Error(rbErr))
			return fmt.Errorf("transaction failed: %w; rollback failed: %w", fnErr, rbErr)
		}
		return fnErr
	}

	if commitErr := tx.Commit(); commitErr != nil {
		return fmt.Errorf("commit transaction: %w", commitErr)
	}

	return nil
}

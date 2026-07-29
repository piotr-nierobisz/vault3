package runtime

import (
	"context"
	"database/sql"
	"fmt"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/view"

	"github.com/Masterminds/squirrel"
	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// Runtime is the single dependency-injection container: every application
// dependency lives here and is passed as *Runtime, never a global. Page
// handlers, API handlers, and security-layer handlers are methods on it.
type Runtime struct {
	Log     *zap.Logger
	DB      *sql.DB
	Builder squirrel.StatementBuilderType
	Config  *config.Config
	TX      *sql.Tx
	// Cipher is the server-side field encryptor (internal/crypto): display
	// names, session IP/UA, TOTP secrets. Vault data never touches it.
	Cipher *crypto.FieldCipher
	// Lookups bundles reference-table snapshots used by the view layer to
	// shape data for templates. Populated once at startup; restart to pick
	// up reference edits.
	Lookups *view.Lookups
	// Signals is the in-process change-signal hub behind /events: mutations
	// publish the user's new revision and every other connected client is
	// told to refresh. Nil in the worker process (no HTTP clients to tell).
	Signals *SignalHub
}

// Start bootstraps the runtime for the web process: it owns the dev schema
// sync so the database is migrated before the server accepts traffic.
func Start() *Runtime {
	return start(true)
}

// StartWorker bootstraps the runtime for a background worker (the job
// scheduler in cmd/scheduler): the same config, logger, DB pool and lookups
// as the web process, but it never runs the dev schema sync. The web process
// owns schema application; a worker that also synced could race it on first
// boot.
func StartWorker() *Runtime {
	return start(false)
}

func start(syncSchema bool) *Runtime {
	cfg := config.Start()

	production := cfg.MustBool("PRODUCTION_BOOL")

	logger, err := newLogger(production)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}

	dsn := cfg.MustString("POSTGRES_DSN_STRING")
	builder := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic(fmt.Sprintf("failed to open database connection: %v", err))
	}

	if err := db.Ping(); err != nil {
		panic(fmt.Sprintf("failed to ping database: %v", err))
	}

	if syncSchema && !production {
		cfg.SyncDatabaseSchema(db, logger)
	}

	cipher, cipherErr := crypto.NewFieldCipher(cfg.MustString("SERVER_ENCRYPTION_KEY_STRING"))
	if cipherErr != nil {
		panic(fmt.Sprintf("failed to initialise field cipher: %v", cipherErr))
	}

	lookups, lookupsErr := view.NewLookups(context.Background(), db, &builder)
	if lookupsErr != nil {
		panic(fmt.Sprintf("failed to load view lookups: %v", lookupsErr))
	}

	logger.Info("runtime initialized", zap.Bool("production", production))
	return &Runtime{
		Log:     logger,
		DB:      db,
		Builder: builder,
		Config:  cfg,
		TX:      nil,
		Cipher:  cipher,
		Lookups: lookups,
		Signals: NewSignalHub(),
	}
}

func (r *Runtime) Stop() {
	r.Log.Info("stopping runtime")
	r.DB.Close()
	r.Log.Sync()
}

// GetDb returns whichever query executor is currently active: the connection
// pool by default, or the transaction handle when called inside
// WithTransaction. The result type is database.DbTx so it can be passed
// directly into functions in internal/database without further conversion.
func (r *Runtime) GetDb() database.DbTx {
	if r.TX != nil {
		return r.TX
	}
	return r.DB
}

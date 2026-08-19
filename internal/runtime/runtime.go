package runtime

import (
	"context"
	"database/sql"
	"fmt"

	"vault3/internal/config"
	"vault3/internal/crypto"
	"vault3/internal/database"
	"vault3/internal/integrations"
	"vault3/internal/view"

	"github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	bungo "github.com/piotr-nierobisz/BunGo"
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
	// Integrations holds every third-party client (internal/integrations).
	// Credentials are read once, here, so no handler reaches for r.Config to
	// talk to a vendor — and the field is the complete list of who this
	// deployment calls out to.
	Integrations *integrations.Clients
	// Signals is the WebSocket hub behind the change-signal route: mutations
	// publish the user's new revision and every other connected client is
	// told to refresh. Owned by BunGo and handed over by main.go when it
	// registers the route, so it stays nil in the worker process (no HTTP
	// clients to tell) and until the web process has registered its routes.
	Signals *bungo.WebSocketHub
}

// Start bootstraps the runtime for the web process: it owns the dev schema
// sync so the database is migrated before the server accepts traffic, and it
// applies the optional admin bootstrap afterwards (the grant needs the schema
// in place, and only the process serving the console has any use for it).
func Start() *Runtime {
	rt := start(true)
	rt.bootstrapAdmin(context.Background())
	return rt
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
		Log:          logger,
		DB:           db,
		Builder:      builder,
		Config:       cfg,
		TX:           nil,
		Cipher:       cipher,
		Lookups:      lookups,
		Integrations: newIntegrations(cfg),
	}
}

// newIntegrations resolves every third-party credential from config and hands
// the values to internal/integrations. It is the one place env keys and
// vendors meet: integrations/ imports neither config nor runtime, the same
// way database/ imports neither, so the wiring has to be stated somewhere and
// this is the somewhere.
//
// The Mailgun trio is read with LookupString because it is deliberately
// optional — the client reports itself unconfigured and email degrades to a
// logged skip (see SendTemplateEmail). Turnstile takes Cloudflare's published
// test pair outside production, so dev runs the real widget and the real
// siteverify round-trip without holding the deployment secret.
func newIntegrations(cfg *config.Config) *integrations.Clients {
	siteKey, secretKey := integrations.TurnstileTestSiteKey, integrations.TurnstileTestSecretKey
	if cfg.MustBool("PRODUCTION_BOOL") {
		siteKey = cfg.MustString(config.TurnstileSiteKeyEnv)
		secretKey = cfg.MustString(config.TurnstileSecretKeyEnv)
	}

	apiKey, _ := cfg.LookupString(config.MailgunAPIKeyEnv)
	domain, _ := cfg.LookupString(config.MailgunDomainEnv)
	fromEmail, _ := cfg.LookupString(config.MailgunFromEmailEnv)

	return integrations.New(integrations.Config{
		MailgunAPIKey:      apiKey,
		MailgunDomain:      domain,
		MailgunFromEmail:   fromEmail,
		MailgunFromName:    config.SITE_NAME,
		TurnstileSiteKey:   siteKey,
		TurnstileSecretKey: secretKey,
	})
}

// newUUID returns a fresh UUIDv7 string. Generation panics only if the OS
// entropy source is broken, which no request in a password manager should
// limp past: a dead RNG must stop the process, not quietly skip the row it
// was minting an id for.
func newUUID() string {
	return uuid.Must(uuid.NewV7()).String()
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

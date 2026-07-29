package config

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

func (*Config) SyncDatabaseSchema(db *sql.DB, log *zap.Logger) {

	for i := 1; i <= LATEST_SQL_SCRIPT_VERSION; i++ {
		name := fmt.Sprintf("%03d.sql", i)
		p := filepath.Join(SQLScriptsDir, name)
		body, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			panic(fmt.Sprintf("SyncDatabaseSchema: read %s: %v", p, err))
		}
		query := strings.TrimSpace(string(body))
		if query == "" {
			panic(fmt.Sprintf("SyncDatabaseSchema: %s is empty", p))
		}

		log.Info("executing SQL script (dev)", zap.Int("script", i), zap.String("path", p))
		if _, err := db.Exec(query); err != nil {
			panic(fmt.Sprintf("SyncDatabaseSchema: execute %s: %v", p, err))
		}
	}

	log.Info("dev SQL scripts applied", zap.Int("through", LATEST_SQL_SCRIPT_VERSION))
}

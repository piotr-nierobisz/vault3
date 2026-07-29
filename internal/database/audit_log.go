package database

import (
	"context"
	"fmt"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// InsertAuditLog appends one security-trail row, encrypting IP, user agent
// and the detail blob at rest. Callers treat failures as log-and-continue:
// the audit trail must never take down the action it describes.
func InsertAuditLog(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	entry *models.AuditLog,
) error {
	ipEnc, ipErr := cipher.EncryptString(entry.IPAddress)
	if ipErr != nil {
		return fmt.Errorf("encrypt audit ip: %w", ipErr)
	}
	uaEnc, uaErr := cipher.EncryptString(entry.UserAgent)
	if uaErr != nil {
		return fmt.Errorf("encrypt audit user agent: %w", uaErr)
	}
	detailEnc, detailErr := cipher.EncryptString(entry.Detail)
	if detailErr != nil {
		return fmt.Errorf("encrypt audit detail: %w", detailErr)
	}

	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_audit_log"`).
		Columns(
			`"Vault3AuditLogID"`,
			`"Vault3AuditLogUserID"`,
			`"Vault3AuditLogAction"`,
			`"Vault3AuditLogEntityType"`,
			`"Vault3AuditLogEntityID"`,
			`"Vault3AuditLogIpAddressEnc"`,
			`"Vault3AuditLogUserAgentEnc"`,
			`"Vault3AuditLogDetailEnc"`,
		).
		Values(
			entry.ID,
			nullIfEmptyString(entry.UserID),
			entry.Action,
			nullIfEmptyString(entry.EntityType),
			nullIfEmptyString(entry.EntityID),
			nullIfEmptyString(ipEnc),
			nullIfEmptyString(uaEnc),
			nullIfEmptyString(detailEnc),
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert audit log: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert audit log: %w", execErr)
	}
	return nil
}

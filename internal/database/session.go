package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// InsertSession persists a new session row. The opaque token itself is never
// stored; only its hash (caller-supplied) is. IP and user agent are encrypted
// through the cipher here, and the IP blind is derived alongside so
// new-device checks can match without decrypting.
func InsertSession(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	session *models.Session,
) error {
	ipEnc, ipErr := cipher.EncryptString(session.IPAddress)
	if ipErr != nil {
		return fmt.Errorf("encrypt session ip: %w", ipErr)
	}
	uaEnc, uaErr := cipher.EncryptString(session.UserAgent)
	if uaErr != nil {
		return fmt.Errorf("encrypt session user agent: %w", uaErr)
	}
	ipHash := ""
	if session.IPAddress != "" {
		ipHash = cipher.Blind(session.IPAddress)
	}

	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_session"`).
		Columns(
			`"Vault3SessionID"`,
			`"Vault3SessionTokenHash"`,
			`"Vault3SessionUserID"`,
			`"Vault3SessionIpAddressEnc"`,
			`"Vault3SessionIpHash"`,
			`"Vault3SessionUserAgentEnc"`,
			`"Vault3SessionExpiresAt"`,
		).
		Values(
			session.ID,
			session.TokenHash,
			session.UserID,
			nullIfEmptyString(ipEnc),
			nullIfEmptyString(ipHash),
			nullIfEmptyString(uaEnc),
			session.ExpiresAt,
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert session: %w", sqlErr)
	}

	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert session: %w", execErr)
	}
	return nil
}

// SelectSessionByTokenHash returns the live (non-expired) session matching
// the supplied token hash, with IP/UA decrypted for display. Returns
// sql.ErrNoRows if no live row matches.
func SelectSessionByTokenHash(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	tokenHash string,
) (*models.Session, error) {
	sqlStr, args, sqlErr := sessionSelect(builder).
		Where(sq.Eq{`"Vault3SessionTokenHash"`: tokenHash}).
		Where(sq.Expr(`"Vault3SessionExpiresAt" > now()`)).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build select session: %w", sqlErr)
	}

	s, scanErr := scanSession(db.QueryRowContext(ctx, sqlStr, args...), cipher)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("select session: %w", scanErr)
	}
	return s, nil
}

// SelectUserSessions lists the user's live sessions, newest first, for the
// active-sessions panel on the profile page.
func SelectUserSessions(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userID string,
) ([]models.Session, error) {
	sqlStr, args, sqlErr := sessionSelect(builder).
		Where(sq.Eq{`"Vault3SessionUserID"`: userID}).
		Where(sq.Expr(`"Vault3SessionExpiresAt" > now()`)).
		OrderBy(`"Vault3SessionLastSeenAt" DESC`).
		ToSql()
	if sqlErr != nil {
		return nil, fmt.Errorf("build select user sessions: %w", sqlErr)
	}

	rows, queryErr := db.QueryContext(ctx, sqlStr, args...)
	if queryErr != nil {
		return nil, fmt.Errorf("select user sessions: %w", queryErr)
	}
	defer rows.Close()

	out := make([]models.Session, 0)
	for rows.Next() {
		s, scanErr := scanSession(rows, cipher)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, *s)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, rowsErr
	}
	return out, nil
}

// UserHasSessionFromIP reports whether the user already holds a live session
// from this IP (matched via the deterministic blind), which is how a sign-in
// decides whether to raise the new-device security alert.
func UserHasSessionFromIP(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	userID string,
	ipAddress string,
) (bool, error) {
	if ipAddress == "" {
		return false, nil
	}
	sqlStr, args, sqlErr := builder.
		Select(`1`).
		From(`"vault3_session"`).
		Where(sq.Eq{
			`"Vault3SessionUserID"`: userID,
			`"Vault3SessionIpHash"`: cipher.Blind(ipAddress),
		}).
		Where(sq.Expr(`"Vault3SessionExpiresAt" > now()`)).
		Limit(1).
		ToSql()
	if sqlErr != nil {
		return false, fmt.Errorf("build session ip check: %w", sqlErr)
	}
	var one int
	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&one)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("session ip check: %w", scanErr)
	}
	return true, nil
}

// TouchSessionLastSeen bumps the LastSeenAt timestamp to now. Best-effort:
// callers may log-and-ignore the error to avoid failing a request on a noisy
// update.
func TouchSessionLastSeen(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	sessionID string,
) error {
	sqlStr, args, sqlErr := builder.
		Update(`"vault3_session"`).
		Set(`"Vault3SessionLastSeenAt"`, sq.Expr(`now()`)).
		Where(sq.Eq{`"Vault3SessionID"`: sessionID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build touch session: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("touch session: %w", execErr)
	}
	return nil
}

// DeleteSessionByTokenHash removes the matching session row (used for
// logout). Returns nil whether or not a row was present.
func DeleteSessionByTokenHash(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	tokenHash string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_session"`).
		Where(sq.Eq{`"Vault3SessionTokenHash"`: tokenHash}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete session: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("delete session: %w", execErr)
	}
	return nil
}

// DeleteSessionByID revokes one session, scoped to its owner so a request
// can never revoke another account's session.
func DeleteSessionByID(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	sessionID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_session"`).
		Where(sq.Eq{
			`"Vault3SessionID"`:     sessionID,
			`"Vault3SessionUserID"`: userID,
		}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build revoke session: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("revoke session: %w", execErr)
	}
	return nil
}

// DeleteOtherUserSessions revokes every session except the given one — the
// post-password-change sweep that signs out all other devices.
func DeleteOtherUserSessions(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	userID string,
	keepSessionID string,
) error {
	sqlStr, args, sqlErr := builder.
		Delete(`"vault3_session"`).
		Where(sq.Eq{`"Vault3SessionUserID"`: userID}).
		Where(sq.NotEq{`"Vault3SessionID"`: keepSessionID}).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build delete other sessions: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("delete other sessions: %w", execErr)
	}
	return nil
}

// SelectUserAuthKeyHash returns the auth-key bcrypt hash for an active,
// unarchived user looked up by email. Returns sql.ErrNoRows when no live
// user has that email.
func SelectUserAuthKeyHash(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	email string,
) (userID string, authKeyHash string, err error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`u."Vault3UserID"`,
			`COALESCE(a."Vault3UserAuthAuthKeyHash", '')`,
		).
		From(`"vault3_user" u`).
		LeftJoin(`"vault3_user_auth" a ON a."Vault3UserAuthUserID" = u."Vault3UserID"`).
		Where(sq.Eq{
			`u."Vault3UserEmail"`:    email,
			`u."Vault3UserIsActive"`: true,
		}).
		Where(sq.Expr(`u."Vault3UserArchivedAt" IS NULL`)).
		ToSql()
	if sqlErr != nil {
		return "", "", fmt.Errorf("build select user auth key hash: %w", sqlErr)
	}

	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&userID, &authKeyHash)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", "", sql.ErrNoRows
		}
		return "", "", fmt.Errorf("select user auth key hash: %w", scanErr)
	}
	return userID, authKeyHash, nil
}

// SelectKdfParamsByEmail returns the public unlock parameters for an active
// account. Returns sql.ErrNoRows when no live user has that email — the
// caller substitutes deterministic decoys so the response never reveals
// whether an account exists.
func SelectKdfParamsByEmail(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	email string,
) (kdfSalt string, kdfIterations int, err error) {
	sqlStr, args, sqlErr := builder.
		Select(
			`a."Vault3UserAuthKdfSalt"`,
			`a."Vault3UserAuthKdfIterations"`,
		).
		From(`"vault3_user" u`).
		Join(`"vault3_user_auth" a ON a."Vault3UserAuthUserID" = u."Vault3UserID"`).
		Where(sq.Eq{
			`u."Vault3UserEmail"`:    email,
			`u."Vault3UserIsActive"`: true,
		}).
		Where(sq.Expr(`u."Vault3UserArchivedAt" IS NULL`)).
		ToSql()
	if sqlErr != nil {
		return "", 0, fmt.Errorf("build select kdf params: %w", sqlErr)
	}

	scanErr := db.QueryRowContext(ctx, sqlStr, args...).Scan(&kdfSalt, &kdfIterations)
	if scanErr != nil {
		if errors.Is(scanErr, sql.ErrNoRows) {
			return "", 0, sql.ErrNoRows
		}
		return "", 0, fmt.Errorf("select kdf params: %w", scanErr)
	}
	return kdfSalt, kdfIterations, nil
}

// sessionSelect is the shared projection for session reads.
func sessionSelect(builder *sq.StatementBuilderType) sq.SelectBuilder {
	return builder.
		Select(
			`"Vault3SessionID"`,
			`"Vault3SessionTokenHash"`,
			`COALESCE("Vault3SessionUserID"::text, '')`,
			`COALESCE("Vault3SessionIpAddressEnc", '')`,
			`COALESCE("Vault3SessionUserAgentEnc", '')`,
			`"Vault3SessionExpiresAt"`,
			`"Vault3SessionCreatedAt"`,
			`"Vault3SessionLastSeenAt"`,
		).
		From(`"vault3_session"`)
}

// rowScanner covers *sql.Row and *sql.Rows for the shared session scanner.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanSession(row rowScanner, cipher *crypto.FieldCipher) (*models.Session, error) {
	s := &models.Session{}
	var ipEnc, uaEnc string
	scanErr := row.Scan(
		&s.ID,
		&s.TokenHash,
		&s.UserID,
		&ipEnc,
		&uaEnc,
		&s.ExpiresAt,
		&s.CreatedAt,
		&s.LastSeenAt,
	)
	if scanErr != nil {
		return nil, scanErr
	}
	ip, ipErr := cipher.DecryptString(ipEnc)
	if ipErr != nil {
		return nil, fmt.Errorf("decrypt session ip: %w", ipErr)
	}
	ua, uaErr := cipher.DecryptString(uaEnc)
	if uaErr != nil {
		return nil, fmt.Errorf("decrypt session user agent: %w", uaErr)
	}
	s.IPAddress = ip
	s.UserAgent = ua
	return s, nil
}

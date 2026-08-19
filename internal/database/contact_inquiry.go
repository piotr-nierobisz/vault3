package database

import (
	"context"
	"fmt"

	"vault3/internal/crypto"
	"vault3/internal/models"

	sq "github.com/Masterminds/squirrel"
)

// InsertContactInquiry stores one contact-form submission, encrypting the
// requester's IP and user agent at rest. Name, email and message are stored
// in the clear: they are what the sender chose to tell us, and the admin
// console has to read them back to reply.
//
// The reads for this table (SelectContactInquiries, SetContactInquiryHandled)
// live in admin.go, where the rest of the console's queries are.
func InsertContactInquiry(
	ctx context.Context,
	db DbTx,
	builder *sq.StatementBuilderType,
	cipher *crypto.FieldCipher,
	inquiry *models.ContactInquiry,
) error {
	ipEnc, ipErr := cipher.EncryptString(inquiry.IPAddress)
	if ipErr != nil {
		return fmt.Errorf("encrypt contact ip: %w", ipErr)
	}
	uaEnc, uaErr := cipher.EncryptString(inquiry.UserAgent)
	if uaErr != nil {
		return fmt.Errorf("encrypt contact user agent: %w", uaErr)
	}

	sqlStr, args, sqlErr := builder.
		Insert(`"vault3_contact_inquiry"`).
		Columns(
			`"Vault3ContactInquiryID"`,
			`"Vault3ContactInquiryName"`,
			`"Vault3ContactInquiryEmail"`,
			`"Vault3ContactInquiryMessage"`,
			`"Vault3ContactInquiryIpAddressEnc"`,
			`"Vault3ContactInquiryUserAgentEnc"`,
		).
		Values(
			inquiry.ID,
			inquiry.Name,
			inquiry.Email,
			inquiry.Message,
			nullIfEmptyString(ipEnc),
			nullIfEmptyString(uaEnc),
		).
		ToSql()
	if sqlErr != nil {
		return fmt.Errorf("build insert contact inquiry: %w", sqlErr)
	}
	if _, execErr := db.ExecContext(ctx, sqlStr, args...); execErr != nil {
		return fmt.Errorf("insert contact inquiry: %w", execErr)
	}
	return nil
}

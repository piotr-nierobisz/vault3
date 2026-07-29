package models

import "time"

// UserAuth mirrors vault3_user_auth (see scripts/sql/002.sql).
// Auth-sensitive fields split 1:1 from vault3_user so ordinary user reads do
// not load secrets. AuthKeyHash is bcrypt of the CLIENT-derived auth key —
// the Master Password itself never reaches the server. KdfSalt and
// KdfIterations are the public unlock parameters /api/v1/auth/params serves.
// The TwoFactor fields hold FieldCipher ciphertext as stored; the database
// layer decrypts them only for the handlers that need the TOTP secret.
type UserAuth struct {
	UserID                       string     `json:"userId" db:"Vault3UserAuthUserID"`
	AuthKeyHash                  string     `json:"-" db:"Vault3UserAuthAuthKeyHash"`
	KdfSalt                      string     `json:"kdfSalt,omitempty" db:"Vault3UserAuthKdfSalt"`
	KdfIterations                int        `json:"kdfIterations,omitempty" db:"Vault3UserAuthKdfIterations"`
	LastPasswordChangeAt         *time.Time `json:"lastPasswordChangeAt,omitempty" db:"Vault3UserAuthLastPasswordChangeAt"`
	TwoFactorSecretEnc           string     `json:"-" db:"Vault3UserAuthTwoFactorSecretEnc"`
	TempTwoFactorSecretEnc       string     `json:"-" db:"Vault3UserAuthTempTwoFactorSecretEnc"`
	EmailVerified                bool       `json:"emailVerified" db:"Vault3UserAuthEmailVerified"`
	EmailVerificationTokenHash   string     `json:"-" db:"Vault3UserAuthEmailVerificationTokenHash"`
	EmailVerificationTokenExpiry *time.Time `json:"-" db:"Vault3UserAuthEmailVerificationTokenExpiry"`
	AccountResetTokenHash        string     `json:"-" db:"Vault3UserAuthAccountResetTokenHash"`
	AccountResetTokenExpiry      *time.Time `json:"-" db:"Vault3UserAuthAccountResetTokenExpiry"`
	UpdatedAt                    time.Time  `json:"updatedAt" db:"Vault3UserAuthUpdatedAt"`
}

// TwoFactorEnabled reports whether a promoted TOTP secret is on file.
func (a *UserAuth) TwoFactorEnabled() bool {
	return a != nil && a.TwoFactorSecretEnc != ""
}

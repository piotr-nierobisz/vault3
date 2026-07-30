package models

import "time"

// KdfCosts are the per-account key-derivation parameters the browser needs
// before it can derive anything: PBKDF2 iterations plus the Argon2id costs
// layered over them (see web/lib/crypto.ts).
//
// They are stored per account rather than read from config at unlock time so
// the platform defaults can be raised whenever hardware allows without
// stranding accounts registered under the old ones — an account keeps
// deriving with the costs it was created with until its Master Password
// changes. Nothing here is secret: /api/v1/auth/params serves it publicly,
// because deriving the right key requires knowing which costs produced it.
type KdfCosts struct {
	KdfIterations   int `json:"kdfIterations"`
	Argon2MemoryKiB int `json:"argon2MemoryKiB"`
	Argon2Time      int `json:"argon2Time"`
	Argon2Lanes     int `json:"argon2Lanes"`
}

// UserAuth mirrors vault3_user_auth (see scripts/sql/002.sql and 008.sql).
// Auth-sensitive fields split 1:1 from vault3_user so ordinary user reads do
// not load secrets. AuthKeyHash is Argon2id over the CLIENT-derived auth key —
// the Master Password itself never reaches the server. KdfSalt and the cost
// fields are the public unlock parameters /api/v1/auth/params serves.
// The TwoFactor fields hold FieldCipher ciphertext as stored; the database
// layer decrypts them only for the handlers that need the TOTP secret.
type UserAuth struct {
	UserID                       string     `json:"userId" db:"Vault3UserAuthUserID"`
	AuthKeyHash                  string     `json:"-" db:"Vault3UserAuthAuthKeyHash"`
	KdfSalt                      string     `json:"kdfSalt,omitempty" db:"Vault3UserAuthKdfSalt"`
	KdfIterations                int        `json:"kdfIterations,omitempty" db:"Vault3UserAuthKdfIterations"`
	Argon2MemoryKiB              int        `json:"argon2MemoryKiB,omitempty" db:"Vault3UserAuthArgon2MemoryKiB"`
	Argon2Time                   int        `json:"argon2Time,omitempty" db:"Vault3UserAuthArgon2Time"`
	Argon2Lanes                  int        `json:"argon2Lanes,omitempty" db:"Vault3UserAuthArgon2Lanes"`
	LastPasswordChangeAt         *time.Time `json:"lastPasswordChangeAt,omitempty" db:"Vault3UserAuthLastPasswordChangeAt"`
	TwoFactorSecretEnc           string     `json:"-" db:"Vault3UserAuthTwoFactorSecretEnc"`
	TempTwoFactorSecretEnc       string     `json:"-" db:"Vault3UserAuthTempTwoFactorSecretEnc"`
	EmailVerified                bool       `json:"emailVerified" db:"Vault3UserAuthEmailVerified"`
	EmailVerificationTokenHash   string     `json:"-" db:"Vault3UserAuthEmailVerificationTokenHash"`
	EmailVerificationTokenExpiry *time.Time `json:"-" db:"Vault3UserAuthEmailVerificationTokenExpiry"`
	UpdatedAt                    time.Time  `json:"updatedAt" db:"Vault3UserAuthUpdatedAt"`
}

// Costs projects the stored parameters into the shape handlers and views
// pass around.
func (a *UserAuth) Costs() KdfCosts {
	return KdfCosts{
		KdfIterations:   a.KdfIterations,
		Argon2MemoryKiB: a.Argon2MemoryKiB,
		Argon2Time:      a.Argon2Time,
		Argon2Lanes:     a.Argon2Lanes,
	}
}

// TwoFactorEnabled reports whether a promoted TOTP secret is on file.
func (a *UserAuth) TwoFactorEnabled() bool {
	return a != nil && a.TwoFactorSecretEnc != ""
}

package view

import (
	"encoding/json"

	"vault3/internal/models"
)

// Keyset is everything the browser needs to unlock after deriving the MUK:
// the account's KDF parameters, the encrypted private key, and each vault's
// wrapped key. All key material here is ciphertext (or public), so shipping
// it in window.__BUNGO_DATA__ or a JSON response discloses nothing — it is
// exactly what a database dump would already contain.
type Keyset struct {
	KdfSalt       string          `json:"kdfSalt"`
	KdfIterations int             `json:"kdfIterations"`
	Algo          string          `json:"algo"`
	PublicKey     json.RawMessage `json:"publicKey"`
	EncPrivateKey json.RawMessage `json:"encPrivateKey"`
	Vaults        []KeysetVault   `json:"vaults"`
}

// KeysetVault is one vault the user can unlock: identity plus the wrapped
// vault key and the client-side-encrypted name. MemberCount lets the client
// badge shared vaults without decrypting anything.
type KeysetVault struct {
	ID          string          `json:"id"`
	Kind        string          `json:"kind"`
	Role        string          `json:"role"`
	WrapAlgo    string          `json:"wrapAlgo"`
	WrappedKey  json.RawMessage `json:"wrappedKey"`
	EncName     json.RawMessage `json:"encName"`
	MemberCount int             `json:"memberCount"`
}

// NewKeysetVault projects one access+vault pair — the shape the vault list
// and the vault-mutation APIs return.
func NewKeysetVault(uv *models.UserVault) KeysetVault {
	return KeysetVault{
		ID:          uv.Vault.ID,
		Kind:        uv.Vault.Kind,
		Role:        uv.Access.Role,
		WrapAlgo:    uv.Access.WrapAlgo,
		WrappedKey:  uv.Access.WrappedKey,
		EncName:     uv.Vault.EncName,
		MemberCount: uv.MemberCount,
	}
}

// NewKeysetVaults projects a slice.
func NewKeysetVaults(vaults []models.UserVault) []KeysetVault {
	out := make([]KeysetVault, 0, len(vaults))
	for i := range vaults {
		out = append(out, NewKeysetVault(&vaults[i]))
	}
	return out
}

// NewKeyset projects a hydrated UserFull into the unlock payload. Returns
// nil when the auth or keys spokes are missing (an account mid-reset), which
// the client treats as "cannot unlock".
func NewKeyset(uf *models.UserFull) *Keyset {
	if uf == nil || uf.Auth == nil || uf.Keys == nil {
		return nil
	}
	ks := &Keyset{
		KdfSalt:       uf.Auth.KdfSalt,
		KdfIterations: uf.Auth.KdfIterations,
		Algo:          uf.Keys.Algo,
		PublicKey:     uf.Keys.PublicKey,
		EncPrivateKey: uf.Keys.EncPrivateKey,
		Vaults:        make([]KeysetVault, 0, len(uf.Vaults)),
	}
	ks.Vaults = NewKeysetVaults(uf.Vaults)
	return ks
}

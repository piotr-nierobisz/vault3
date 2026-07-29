// Package crypto is Vault3's server-side cryptographic toolbox. It has two
// jobs, and one very deliberate non-job:
//
//   - FieldCipher: AES-256-GCM encryption at rest for the small set of
//     operational fields the server must be able to read back (display name,
//     session IP/UA, TOTP secrets). Keyed by SERVER_ENCRYPTION_KEY_STRING.
//   - Token helpers: opaque single-use tokens (sessions, email verification,
//     account reset) generated here and stored only as SHA-256 hashes.
//
// What this package must NEVER do is touch vault data. Vault items, vault
// keys, and the user's private key are encrypted in the browser with keys
// derived from the Master Password and Secret Key (see web/lib/crypto.ts and
// docs/security.md); the server stores those blobs as opaque ciphertext and
// has no code path that could decrypt them.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// fieldCipherVersion prefixes every FieldCipher output so the encoding can
// evolve (e.g. a key rotation scheme) without ambiguity about how to decode
// existing rows.
const fieldCipherVersion = "v1"

// FieldCipher encrypts and decrypts individual database fields with
// AES-256-GCM under a single server-held key. Construct once at startup via
// NewFieldCipher and share through Runtime; the zero value is unusable.
type FieldCipher struct {
	aead cipher.AEAD
	key  []byte
}

// NewFieldCipher builds a FieldCipher from a base64 (std or URL, padded or
// not) encoded 32-byte key. Anything else is an error so a truncated or
// mistyped key fails at startup, never at first decrypt.
func NewFieldCipher(encodedKey string) (*FieldCipher, error) {
	key, decodeErr := decodeFlexibleBase64(encodedKey)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode server encryption key: %w", decodeErr)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("server encryption key must decode to 32 bytes, got %d", len(key))
	}

	block, blockErr := aes.NewCipher(key)
	if blockErr != nil {
		return nil, fmt.Errorf("initialise AES: %w", blockErr)
	}
	aead, gcmErr := cipher.NewGCM(block)
	if gcmErr != nil {
		return nil, fmt.Errorf("initialise GCM: %w", gcmErr)
	}
	return &FieldCipher{aead: aead, key: key}, nil
}

// EncryptString seals a plaintext field into the compact stored form
// "v1:base64url(nonce || ciphertext || tag)". Empty input encrypts to the
// empty string so optional columns can stay NULL/” without a special case
// at every call site.
func (c *FieldCipher) EncryptString(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, readErr := rand.Read(nonce); readErr != nil {
		return "", fmt.Errorf("generate nonce: %w", readErr)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return fieldCipherVersion + ":" + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// DecryptString reverses EncryptString. An empty stored value decrypts to the
// empty string; a malformed or tampered value returns an error (GCM
// authentication failure), never silent garbage.
func (c *FieldCipher) DecryptString(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	version, payload, found := strings.Cut(stored, ":")
	if !found || version != fieldCipherVersion {
		return "", fmt.Errorf("unrecognised field cipher encoding")
	}
	raw, decodeErr := base64.RawURLEncoding.DecodeString(payload)
	if decodeErr != nil {
		return "", fmt.Errorf("decode field ciphertext: %w", decodeErr)
	}
	if len(raw) < c.aead.NonceSize() {
		return "", fmt.Errorf("field ciphertext too short")
	}
	nonce, ciphertext := raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():]
	plaintext, openErr := c.aead.Open(nil, nonce, ciphertext, nil)
	if openErr != nil {
		return "", fmt.Errorf("decrypt field: %w", openErr)
	}
	return string(plaintext), nil
}

// Blind produces a deterministic, keyed digest of a value (HMAC-SHA256 under
// the server key, hex encoded). It exists for equality checks against
// encrypted columns — e.g. "has this account seen this IP before?" — where
// FieldCipher's random nonces make the ciphertext itself unmatchable. The
// output reveals only equality, never the value.
func (c *FieldCipher) Blind(value string) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// NewToken returns (opaqueToken, tokenHash): 32 bytes of CSPRNG output,
// base64url encoded, plus its storage hash. The opaque token goes to the
// client (cookie or email link); only the hash is persisted, so a database
// leak yields nothing redeemable.
func NewToken() (token string, tokenHash string, err error) {
	buf := make([]byte, 32)
	if _, readErr := rand.Read(buf); readErr != nil {
		return "", "", readErr
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, HashToken(token), nil
}

// HashToken returns the lowercase hex SHA-256 digest of an opaque token.
// SHA-256 is sufficient: the token is already 256 bits of uniform random, so
// a stretching KDF would buy nothing.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEquals compares two strings without leaking a timing signal.
func ConstantTimeEquals(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// decodeFlexibleBase64 accepts std/URL alphabets with or without padding, so
// operators can paste a key from `openssl rand -base64 32` or a URL-safe
// generator interchangeably.
func decodeFlexibleBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("value is not valid base64")
}

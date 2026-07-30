package models

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// CipherEnvelope is the client-side ciphertext container stored in every
// encrypted JSONB column (wrapped keys, item blobs, vault names, the user's
// private key). It is produced and consumed exclusively by the browser
// (web/lib/crypto.ts); the server only validates its shape and size so a
// malformed write is rejected before it reaches the database.
type CipherEnvelope struct {
	Version    int    `json:"v"`
	Algorithm  string `json:"alg"`
	Nonce      string `json:"n"`
	Ciphertext string `json:"c"`
}

// EnvelopeVersion is the only envelope version this release accepts.
//
// Version 1 was the pre-quantum format. It differed in permitting a second
// algorithm, RSA-OAEP-256, for wrapping a key to an account's public key —
// the one Shor-breakable construction Vault3 ever defined. It was never
// produced (sharing shipped symmetric instead), and removing it leaves the
// format with a single algorithm and nothing an eventual quantum adversary
// could unwrap.
//
// Bumping the version rather than quietly narrowing v1's meaning is the rule
// docs/security.md sets: a v1 envelope means what it always meant, and there
// simply are none.
const EnvelopeVersion = 2

// envelopeAlgorithms are the client-side algorithms the server accepts.
// A256GCM seals data under a symmetric key — and is the only entry, by
// design. AES-256 retains 128 bits of security against Grover's algorithm,
// which is NIST's highest post-quantum category, so there is no successor to
// plan for here.
var envelopeAlgorithms = map[string]bool{
	"A256GCM": true,
}

// ValidateCipherEnvelope structurally checks a raw JSON envelope: known
// version and algorithm, base64url fields, and a ciphertext no larger than
// maxCiphertextBytes (of decoded ciphertext). It cannot — by design — check
// anything about the plaintext.
func ValidateCipherEnvelope(raw json.RawMessage, maxCiphertextBytes int) error {
	if len(raw) == 0 {
		return fmt.Errorf("cipher envelope is empty")
	}
	var env CipherEnvelope
	if unmarshalErr := json.Unmarshal(raw, &env); unmarshalErr != nil {
		return fmt.Errorf("cipher envelope is not valid JSON: %w", unmarshalErr)
	}
	if env.Version != EnvelopeVersion {
		return fmt.Errorf("unsupported cipher envelope version %d", env.Version)
	}
	if !envelopeAlgorithms[env.Algorithm] {
		return fmt.Errorf("unsupported cipher algorithm %q", env.Algorithm)
	}
	if env.Ciphertext == "" {
		return fmt.Errorf("cipher envelope has no ciphertext")
	}
	ct, ctErr := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if ctErr != nil {
		return fmt.Errorf("ciphertext is not base64url: %w", ctErr)
	}
	if maxCiphertextBytes > 0 && len(ct) > maxCiphertextBytes {
		return fmt.Errorf("ciphertext exceeds %d bytes", maxCiphertextBytes)
	}
	// Unconditional now that A256GCM is the only algorithm: every envelope
	// carries a nonce, and one that does not is malformed rather than merely
	// a different shape.
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(env.Nonce)
	if nonceErr != nil {
		return fmt.Errorf("nonce is not base64url: %w", nonceErr)
	}
	if len(nonce) != 12 {
		return fmt.Errorf("A256GCM nonce must be 12 bytes, got %d", len(nonce))
	}
	return nil
}

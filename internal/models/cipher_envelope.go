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

// envelopeAlgorithms are the client-side algorithms the server accepts.
// A256GCM seals data under a symmetric key; RSA-OAEP-256 wraps a key to a
// public key (no nonce). Anything else is rejected.
var envelopeAlgorithms = map[string]bool{
	"A256GCM":      true,
	"RSA-OAEP-256": true,
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
	if env.Version != 1 {
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
	if env.Algorithm == "A256GCM" {
		nonce, nErr := base64.RawURLEncoding.DecodeString(env.Nonce)
		if nErr != nil {
			return fmt.Errorf("nonce is not base64url: %w", nErr)
		}
		if len(nonce) != 12 {
			return fmt.Errorf("A256GCM nonce must be 12 bytes, got %d", len(nonce))
		}
	}
	return nil
}

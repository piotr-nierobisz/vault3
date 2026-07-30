package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"vault3/internal/config"

	"golang.org/x/crypto/argon2"
)

// The Argon2id known-answer vectors are shared with the browser: this test
// asserts that Go's native implementation still produces them, and
// scripts/verify-wasm.mjs asserts that the compiled wasm module produces the
// same ones. Together they pin both halves of the KDF to a single answer, so
// the browser and the server can never drift onto different derivations of
// the same password.
//
// A failure here means golang.org/x/crypto/argon2 changed its output, which
// would invalidate every stored credential — treat it as a migration event,
// not a test to update.
type argon2Vector struct {
	Note      string `json:"note"`
	Password  string `json:"password"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memoryKiB"`
	Lanes     uint8  `json:"lanes"`
	OutLen    uint32 `json:"outLen"`
	Want      string `json:"want"`
}

func loadArgon2Vectors(t *testing.T) []argon2Vector {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/argon2_vectors.json")
	if readErr != nil {
		t.Fatalf("read vectors: %v", readErr)
	}
	var vectors []argon2Vector
	if unmarshalErr := json.Unmarshal(raw, &vectors); unmarshalErr != nil {
		t.Fatalf("parse vectors: %v", unmarshalErr)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vectors
}

func TestArgon2IDKnownAnswers(t *testing.T) {
	for _, v := range loadArgon2Vectors(t) {
		t.Run(v.Note, func(t *testing.T) {
			password, pwErr := base64.RawURLEncoding.DecodeString(v.Password)
			if pwErr != nil {
				t.Fatalf("decode password: %v", pwErr)
			}
			salt, saltErr := base64.RawURLEncoding.DecodeString(v.Salt)
			if saltErr != nil {
				t.Fatalf("decode salt: %v", saltErr)
			}
			got := hex.EncodeToString(argon2.IDKey(password, salt, v.Time, v.MemoryKiB, v.Lanes, v.OutLen))
			if got != v.Want {
				t.Errorf("argon2id mismatch\n want %s\n got  %s", v.Want, got)
			}
		})
	}
}

// TestArgon2VectorsCoverClientDefaults keeps the vector file honest: if the
// registered client costs are raised, the KAT set must gain a vector at the
// new costs, or scripts/verify-wasm.mjs would go on verifying the wasm module
// at settings no browser actually uses.
func TestArgon2VectorsCoverClientDefaults(t *testing.T) {
	for _, v := range loadArgon2Vectors(t) {
		if v.Time == config.Argon2DefaultTime &&
			v.MemoryKiB == config.Argon2DefaultMemoryKiB &&
			v.Lanes == config.Argon2DefaultLanes {
			return
		}
	}
	t.Errorf("no vector covers the client defaults (t=%d m=%d p=%d); regenerate testdata/argon2_vectors.json",
		config.Argon2DefaultTime, config.Argon2DefaultMemoryKiB, config.Argon2DefaultLanes)
}

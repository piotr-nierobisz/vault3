package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Storage hashing for the client-derived auth key.
//
// What arrives here is not a password. It is the 64-byte output of the
// browser's two-secret derivation (web/lib/crypto.ts) — 512 bits of uniform
// random as far as any attacker is concerned — so no storage hash can add
// meaningful guessing resistance to it. The reason a slow hash is used anyway
// is that this property is an invariant of the client, and the server should
// not be the thing that fails if the client ever stops upholding it.
//
// Argon2id rather than bcrypt, for reasons that are not about speed:
//
//   - bcrypt silently truncates its input at 72 bytes. A 64-byte auth key
//     base64s to 86 characters, so bcrypt would have ignored the last 14 of
//     them — quietly discarding 84 bits and making distinct auth keys collide.
//     That alone rules it out.
//   - bcrypt's cost is CPU-only. Argon2id's is memory-bound, which is what a
//     cracking rig actually struggles to parallelise.
//   - Neither is broken by a quantum adversary; both are symmetric
//     constructions where Grover buys only a square root. This change is
//     about the truncation bug and about not keeping a Blowfish derivative
//     around, not about post-quantum security.
//
// Costs are OWASP's minimum Argon2id configuration and deliberately modest:
// login is an unauthenticated endpoint, so the memory each attempt reserves
// is a lever an attacker can pull. Against a 512-bit uniform input there is
// nothing to buy by pulling harder here.
const (
	authKeyArgon2Time      = 2
	authKeyArgon2MemoryKiB = 19456 // 19 MiB
	authKeyArgon2Lanes     = 1
	authKeyArgon2KeyLen    = 32
	authKeyArgon2SaltLen   = 16
)

// argon2idPrefix is the PHC-format identifier every stored hash starts with.
// Storing the parameters alongside the digest is what lets the costs above be
// raised later without invalidating hashes written under the old ones.
const argon2idPrefix = "$argon2id$"

// HashAuthKey derives a storage hash for the client's auth key, in the
// standard PHC encoding:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>
func HashAuthKey(authKey string) (string, error) {
	salt := make([]byte, authKeyArgon2SaltLen)
	if _, readErr := rand.Read(salt); readErr != nil {
		return "", fmt.Errorf("generate argon2 salt: %w", readErr)
	}
	digest := argon2.IDKey([]byte(authKey), salt,
		authKeyArgon2Time, authKeyArgon2MemoryKiB, authKeyArgon2Lanes, authKeyArgon2KeyLen)

	return fmt.Sprintf("%sv=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2idPrefix, argon2.Version,
		authKeyArgon2MemoryKiB, authKeyArgon2Time, authKeyArgon2Lanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(digest),
	), nil
}

// CompareAuthKey reports whether authKey reproduces a stored hash. It reads
// the cost parameters back out of the encoded form rather than assuming the
// current constants, so hashes written before a cost increase still verify.
//
// The comparison is constant time. A malformed stored hash returns false
// rather than an error: every caller is on the sign-in path, where the only
// safe response to anything unexpected is the same generic failure.
func CompareAuthKey(stored, authKey string) bool {
	if !strings.HasPrefix(stored, argon2idPrefix) {
		return false
	}
	// $argon2id$v=19$m=…,t=…,p=…$salt$digest → ["", "argon2id", "v=19", "m=…,t=…,p=…", salt, digest]
	parts := strings.Split(stored, "$")
	if len(parts) != 6 {
		return false
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil || version != argon2.Version {
		return false
	}
	var memoryKiB, time uint32
	var lanes uint8
	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memoryKiB, &time, &lanes); scanErr != nil {
		return false
	}
	if memoryKiB < 8 || time < 1 || lanes < 1 {
		return false
	}

	salt, saltErr := base64.RawStdEncoding.DecodeString(parts[4])
	if saltErr != nil || len(salt) == 0 {
		return false
	}
	want, wantErr := base64.RawStdEncoding.DecodeString(parts[5])
	if wantErr != nil || len(want) == 0 {
		return false
	}

	got := argon2.IDKey([]byte(authKey), salt, time, memoryKiB, lanes, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

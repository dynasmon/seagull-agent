package sources

import (
	"crypto/rand"
	"encoding/hex"
)

// newUUIDv4 generates a random RFC 4122 UUID (version 4).
func newUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString(b[:])
	}
	// Set version (4) and variant (10xx)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	// 8-4-4-4-12
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

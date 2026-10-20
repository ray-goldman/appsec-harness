package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func Fingerprint(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

func SessionID() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

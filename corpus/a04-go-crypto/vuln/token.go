package auth

import (
	"crypto/md5"
	"fmt"
	"math/rand"
)

func Fingerprint(b []byte) string { return fmt.Sprintf("%x", md5.Sum(b)) }

func SessionID() string {
	sessionToken := rand.Int63()
	return fmt.Sprint(sessionToken)
}

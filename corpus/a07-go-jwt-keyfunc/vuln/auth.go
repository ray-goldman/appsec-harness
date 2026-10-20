package auth

import "github.com/golang-jwt/jwt/v5"

func Check(tok string, key []byte) (*jwt.Token, error) {
	return jwt.Parse(tok, func(t *jwt.Token) (interface{}, error) { return key, nil })
}

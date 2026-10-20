package auth

import "github.com/golang-jwt/jwt/v5"

func Check(tok string, kf jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(tok, kf, jwt.WithValidMethods([]string{"RS256"}))
}

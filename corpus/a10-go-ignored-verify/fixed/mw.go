package mw

func user(tok string) (string, error) {
	claims, err := Verify(tok)
	if err != nil {
		return "", err
	}
	return claims.Sub, nil
}

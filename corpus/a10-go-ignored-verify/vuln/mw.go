package mw

func user(tok string) string {
	claims, _ := Verify(tok)
	return claims.Sub
}

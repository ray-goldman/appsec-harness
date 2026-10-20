package web

import (
	"fmt"
	"net/http"
)

func q(r *http.Request) string {
	return fmt.Sprintf("SELECT * FROM t WHERE n = '%s'", r.FormValue("n"))
}

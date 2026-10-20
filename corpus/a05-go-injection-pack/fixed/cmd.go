package web

import (
	"net/http"
	"os/exec"
)

func ping(r *http.Request) error {
	host := validateHost(r.FormValue("h"))
	return exec.Command("ping", "-c", "1", "--", host).Run()
}

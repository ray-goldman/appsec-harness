package web

import (
	"net/http"
	"os/exec"
)

func ping(r *http.Request) error {
	host := r.FormValue("h")
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

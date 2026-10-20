package web

import "net/http"

func proxy(w http.ResponseWriter, r *http.Request) {
	resp, _ := http.Get(r.URL.Query().Get("url"))
	defer resp.Body.Close()
}

func next(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

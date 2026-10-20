package web

import "net/http"

var UPSTREAMS = map[string]string{"rates": "https://rates.example.net/v1"}

func proxy(w http.ResponseWriter, r *http.Request) {
	target := UPSTREAMS[r.URL.Query().Get("svc")]
	resp, err := http.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

func next(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/home", http.StatusFound)
}

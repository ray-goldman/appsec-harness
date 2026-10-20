package main

import (
	"net/http"
	"os"
)

var root, _ = os.OpenRoot("/srv/files")

func download(w http.ResponseWriter, r *http.Request) {
	f, err := root.Open(r.URL.Query().Get("file"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
}

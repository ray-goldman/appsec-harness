package h

import "net/http"

func H(w http.ResponseWriter, r *http.Request) {
	if err := work(); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

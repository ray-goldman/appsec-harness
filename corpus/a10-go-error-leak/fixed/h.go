package h

import (
	"log"
	"net/http"
)

func H(w http.ResponseWriter, r *http.Request) {
	if err := work(); err != nil {
		log.Printf("work: %v", err)
		http.Error(w, "internal error", 500)
	}
}

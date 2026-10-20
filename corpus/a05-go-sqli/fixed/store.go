package store

import (
	"database/sql"
	"net/http"
)

func Find(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	return db.Query("SELECT id FROM users WHERE name = $1", r.URL.Query().Get("name"))
}

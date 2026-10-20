package store

import (
	"database/sql"
	"fmt"
	"net/http"
)

func Find(db *sql.DB, r *http.Request) (*sql.Rows, error) {
	name := r.URL.Query().Get("name")
	return db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
}

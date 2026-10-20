package main
import (
  "net/http"
  "path/filepath"
  "os"
)
const root = "/srv/files"
func other(r *http.Request) {
  name := r.FormValue("name")
  _ = name
}
func read(w http.ResponseWriter, r *http.Request) {
  name := filepath.Base(r.URL.Query().Get("name"))
  if !filepath.IsLocal(name) { return }
  data, _ := os.ReadFile(filepath.Join(root, name))
  w.Write(data)
}

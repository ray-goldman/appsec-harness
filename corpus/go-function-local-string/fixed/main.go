package main
import "net/http"
import "os"
func unrelated(r *http.Request) {
  name := r.FormValue("name")
  _ = name
}
func read(r *http.Request) {
  name := "README.txt"
  os.ReadFile(name)
}

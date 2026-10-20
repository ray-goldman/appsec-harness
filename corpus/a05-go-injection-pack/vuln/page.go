package web

import (
	"net/http"
	"text/template"
)

var page = template.Must(template.New("p").Parse("<p>{{.}}</p>"))

func render(w http.ResponseWriter, r *http.Request) { page.Execute(w, r.FormValue("q")) }

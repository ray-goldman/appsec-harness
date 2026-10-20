package web

import (
	"html/template"
	"net/http"
)

var t = template.Must(template.New("b").Parse("<p>{{.}}</p>"))

func bio(w http.ResponseWriter, r *http.Request) { t.Execute(w, r.FormValue("bio")) }

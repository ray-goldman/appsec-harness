package web

import (
	"html/template"
	"net/http"
)

func bio(r *http.Request) template.HTML {
	return template.HTML(r.FormValue("bio"))
}

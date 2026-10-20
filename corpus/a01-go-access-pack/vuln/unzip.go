package web

import (
	"archive/zip"
	"path/filepath"
)

func dest(base string, f *zip.File) string {
	return filepath.Join(base, f.Name)
}

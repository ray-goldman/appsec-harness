package web

import (
	"archive/zip"
	"errors"
	"path/filepath"
)

func dest(base string, f *zip.File) (string, error) {
	name := filepath.Clean(f.Name)
	if !filepath.IsLocal(name) {
		return "", errors.New("unsafe path")
	}
	return filepath.Join(base, name), nil
}

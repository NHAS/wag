package frontend

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
)

var (
	//go:embed dist/assets/*
	adminResources embed.FS

	//go:embed dist/index.html dist/favicon.ico
	index embed.FS

	distFiles = must(fs.Sub(adminResources, "dist"))
)

func must(f fs.FS, err error) fs.FS {
	if err != nil {
		panic(err)
	}

	return f
}

func Index(w http.ResponseWriter, r *http.Request) {

	f, err := index.Open("dist/index.html")
	if err != nil {
		panic(err)
	}

	w.Header().Set("content-type", "text/html; charset=utf-8")
	io.Copy(w, f)
}

func Favicon(w http.ResponseWriter, r *http.Request) {

	f, err := index.Open("dist/favicon.ico")
	if err != nil {
		panic(err)
	}

	w.Header().Set("content-type", "image/x-icon")
	io.Copy(w, f)
}

func Assets(w http.ResponseWriter, r *http.Request) {

	http.StripPrefix("/", http.FileServer(http.FS(distFiles))).ServeHTTP(w, r)
}

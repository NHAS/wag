package resources

import (
	"crypto/sha1"
	"embed"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

var (
	//go:embed all:frontend/dist/*
	static embed.FS
	Static = must(fs.Sub(static, "frontend/dist"))
)

func must(f fs.FS, err error) fs.FS {
	if err != nil {
		panic(err)
	}

	return f
}

// dummys first versioning
func Version() string {
	file, err := Static.Open("index.html")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	hasher := sha1.New()
	if _, err = io.Copy(hasher, file); err != nil {
		panic(err)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func Assets(w http.ResponseWriter, r *http.Request) {

	path := strings.TrimPrefix(r.URL.Path, "/")

	_, err := Static.Open(path)
	if err != nil {
		file, err := Static.Open("index.html")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		w.Header().Set("Content-Type", "text/html")
		io.Copy(w, file)
		return
	}
	http.StripPrefix("/", http.FileServer(http.FS(Static))).ServeHTTP(w, r)
}

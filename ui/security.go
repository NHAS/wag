package ui

import (
	"net/http"
	"net/url"
)

type security struct {
	next http.Handler
}

func (sh *security) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if r.Method != "GET" {
		u, err := url.Parse(r.Header.Get("Origin"))
		if err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		//If origin != host header
		if r.Host != u.Host {
			http.Error(w, "Bad Request", 400)
			return
		}
	}

	sh.next.ServeHTTP(w, r)
}

func setSecurityHeaders(f http.Handler) http.Handler {
	return &security{
		next: f,
	}
}

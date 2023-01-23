package webserver

import "net/http"

type securityHeaders struct {
	next http.Handler
}

func (sh *securityHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; object-src 'none'; img-src 'self' data:; require-trusted-types-for 'script'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com fonts.googleapis.com; ")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")

	sh.next.ServeHTTP(w, r)
}

func setSecurityHeaders(f http.Handler) http.Handler {
	return &securityHeaders{
		next: f,
	}
}

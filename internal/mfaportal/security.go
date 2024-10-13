package webserver

import (
	"net"
	"net/http"
	"strings"
)

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

type httpRedirectHandler struct {
	TLSPort string
}

func (sh *httpRedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			host = r.Host
		} else {
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "https://"+host+r.RequestURI, http.StatusTemporaryRedirect)
}

func setRedirectHandler(TLSPort string) http.Handler {
	return &httpRedirectHandler{TLSPort: TLSPort}
}

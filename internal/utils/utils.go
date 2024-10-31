package utils

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/NHAS/wag/internal/config"
)

func EmbeddedStatic(fs embed.FS) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		var fileContent []byte

		if len(r.URL.Path) > 0 {
			r.URL.Path = r.URL.Path[1:]
		}

		if fileContent, err = fs.ReadFile(r.URL.Path); err != nil {
			log.Println("Error getting static: ", err)
			http.NotFound(w, r)
			return
		}

		headers := w.Header()
		ext := filepath.Ext(r.URL.Path)

		switch ext {
		case ".js":
			headers.Set("Content-Type", "text/javascript")
		case ".css":
			headers.Set("Content-Type", "text/css")
		case ".png":
			headers.Set("Content-Type", "image/png")
		case ".jpg":
			headers.Set("Content-Type", "image/jpg")
		case ".svg":
			headers.Set("Content-Type", "image/svg")
		}

		_, err = w.Write(fileContent)
		if err != nil {
			log.Println("Unable to write static resource: ", err, " path: ", r.URL.Path)
			http.Error(w, "Server Error", 500)
		}
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

func SetRedirectHandler(TLSPort string) http.Handler {
	return &httpRedirectHandler{TLSPort: TLSPort}
}

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

func SetSecurityHeaders(f http.Handler) http.Handler {
	return &security{
		next: f,
	}
}

func GetIP(addr string) string {
	for i := len(addr) - 1; i > 0; i-- {
		if addr[i] == ':' || addr[i] == '/' {
			return addr[:i]
		}
	}

	return addr
}

func GetIPFromRequest(r *http.Request) net.IP {

	//Do not respect the X-Forwarded-For header until we are explictly told we are being proxied.
	if config.Values.NumberProxies > 0 {
		ips := r.Header.Get("X-Forwarded-For")
		addresses := strings.Split(ips, ",")

		if ips != "" && len(addresses) > 0 {

			if len(addresses)-config.Values.NumberProxies < 0 {
				log.Println("WARNING XFF parsing may be broken: ", len(addresses)-config.Values.NumberProxies, " check config.Values.NumberProxies")
				return net.ParseIP(strings.TrimSpace(addresses[len(addresses)-1]))
			}

			return net.ParseIP(strings.TrimSpace(addresses[len(addresses)-config.Values.NumberProxies]))
		}
	}

	return net.ParseIP(GetIP(r.RemoteAddr))
}

func GenerateRandomHex(n uint32) (string, error) {
	b, err := GenerateRandom(n)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func GenerateRandom(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return b, err
	}

	return b, nil
}

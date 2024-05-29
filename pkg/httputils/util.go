package httputils

import (
	"net/http"
	"strings"
)

type HTTPUtilMux struct {
	*http.ServeMux
}

func (hum *HTTPUtilMux) AllowedMethods(path string, h http.HandlerFunc, methods ...string) {

	hum.ServeMux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {

		for _, method := range methods {
			if r.Method == method {
				h(w, r)
				return
			}
		}

		w.Header().Set("Allow", strings.Join(methods, ", "))
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
}

func (hum *HTTPUtilMux) Get(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, h, http.MethodGet)
}

func (hum *HTTPUtilMux) Post(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, h, http.MethodPost)

}

func (hum *HTTPUtilMux) Delete(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, h, http.MethodDelete)
}

func NewMux() *HTTPUtilMux {
	return &HTTPUtilMux{
		ServeMux: http.NewServeMux(),
	}
}

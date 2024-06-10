package httputils

import (
	"net/http"
	"strings"
)

const JSON = "application/json"

type HTTPUtilMux struct {
	*http.ServeMux
}

func (hum *HTTPUtilMux) AllowedMethods(path, contenttype string, h http.HandlerFunc, methods ...string) {

	hum.ServeMux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {

		if contenttype != "" && r.Header.Get("content-type") != contenttype {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

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
	hum.AllowedMethods(path, "", h, http.MethodGet)
}

func (hum *HTTPUtilMux) GetJSON(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, JSON, h, http.MethodGet)
}

func (hum *HTTPUtilMux) GetOrPost(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, "", h, http.MethodGet, http.MethodPost)
}

func (hum *HTTPUtilMux) GetOrPostJSON(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, JSON, h, http.MethodGet)
}

func (hum *HTTPUtilMux) Post(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, "", h, http.MethodPost)
}

func (hum *HTTPUtilMux) PostJSON(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, JSON, h, http.MethodPost)
}

func (hum *HTTPUtilMux) Delete(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, "", h, http.MethodDelete)
}

func (hum *HTTPUtilMux) DeleteJSON(path string, h http.HandlerFunc) {
	hum.AllowedMethods(path, JSON, h, http.MethodDelete)
}

func NewMux() *HTTPUtilMux {
	return &HTTPUtilMux{
		ServeMux: http.NewServeMux(),
	}
}

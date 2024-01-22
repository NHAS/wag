package webserver

import (
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators"
)

func watchConfigChanges(serveMux *http.ServeMux) data.ConfigChangesFunc {
	return func(be data.BasicEvent[string], i int) {
		if strings.HasPrefix(be.Key, "wag-config-authenticaton-") {
			authenticators.SetRoutesFromMethods(serveMux)
		}
	}
}

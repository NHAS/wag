package webserver

import (
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators"
)

func watchConfigChanges(serveMux *http.ServeMux) data.ConfigChangesFunc {
	return func(be data.BasicEvent[string], i int) {
		if strings.HasPrefix(be.Key, "wag-config-authentication-") {

			log.Println("authentication settings have changed, updating auth handlers")
			authenticators.SetRoutesFromMethods(serveMux)
		}
	}
}

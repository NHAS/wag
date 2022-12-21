package methods

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/webserver/authenticators"
	"github.com/NHAS/wag/webserver/resources"
)

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

func init() {
	authenticators.MFA[authenticators.TotpMFA] = new(Totp)
	authenticators.MFA[authenticators.WebauthnMFA] = new(Webauthn)
	authenticators.MFA[authenticators.OidcMFA] = new(Oidc)
}

func resultMessage(err error) (string, int) {
	if err == nil {
		return "Success", http.StatusOK
	}

	msg := "Validation failed"
	if strings.Contains(err.Error(), "locked") {
		msg = "Account is locked contact: " + config.Values().HelpMail
	}
	return msg, http.StatusBadRequest
}

func renderTemplate(w http.ResponseWriter, tmplt *template.Template, message, url string) error {

	data := resources.Msg{
		HelpMail:   config.Values().HelpMail,
		NumMethods: len(authenticators.MFA),
		Message:    message,
		URL:        url,
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	err := tmplt.Execute(w, &data)
	if err != nil {
		http.Error(w, "Server error", 500)
		return err
	}

	return err
}

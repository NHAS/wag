package authenticators

import (
	"html/template"
	"net/http"
)

type AuthenticatorFunc func(mfaSecret, username string) error

const (
	UnsetMFA    = "unset"
	TotpMFA     = "totp"
	WebauthnMFA = "webauthn"
)

type Authenticator interface {
	Type() string
	FriendlyName() string

	RegistrationEndpoint(w http.ResponseWriter, r *http.Request)
	AuthorisationEndpoint(w http.ResponseWriter, r *http.Request)

	PromptTemplate() *template.Template
	RegistrationTemplate() *template.Template
}

var MFA = map[string]Authenticator{}

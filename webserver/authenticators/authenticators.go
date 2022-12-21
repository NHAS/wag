package authenticators

import (
	"net/http"
)

type AuthenticatorFunc func(mfaSecret, username string) error

const (
	UnsetMFA    = "unset"
	TotpMFA     = "totp"
	WebauthnMFA = "webauthn"
	OidcMFA     = "oidc"
)

type Authenticator interface {
	Init(settings map[string]string) error

	Type() string
	FriendlyName() string

	RegistrationEndpoint(w http.ResponseWriter, r *http.Request)
	AuthorisationEndpoint(w http.ResponseWriter, r *http.Request)

	PromptHandler(w http.ResponseWriter, r *http.Request, username, ip string)
	RegistrationHandler(w http.ResponseWriter, r *http.Request, username, ip string)
}

var MFA = map[string]Authenticator{}

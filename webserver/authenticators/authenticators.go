package authenticators

import (
	"net/http"
)

// This is passed to the users.Authenticate(...) function
type AuthenticatorFunc func(mfaSecret, username string) error

// All supported mfa methods, altered in config based on users selection
var MFA = map[string]Authenticator{}

const (
	UnsetMFA    = "unset"
	TotpMFA     = "totp"
	WebauthnMFA = "webauthn"
	OidcMFA     = "oidc"
)

type Authenticator interface {

	// An ugly hack to be able to initalise authenticators with settings from config at runtime
	Init(settings map[string]string) error

	Type() string

	// Name that is displayed in the MFA selection table
	FriendlyName() string

	// Redirection path that deauthenticates selected mfa method (mostly just "/" unless its externally connected to something)
	LogoutPath() string

	// Automatically added under /register_mfa/<mfa_method_name>
	RegistrationAPI(w http.ResponseWriter, r *http.Request)

	// Automatically added under /authorise/<mfa_method_name>
	AuthorisationAPI(w http.ResponseWriter, r *http.Request)

	// Executed in /authorise/ path to display UI when user browses to that path
	MFAPromptUI(w http.ResponseWriter, r *http.Request, username, ip string)

	// Executed in /register_mfa/ path to show the UI for registration
	RegistrationUI(w http.ResponseWriter, r *http.Request, username, ip string)
}

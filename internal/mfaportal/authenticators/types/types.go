package types

type MFA string

const (
	Unset MFA = "unset"

	Totp     MFA = "totp"
	Webauthn MFA = "webauthn"
	Oidc     MFA = "oidc"
	Pam      MFA = "pam"
)

// This is passed to the users.Authenticate(...) function
type AuthenticatorFunc func(mfaSecret, username string) error

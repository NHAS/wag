package authenticators

type Authenticator func(mfaSecret, username string) error

const (
	UnsetMFA    = "unset"
	TotpMFA     = "totp"
	WebauthnMFA = "webauthn"
)

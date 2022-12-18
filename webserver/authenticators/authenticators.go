package authenticators

type Authenticator func(mfaSecret, mfaType, username string) error

const (
	UnsetMFA    = "unset"
	TotpMFA     = "totp"
	WebauthnMFA = "webauthn"
)

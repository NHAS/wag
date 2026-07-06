package types

import "slices"

type MFA string

const (
	Unset MFA = "unset"

	Totp     MFA = "totp"
	Webauthn MFA = "webauthn"
	Oidc     MFA = "oidc"
	Pam      MFA = "pam"
)

var validMethods = []MFA{
	Totp,
	Webauthn,
	Oidc,
	Pam,
}

func ValidMFA(mfaName string) bool {
	return slices.Contains(validMethods, MFA(mfaName))
}

func ValidMFAMethods(mfaNames []string) bool {
	for _, method := range mfaNames {
		if !ValidMFA(method) {
			return false
		}
	}

	return true
}

func Valid(mfaName MFA) bool {
	return slices.Contains(validMethods, mfaName)
}

// This is passed to the users.Authenticate(...) function
type AuthenticatorFunc func(mfaSecret, username string) error

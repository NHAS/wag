package interfaces

import "github.com/NHAS/wag/pkg/control"

type RegistrationWriter interface {
	AddRegistrationToken(token, username, overwrite, staticIp string, groups []string, uses, mtu int, tag string) error
	GenerateRegistrationToken(username, overwrite, staticIp string, groups []string, uses, mtu int, tag string) (token string, err error)

	DeleteRegistrationToken(identifier string) error
}

type RegistrationReader interface {
	GetRegistrationToken(token string) (result control.RegistrationResult, err error)
	GetRegistrationTokens() (results []control.RegistrationResult, err error)
}

type RegistrationRepository interface {
	RegistrationWriter
	RegistrationReader
}

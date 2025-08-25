package interfaces

import "github.com/NHAS/wag/pkg/control"

type RegistrationWriter interface {
	AddRegistrationToken(token, username, overwrite, staticIp string, groups []string, uses int, tag string) error
	GenerateRegistrationToken(username, overwrite, staticIp string, groups []string, uses int, tag string) (token string, err error)

	DeleteRegistrationToken(identifier string) error
}

type RegistrationReader interface {
	GetRegistrationToken(token string) (username, overwrites, staticIP string, group []string, tag string, err error)
	GetRegistrationTokens() (results []control.RegistrationResult, err error)
}

type RegistrationRepository interface {
	RegistrationWriter
	RegistrationReader
}

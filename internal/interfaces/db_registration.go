package interfaces

import "github.com/NHAS/wag/pkg/control"

type ReigstrationWriter interface {
	AddRegistrationToken(token, username, overwrite, staticIp string, groups []string, uses int) error
	FinaliseRegistration(token string) error
	DeleteRegistrationToken(identifier string) error
}

type RegistrationReader interface {
	GenerateRegistrationToken(username, overwrite, staticIp string, groups []string, uses int) (token string, err error)
	GetRegistrationToken(token string) (username, overwrites, staticIP string, group []string, err error)
	GetRegistrationTokens() (results []control.RegistrationResult, err error)
}

type RegistrationRepository interface {
	ReigstrationWriter
	RegistrationReader
}

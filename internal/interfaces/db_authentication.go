package interfaces

import (
	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
)

type AuthenticationReader interface {
	GetAuthenticationDetails(username, device string) (mfa, mfaType string, attempts int, locked bool, err error)
	GetLockout() (int, error)
	GetSessionInactivityTimeoutMinutes() (int, error)
	GetSessionLifetimeMinutes() (int, error)
	HasDeviceAuthorised(current, previous data.Device) bool
	GetEffectiveAcl(username string) acls.Acl
}

type AuthenticationWriter interface {
	AuthoriseDevice(username, address string) error
	DeauthenticateDevice(address string) error

	SetSessionInactivityTimeoutMinutes(inactivityTimeout int) error
	SetSessionLifetimeMinutes(lifetimeMinutes int) error

	MarkDeviceSessionEnded(address string) error

	ValidateChallenge(username, address, challenge string) error

	IncrementAdminAuthenticationAttempt(username string) error
	IncrementAuthenticationAttempt(username, device string) error

	SetDeviceAuthenticationAttempts(username, address string, attempts int) error
}

type AuthenticationActions interface {
	AuthenticationReader
	AuthenticationWriter
}

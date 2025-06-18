package interfaces

type MFAReader interface {
	GetMFASecret(username string) (string, error)
	GetMFAType(username string) (string, error)

	IsEnforcingMFA(username string) bool

	GetEnabledMFAMethods() (result []string, err error)

	GetDefaultMFAMethod() (string, error)
}

type MFAWriter interface {
	SetEnforceMFAOff(username string) error
	SetEnforceMFAOn(username string) error

	SetDefaultMFAMethod(method string) error
	SetEnabledMFAMethods(methods []string) error
}

type MFARespository interface {
	MFAReader
	MFAWriter
}

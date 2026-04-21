package interfaces

import "github.com/NHAS/wag/internal/config"

type AcmeReader interface {
	GetAcmeEmail() (string, error)
	GetAcmeProvider() (string, error)
	GetAcmeDNS01CloudflareToken() (config.CloudflareToken, error)
}

type AcmeWriter interface {
	SetAcmeDNS01CloudflareToken(token string) error
	SetAcmeEmail(email string) error
	SetAcmeProvider(providerURL string) error
}

type AcmeRepository interface {
	AcmeReader
	AcmeWriter
}

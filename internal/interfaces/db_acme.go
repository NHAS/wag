package interfaces

import "github.com/NHAS/wag/internal/data"

type AcmeReader interface {
	GetAcmeEmail() (string, error)
	GetAcmeProvider() (string, error)
	GetAcmeDNS01CloudflareToken() (data.CloudflareToken, error)
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

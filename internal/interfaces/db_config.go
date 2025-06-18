package interfaces

import "github.com/NHAS/wag/internal/data"

type ConfigReader interface {
	GetTunnelDomainUrl() (string, error)

	GetGeneralSettings() (s data.GeneralSettings, err error)

	GetWireguardConfigName() string
	GetAllWebserverConfigs() (details map[string]data.WebserverConfiguration, err error)
	GetWebserverConfig(forWhat data.Webserver) (details data.WebserverConfiguration, err error)

	GetDNS() ([]string, error)
	GetExternalAddress() (string, error)
	GetHelpMail() string
	GetIssuer() (string, error)
	ShouldCheckUpdates() (bool, error)
	GetLoginSettings() (s data.LoginSettings, err error)
}

type ConfigWriter interface {
	SetWebserverConfig(forWhat data.Webserver, details data.WebserverConfiguration) (err error)
	SetGeneralSettings(generalSettings data.GeneralSettings) error
	SetHelpMail(helpMail string) error
	SetIssuer(issuer string) error
	SetLastLoginInformation(username, ip string) error

	SetLoginSettings(loginSettings data.LoginSettings) error
	SetDNS(dns []string) error
}

type ConfigRepository interface {
	ConfigReader
	ConfigWriter
	AcmeRepository
}

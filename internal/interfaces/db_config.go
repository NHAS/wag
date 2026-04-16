package interfaces

import (
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
)

type ConfigReader interface {
	GetTunnelDomainUrl() (string, error)

	GetGeneralSettings() (s data.GeneralSettingsDTO, err error)

	GetWireguardConfigName() string
	GetAllWebserverConfigs() (details map[string]config.WebserverDetails, err error)
	GetWebserverConfig(forWhat data.Webserver) (details config.WebserverDetails, err error)

	GetDNS() ([]string, error)
	GetExternalAddress() (string, error)
	GetHelpMail() string
	GetIssuer() (string, error)
	ShouldCheckUpdates() (bool, error)
	GetLoginSettings() (s data.LoginSettingsDTO, err error)
}

type ConfigWriter interface {
	SetWebserverConfig(forWhat data.Webserver, details config.WebserverDetails) (err error)
	SetGeneralSettings(generalSettings data.GeneralSettingsDTO) error
	SetHelpMail(helpMail string) error
	SetIssuer(issuer string) error
	SetLastLoginInformation(username, ip string) error

	SetLoginSettings(loginSettings data.LoginSettingsDTO) error
	SetDNS(dns []string) error
}

type ConfigRepository interface {
	ConfigReader
	ConfigWriter
	AcmeRepository
}

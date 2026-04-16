package data

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/NHAS/tetcd"
	paths "github.com/NHAS/tetcd/paths"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/go-playground/validator/v10"
)

type Webserver string

const (
	Tunnel     = Webserver("tunnel")
	Management = Webserver("management")
	Public     = Webserver("public")
)

func (d *database) GetAllWebserverConfigs() (details map[string]config.WebserverDetails, err error) {

	details = make(map[string]config.WebserverDetails, 3)

	details[string(Tunnel)], err = Config.Webserver.Tunnel.HTTPSettings.Get(context.Background(), d.etcd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch tunnel settings: %w", err)
	}

	details[string(Management)], err = Config.Webserver.Management.HTTPSettings.Get(context.Background(), d.etcd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch management settings: %w", err)
	}

	details[string(Public)], err = Config.Webserver.Public.HTTPSettings.Get(context.Background(), d.etcd)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public settings: %w", err)
	}

	return details, nil
}

func (d *database) GetWebserverConfig(forWhat Webserver) (details config.WebserverDetails, err error) {

	switch forWhat {
	case Tunnel:
		details, err = Config.Webserver.Tunnel.HTTPSettings.Get(context.Background(), d.etcd)

	case Management:
		details, err = Config.Webserver.Management.HTTPSettings.Get(context.Background(), d.etcd)

	case Public:
		details, err = Config.Webserver.Public.HTTPSettings.Get(context.Background(), d.etcd)

	default:
		return details, fmt.Errorf("unsupported webserver: %q", forWhat)
	}

	if err != nil {
		return details, fmt.Errorf("failed to fetch %q settings: %w", forWhat, err)
	}

	return details, nil
}

func (d *database) SetWebserverConfig(forWhat Webserver, details config.WebserverDetails) (err error) {
	txn := tetcd.NewTxn(context.Background(), d.etcd)

	type HttpSettings interface {
		CertificatePEM() paths.Path[string]
		PrivateKeyPEM() paths.Path[string]

		CertificatePath() paths.Path[string]
		PrivateKeyPath() paths.Path[string]

		StaticCerts() paths.Path[bool]
		Domain() paths.Path[string]
		ListenAddress() paths.Path[string]
		TLS() paths.Path[bool]
	}

	var target HttpSettings

	then := txn.Then()
	switch forWhat {
	case Tunnel:
		target = Config.Webserver.Tunnel.HTTPSettings
	case Management:
		target = Config.Webserver.Management.HTTPSettings
	case Public:
		target = Config.Webserver.Public.HTTPSettings
	default:
		return fmt.Errorf("unsupported webserver: %q", forWhat)
	}

	tetcd.PutTx(then, target.CertificatePEM(), details.CertificatePEM)
	tetcd.PutTx(then, target.PrivateKeyPEM(), details.PrivateKeyPEM)

	tetcd.PutTx(then, target.CertificatePath(), details.CertificatePath)
	tetcd.PutTx(then, target.PrivateKeyPath(), details.PrivateKeyPath)

	tetcd.PutTx(then, target.StaticCerts(), details.StaticCerts)
	tetcd.PutTx(then, target.Domain(), details.Domain)
	tetcd.PutTx(then, target.ListenAddress(), details.ListenAddress)
	tetcd.PutTx(then, target.TLS(), details.TLS)

	if err := txn.Commit(); err != nil {
		return err
	}

	return nil
}

func (d *database) GetPAM() (details config.PAM, err error) {
	return Config.Webserver.Tunnel.PAM.Get(context.Background(), d.etcd)
}

func (d *database) GetOidc() (details config.TunnelOidc, err error) {
	return Config.Webserver.Tunnel.OIDC.Get(context.Background(), d.etcd)
}

type WebauthnDTO struct {
	DisplayName string
	ID          string
	Origin      string
}

func (d *database) GetWebauthn() (wba WebauthnDTO, err error) {

	tunnelConfig, err := Config.Webserver.Tunnel.Get(context.Background(), d.etcd)
	if err != nil {
		return wba, fmt.Errorf("failed to fetch tunnel config: %w", err)
	}

	if tunnelConfig.Issuer == "" {
		return wba, errors.New("no issuer set")
	}

	if tunnelConfig.HTTPSettings.Domain == "" {
		return wba, errors.New("no domain set")
	}

	tunnelURL, err := webserverUrl(tunnelConfig.HTTPSettings.Domain, tunnelConfig.HTTPSettings.ListenAddress, tunnelConfig.HTTPSettings.TLS)
	if err != nil {
		return wba, err
	}

	wba.Origin = tunnelURL
	// Webauthn IDs should never contain the protocol, as they are
	// required to be over HTTPS anyways; so we strip the prefixes away
	// in case they were configured with protocol prefix.
	wba.ID = tunnelConfig.HTTPSettings.Domain
	wba.ID = strings.TrimPrefix(wba.ID, "https://")
	wba.ID = strings.TrimPrefix(wba.ID, "http://")

	return
}

func webserverUrl(domain, listenAddress string, isTLS bool) (string, error) {
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		// keep domain as is, if specified with full prefix
		return domain, nil
	}

	if domain == "" && listenAddress == "" {
		return "", fmt.Errorf("both domain and listenAddress are empty")
	}

	var (
		scheme string = "http://"
		host   string
		port   string

		err error
	)

	if isTLS {
		scheme = "https://"
	}

	host, port, err = net.SplitHostPort(domain)
	if err != nil && domain != "" {
		host = domain
	}

	listenAddressHost, listenAddressPort, _ := net.SplitHostPort(listenAddress)

	if host == "" {
		host = listenAddressHost
		if listenAddressHost == "" {
			return "", fmt.Errorf("unable to determine a host for the webserver, both listenaddress and domain are host empty")
		}
	}

	if port == "" {
		port = listenAddressPort
	}

	if isTLS && port == "443" || !isTLS && port == "80" {
		return scheme + host, nil
	}

	return scheme + host + ":" + port, nil
}

func (d *database) GetWireguardConfigName() string {

	k, err := Config.Webserver.Public.DownloadConfigFileName().Get(context.Background(), d.etcd)
	if err != nil {
		return "wg0.conf"
	}

	if k == "" {
		return "wg0.conf"
	}

	return k
}

func (d *database) SetDefaultMFAMethod(method string) error {
	return Config.Webserver.Tunnel.DefaultMethod().Put(context.Background(), d.etcd, method)
}

func (d *database) GetDefaultMFAMethod() (string, error) {

	return Config.Webserver.Tunnel.DefaultMethod().Get(context.Background(), d.etcd)
}

func (d *database) SetEnabledMFAMethods(methods []string) error {
	return Config.Webserver.Tunnel.Methods().Put(context.Background(), d.etcd, methods)
}

func (d *database) GetEnabledMFAMethods() (result []string, err error) {
	return Config.Webserver.Tunnel.Methods().Get(context.Background(), d.etcd)
}

func (d *database) ShouldCheckUpdates() (bool, error) {
	return Config.CheckUpdates().Get(context.Background(), d.etcd)
}

func (d *database) GetTunnelDomainUrl() (string, error) {

	result, err := Config.Webserver.Tunnel.Get(context.Background(), d.etcd)
	if err != nil {
		return "", fmt.Errorf("failed to fetch tunnel configuration: %w", err)
	}

	url, err := webserverUrl(result.HTTPSettings.Domain, result.HTTPSettings.ListenAddress, result.HTTPSettings.TLS)
	if err != nil {
		return "", err
	}

	return url, nil
}

func (d *database) SetIssuer(issuer string) error {
	return Config.Webserver.Tunnel.Issuer().Put(context.Background(), d.etcd, issuer)
}

func (d *database) GetIssuer() (string, error) {
	return Config.Webserver.Tunnel.Issuer().Get(context.Background(), d.etcd)
}

func (d *database) SetHelpMail(helpMail string) error {
	return Config.Webserver.Tunnel.HelpMail().Put(context.Background(), d.etcd, helpMail)
}

func (d *database) GetHelpMail() string {

	mail, err := Config.Webserver.Tunnel.HelpMail().Get(context.Background(), d.etcd)
	if err != nil {
		return "Server Error"
	}

	return mail
}

func (d *database) GetExternalAddress() (string, error) {
	return Config.Webserver.Public.ExternalAddress().Get(context.Background(), d.etcd)
}

func (d *database) SetDNS(dns []string) error {
	return Config.Wireguard.DNS().Put(context.Background(), d.etcd, dns)
}

func (d *database) GetDNS() ([]string, error) {
	return Config.Wireguard.DNS().Get(context.Background(), d.etcd)
}

func checkValidMFA(method types.MFA) ([]types.MFA, bool) {
	r := []types.MFA{
		types.Totp, types.Webauthn, types.Oidc, types.Pam,
	}

	return r, slices.Contains(r, method)
}

type LoginSettingsDTO struct {
	MaxSessionLifetimeMinutes       int `validate:"required,number" json:"max_session_lifetime_minutes"`
	SessionInactivityTimeoutMinutes int `validate:"required,number" json:"session_inactivity_timeout_minutes"`

	DefaultMethod string   `json:",omitempty"`
	Issuer        string   `validate:"required" json:"issuer"`
	Methods       []string `json:",omitempty" tetcd:"compress"`

	OIDC config.TunnelOidc `json:"oidc,omitzero"`

	PAM     config.PAM `json:"pam,omitzero"`
	Lockout int        `validate:"required,number" json:"lockout"`
}

func (d *database) GetLoginSettings() (s LoginSettingsDTO, err error) {

	result, err := Config.Webserver.Tunnel.Get(context.Background(), d.etcd)
	if err != nil {
		return s, fmt.Errorf("failed to fetch login settings: %w", err)
	}

	lockout, err := Config.Webserver.Lockout().Get(context.Background(), d.etcd)
	if err != nil {
		return s, fmt.Errorf("failed to fetch lockout settings: %w", err)
	}

	// todo clean this up by not using anon structs
	s.MaxSessionLifetimeMinutes = result.MaxSessionLifetimeMinutes
	s.SessionInactivityTimeoutMinutes = result.SessionInactivityTimeoutMinutes
	s.DefaultMethod = result.DefaultMethod
	s.Issuer = result.Issuer
	s.Methods = result.Methods
	s.OIDC = result.OIDC
	s.PAM = result.PAM
	s.Lockout = lockout

	return
}

type GeneralSettingsDTO struct {
	HelpMail               string   `validate:"required,email" json:"help_mail"`
	ExternalAddress        string   `validate:"required,hostname|hostname_port|ip" json:"external_address"`
	DNS                    []string `json:"dns,omitempty" tetcd:"compress" validate:"omitempty,dive,hostname|ip"`
	DownloadConfigFileName string   `json:"wireguard_config_filename,omitempty" validate:"required"`
	CheckUpdates           bool     `json:"check_updates,omitempty"`
}

func (d *database) GetGeneralSettings() (s GeneralSettingsDTO, err error) {
	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	helpMailH := tetcd.GetTx(then, Config.Webserver.Tunnel.HelpMail())
	externalAddressH := tetcd.GetTx(then, Config.Webserver.Public.ExternalAddress())
	dnsH := tetcd.GetTx(then, Config.Wireguard.DNS())
	downloadConfigFileNameH := tetcd.GetTx(then, Config.Webserver.Public.DownloadConfigFileName())
	checkUpdatesH := tetcd.GetTx(then, Config.CheckUpdates())

	if err := txn.Commit(); err != nil {
		return s, fmt.Errorf("failed to get general settings: %w", err)
	}

	helpMail, err := helpMailH.Value()
	if err != nil {
		d.RaiseError(fmt.Errorf("failed to unmarshal helpmail when loading general settings: %w", err), nil)
	}

	s.HelpMail = helpMail

	externalAddress, err := externalAddressH.Value()
	if err != nil {
		d.RaiseError(fmt.Errorf("failed to unmarshal external address when loading general settings: %w", err), nil)
	}
	s.ExternalAddress = externalAddress

	dns, err := dnsH.Value()
	if err != nil {
		d.RaiseError(fmt.Errorf("failed to unmarshal DNS when loading general settings: %w", err), nil)
	}
	s.DNS = dns

	downloadConfigFileName, err := downloadConfigFileNameH.Value()
	if err != nil {
		d.RaiseError(fmt.Errorf("failed to unmarshal download config file name when loading general settings: %w", err), nil)
	}

	s.DownloadConfigFileName = downloadConfigFileName

	checkUpdates, err := checkUpdatesH.Value()
	if err != nil {
		d.RaiseError(fmt.Errorf("failed to unmarshal check updates when loading general settings: %w", err), nil)
	}

	s.CheckUpdates = checkUpdates

	return
}

func (d *database) SetLoginSettings(loginSettings LoginSettingsDTO) error {

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(loginSettings); err != nil {
		return fmt.Errorf("invalid login settings: %w", err)
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	tetcd.PutTx(then, Config.Webserver.Tunnel.MaxSessionLifetimeMinutes(), loginSettings.MaxSessionLifetimeMinutes)
	tetcd.PutTx(then, Config.Webserver.Tunnel.SessionInactivityTimeoutMinutes(), loginSettings.SessionInactivityTimeoutMinutes)
	tetcd.PutTx(then, Config.Webserver.Tunnel.DefaultMethod(), loginSettings.DefaultMethod)
	tetcd.PutTx(then, Config.Webserver.Tunnel.Issuer(), loginSettings.Issuer)
	tetcd.PutTx(then, Config.Webserver.Tunnel.Methods(), loginSettings.Methods)

	tetcd.PutTx(then, Config.Webserver.Tunnel.OIDC.ClientID(), loginSettings.OIDC.ClientID)
	tetcd.PutTx(then, Config.Webserver.Tunnel.OIDC.ClientSecret(), loginSettings.OIDC.ClientSecret)
	tetcd.PutTx(then, Config.Webserver.Tunnel.OIDC.DeviceUsernameClaim(), loginSettings.OIDC.DeviceUsernameClaim)
	tetcd.PutTx(then, Config.Webserver.Tunnel.OIDC.GroupsClaimName(), loginSettings.OIDC.GroupsClaimName)
	tetcd.PutTx(then, Config.Webserver.Tunnel.OIDC.Scopes(), loginSettings.OIDC.Scopes)
	tetcd.PutTx(then, Config.Webserver.Tunnel.OIDC.IssuerURL(), loginSettings.OIDC.IssuerURL)

	tetcd.PutTx(then, Config.Webserver.Tunnel.PAM.ServiceName(), loginSettings.PAM.ServiceName)
	tetcd.PutTx(then, Config.Webserver.Lockout(), loginSettings.Lockout)

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to set general settings: %w", err)
	}

	return nil
}

func (d *database) SetGeneralSettings(generalSettings GeneralSettingsDTO) error {

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(generalSettings); err != nil {
		return fmt.Errorf("invalid general settings: %w", err)
	}

	txn := tetcd.NewTxn(context.Background(), d.etcd)
	then := txn.Then()

	tetcd.PutTx(then, Config.Webserver.Tunnel.HelpMail(), generalSettings.HelpMail)
	tetcd.PutTx(then, Config.Webserver.Public.ExternalAddress(), generalSettings.ExternalAddress)
	tetcd.PutTx(then, Config.Wireguard.DNS(), generalSettings.DNS)
	tetcd.PutTx(then, Config.Webserver.Public.DownloadConfigFileName(), generalSettings.DownloadConfigFileName)
	tetcd.PutTx(then, Config.CheckUpdates(), generalSettings.CheckUpdates)

	if err := txn.Commit(); err != nil {
		return fmt.Errorf("failed to set general settings: %w", err)
	}

	return nil
}

func (d *database) SetSessionLifetimeMinutes(lifetimeMinutes int) error {
	return Config.Webserver.Tunnel.MaxSessionLifetimeMinutes().Put(context.Background(), d.etcd, lifetimeMinutes)
}

// If value is below 0 that means the max session is infinite (i.e disabled)
func (d *database) GetSessionLifetimeMinutes() (int, error) {
	return Config.Webserver.Tunnel.MaxSessionLifetimeMinutes().Get(context.Background(), d.etcd)
}

func (d *database) SetSessionInactivityTimeoutMinutes(inactivityTimeout int) error {
	return Config.Webserver.Tunnel.SessionInactivityTimeoutMinutes().Put(context.Background(), d.etcd, inactivityTimeout)
}

func (d *database) GetSessionInactivityTimeoutMinutes() (int, error) {
	return Config.Webserver.Tunnel.SessionInactivityTimeoutMinutes().Get(context.Background(), d.etcd)
}

// Get account lockout threshold setting
func (d *database) GetLockout() (int, error) {
	return Config.Webserver.Lockout().Get(context.Background(), d.etcd)
}

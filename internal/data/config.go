package data

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/go-playground/validator/v10"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type OIDC struct {
	IssuerURL           string   `json:"issuer"`
	ClientSecret        string   `json:"client_secret" sensitive:"yes"`
	ClientID            string   `json:"client_id"`
	GroupsClaimName     string   `json:"group_claim_name"`
	DeviceUsernameClaim string   `json:"device_username_claim"`
	Scopes              []string `json:"scopes"`
}

func (o *OIDC) Equals(b *OIDC) bool {
	if o == b {
		return true
	}

	if o == nil {
		return false
	}

	return o.IssuerURL == b.IssuerURL && o.ClientSecret == b.ClientSecret && o.ClientID == b.ClientID && o.DeviceUsernameClaim == b.DeviceUsernameClaim && slices.Equal(o.Scopes, b.Scopes)
}

type PAM struct {
	ServiceName string `json:"service_name"`
}

type Webauthn struct {
	DisplayName string
	ID          string
	Origin      string
}

type Webserver string

const (
	Tunnel     = Webserver("tunnel")
	Management = Webserver("management")
	Public     = Webserver("public")
)

const (
	ConfigKey = "wag-config-"

	fullJsonConfigKey = ConfigKey + "full"

	helpMailKey          = ConfigKey + "general-help-mail"
	defaultWGFileNameKey = ConfigKey + "general-wg-filename"
	checkUpdatesKey      = ConfigKey + "general-check-updates"

	InactivityTimeoutKey = ConfigKey + "authentication-inactivity-timeout"
	SessionLifetimeKey   = ConfigKey + "authentication-max-session-lifetime"

	LockoutKey           = ConfigKey + "authentication-lockout"
	IssuerKey            = ConfigKey + "authentication-issuer"
	MFAMethodsEnabledKey = ConfigKey + "authentication-methods"
	DefaultMFAMethodKey  = ConfigKey + "authentication-default-method"

	OidcDetailsKey = ConfigKey + "authentication-oidc"
	PamDetailsKey  = ConfigKey + "authentication-pam"

	externalAddressKey = ConfigKey + "network-external-address"
	dnsKey             = ConfigKey + "network-dns"

	MembershipKey = "wag-membership"

	deviceRef = "deviceref-"

	WebServerConfigKey           = ConfigKey + "webserver-"
	TunnelWebServerConfigKey     = WebServerConfigKey + string(Tunnel)
	PublicWebServerConfigKey     = WebServerConfigKey + string(Public)
	ManagementWebServerConfigKey = WebServerConfigKey + string(Management)
)

type WebserverConfiguration struct {
	ListenAddress string `json:"listen_address"`
	Domain        string `json:"domain"`
	TLS           bool   `json:"tls"`
}

func (a *WebserverConfiguration) Equals(b *WebserverConfiguration) bool {
	if a == b {
		return true
	}

	if a == nil {
		return false
	}

	return a.Domain == b.Domain && a.TLS == b.TLS && a.ListenAddress == b.ListenAddress
}

func GetAllWebserverConfigs() (details map[string]WebserverConfiguration, err error) {

	details = make(map[string]WebserverConfiguration)
	response, err := etcd.Get(context.Background(), WebServerConfigKey, clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}

	for _, res := range response.Kvs {
		var conf WebserverConfiguration
		err := json.Unmarshal(res.Value, &conf)
		if err != nil {
			return nil, err
		}

		details[strings.TrimPrefix(string(res.Key), WebServerConfigKey)] = conf
	}

	return details, nil
}

func GetWebserverConfig(forWhat Webserver) (details WebserverConfiguration, err error) {

	response, err := etcd.Get(context.Background(), WebServerConfigKey+string(forWhat))
	if err != nil {
		return WebserverConfiguration{}, err
	}

	if len(response.Kvs) == 0 {
		return WebserverConfiguration{}, errors.New("no web server settings found")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &details)
	return
}

func SetWebserverConfig(forWhat Webserver, details WebserverConfiguration) (err error) {

	switch forWhat {
	case Tunnel, Management, Public:
	default:
		return errors.New("unsupported webserver")
	}

	b, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = etcd.Put(context.Background(), WebServerConfigKey+string(forWhat), string(b))
	return err
}

func getString(key string) (ret string, err error) {
	resp, err := etcd.Get(context.Background(), key)
	if err != nil {
		return "", err
	}

	if len(resp.Kvs) != 1 {
		return "", fmt.Errorf("incorrect number of %s keys", key)
	}

	err = json.Unmarshal(resp.Kvs[0].Value, &ret)
	if err != nil {
		return "", err
	}

	return ret, nil
}

func setObject[T any](key string, obj T) (err error) {

	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	_, err = etcd.Put(context.Background(), key, string(b))
	if err != nil {
		return err
	}

	return
}

func getObject[T any](key string) (ret T, err error) {

	resp, err := etcd.Get(context.Background(), key)
	if err != nil {
		return ret, err
	}

	if len(resp.Kvs) == 0 {
		return ret, fmt.Errorf("no %s keys", key)

	}

	if len(resp.Kvs) > 1 {
		return ret, fmt.Errorf("incorrect number of %s keys (>1)", key)
	}

	b := bytes.NewBuffer(resp.Kvs[0].Value)

	dec := json.NewDecoder(b)
	dec.DisallowUnknownFields()

	err = dec.Decode(&ret)
	if err != nil {
		return ret, err
	}

	return
}

func getInt(key string) (ret int, err error) {
	resp, err := etcd.Get(context.Background(), key)
	if err != nil {
		return 0, err
	}

	if len(resp.Kvs) != 1 {
		return 0, fmt.Errorf("incorrect number of %s keys", key)
	}

	err = json.Unmarshal(resp.Kvs[0].Value, &ret)
	if err != nil {
		return 0, err
	}

	return ret, nil
}

func GetPAM() (details PAM, err error) {

	response, err := etcd.Get(context.Background(), PamDetailsKey)
	if err != nil {
		return PAM{}, err
	}

	if len(response.Kvs) == 0 {
		return PAM{}, errors.New("no PAM settings found")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &details)
	return
}

func GetOidc() (details OIDC, err error) {

	response, err := etcd.Get(context.Background(), OidcDetailsKey)
	if err != nil {
		return OIDC{}, err
	}

	if len(response.Kvs) == 0 {
		return OIDC{}, errors.New("no oidc settings found")
	}

	err = json.Unmarshal(response.Kvs[0].Value, &details)
	return
}

func GetWebauthn() (wba Webauthn, err error) {

	txn := etcd.Txn(context.Background())
	response, err := txn.Then(clientv3.OpGet(IssuerKey),
		clientv3.OpGet(TunnelWebServerConfigKey)).Commit()
	if err != nil {
		return wba, err
	}

	// Issuer: GetIssuer()
	if response.Responses[0].GetResponseRange().Count != 1 {
		return wba, errors.New("no issuer set")
	}

	if response.Responses[1].GetResponseRange().Count != 1 {
		return wba, errors.New("no domain set")
	}

	// Issuer
	json.Unmarshal(response.Responses[0].GetResponseRange().Kvs[0].Value, &wba.DisplayName)

	var tunnelConfig WebserverConfiguration
	//Domain
	err = json.Unmarshal(response.Responses[1].GetResponseRange().Kvs[0].Value, &tunnelConfig)
	if err != nil {
		return wba, err
	}

	if tunnelConfig.Domain == "" {
		return wba, errors.New("domain was empty")
	}

	tunnelURL := tunnelConfig.Domain
	scheme := "http://"
	if tunnelConfig.TLS {
		scheme = "https://"
	}
	tunnelURL = scheme + tunnelURL

	_, port, err := net.SplitHostPort(tunnelConfig.ListenAddress)
	// ignore default ports
	if err == nil && !(tunnelConfig.TLS && port == "443") && !(!tunnelConfig.TLS && port == "80") {
		tunnelURL = tunnelURL + ":" + port
	}

	wba.Origin = tunnelURL
	wba.ID = tunnelConfig.Domain

	return
}

func GetWireguardConfigName() string {
	k, err := getString(defaultWGFileNameKey)
	if err != nil {
		return "wg0.conf"
	}

	if k == "" {
		return "wg0.conf"
	}

	return k
}

func SetDefaultMfaMethod(method string) error {

	data, _ := json.Marshal(method)

	_, err := etcd.Put(context.Background(), DefaultMFAMethodKey, string(data))
	return err
}

func GetDefaultMfaMethod() (string, error) {
	return getString(DefaultMFAMethodKey)
}

func SetAuthenticationMethods(methods []string) error {
	data, _ := json.Marshal(methods)
	_, err := etcd.Put(context.Background(), MFAMethodsEnabledKey, string(data))
	return err
}

func GetEnabledAuthenticationMethods() (result []string, err error) {

	resp, err := etcd.Get(context.Background(), MFAMethodsEnabledKey)
	if err != nil {
		return nil, err
	}

	if len(resp.Kvs) != 1 {
		return nil, fmt.Errorf("incorrect number of %s keys", MFAMethodsEnabledKey)
	}

	err = json.Unmarshal(resp.Kvs[0].Value, &result)
	if err != nil {
		return nil, err
	}

	return
}

func ShouldCheckUpdates() (bool, error) {

	resp, err := etcd.Get(context.Background(), checkUpdatesKey)
	if err != nil {
		return false, err
	}

	var ret bool

	err = json.Unmarshal(resp.Kvs[0].Value, &ret)
	if err != nil {
		return false, err
	}

	if len(resp.Kvs) != 1 {
		return false, fmt.Errorf("incorrect number of %s keys", checkUpdatesKey)
	}

	return ret, nil
}

func GetTunnelDomainUrl() (string, error) {
	details, err := GetWebserverConfig(Tunnel)
	if err != nil {
		return "", err
	}

	if details.Domain == "" {
		return "", nil
	}

	scheme := "http://"
	if details.TLS {
		scheme = "https://"
	}

	url := scheme + details.Domain
	_, port, err := net.SplitHostPort(details.ListenAddress)
	if err == nil && ((scheme == "http://" && port != "80") || (scheme == "https://" && port != "443")) {
		url = url + ":" + port
	}

	return url, nil

}

func SetIssuer(issuer string) error {
	data, _ := json.Marshal(issuer)
	_, err := etcd.Put(context.Background(), IssuerKey, string(data))
	return err
}

func GetIssuer() (string, error) {
	return getString(IssuerKey)
}

func SetHelpMail(helpMail string) error {
	data, _ := json.Marshal(helpMail)
	_, err := etcd.Put(context.Background(), helpMailKey, string(data))
	return err
}

func GetHelpMail() string {

	mail, err := getString(helpMailKey)
	if err != nil {
		return "Server Error"
	}

	return mail
}

func GetExternalAddress() (string, error) {
	return getString(externalAddressKey)
}

func SetDNS(dns []string) error {
	jsonData, _ := json.Marshal(dns)
	_, err := etcd.Put(context.Background(), dnsKey, string(jsonData))
	return err
}

func GetDNS() ([]string, error) {
	resp, err := etcd.Get(context.Background(), dnsKey)
	if err != nil {
		return nil, err
	}

	if len(resp.Kvs) != 1 {
		return nil, fmt.Errorf("incorrect number of %s keys", dnsKey)
	}

	var servers []string
	err = json.Unmarshal(resp.Kvs[0].Value, &servers)
	if err != nil {
		return nil, err
	}

	return servers, nil
}

type LoginSettings struct {
	SessionInactivityTimeoutMinutes int `validate:"required,number" json:"session_inactivity_timeout_minutes"`
	MaxSessionLifetimeMinutes       int `validate:"required,number" json:"max_session_lifetime_minutes"`
	Lockout                         int `validate:"required,number" json:"lockout" `

	DefaultMFAMethod  string   `validate:"required" json:"default_mfa_method"`
	EnabledMFAMethods []string `validate:"required,lt=10,dive,required" json:"enabled_mfa_methods"`

	Issuer string `validate:"required" json:"issuer"`

	OidcDetails OIDC `json:"oidc"`
	PamDetails  PAM  `json:"pam"`
}

func (lg *LoginSettings) Validate() error {
	lg.Issuer = strings.TrimSpace(lg.Issuer)

	validate := validator.New(validator.WithRequiredStructEnabled())

	return validate.Struct(lg)
}

func (lg *LoginSettings) ToWriteOps() (ret []clientv3.Op, err error) {

	if err := lg.Validate(); err != nil {
		return nil, err
	}

	b, _ := json.Marshal(lg.SessionInactivityTimeoutMinutes)
	ret = append(ret, clientv3.OpPut(InactivityTimeoutKey, string(b)))

	b, _ = json.Marshal(lg.MaxSessionLifetimeMinutes)
	ret = append(ret, clientv3.OpPut(SessionLifetimeKey, string(b)))

	b, _ = json.Marshal(lg.Lockout)
	ret = append(ret, clientv3.OpPut(LockoutKey, string(b)))

	b, _ = json.Marshal(lg.DefaultMFAMethod)
	ret = append(ret, clientv3.OpPut(DefaultMFAMethodKey, string(b)))

	b, _ = json.Marshal(lg.EnabledMFAMethods)
	ret = append(ret, clientv3.OpPut(MFAMethodsEnabledKey, string(b)))

	b, _ = json.Marshal(lg.Issuer)
	ret = append(ret, clientv3.OpPut(IssuerKey, string(b)))

	b, _ = json.Marshal(lg.OidcDetails)
	ret = append(ret, clientv3.OpPut(OidcDetailsKey, string(b)))

	b, _ = json.Marshal(lg.PamDetails)
	ret = append(ret, clientv3.OpPut(PamDetailsKey, string(b)))

	return
}

type GeneralSettings struct {
	HelpMail        string `validate:"required,email" json:"help_mail"`
	ExternalAddress string `validate:"required,hostname|hostname_port|ip" json:"external_address"`
	// Allow hostname or ip/4/6 as dns entry for wireguard config
	DNS []string `validate:"omitempty,dive,hostname|ip" json:"dns"`

	WireguardConfigFilename string `validate:"required" json:"wireguard_config_filename"`
	CheckUpdates            bool   `json:"check_updates"`
}

func (gs *GeneralSettings) Validate() error {

	gs.HelpMail = strings.TrimSpace(gs.HelpMail)
	gs.ExternalAddress = strings.TrimSpace(gs.ExternalAddress)
	gs.WireguardConfigFilename = strings.TrimSpace(gs.WireguardConfigFilename)
	for i := range gs.DNS {
		gs.DNS[i] = strings.TrimSpace(gs.DNS[i])
	}

	validate := validator.New(validator.WithRequiredStructEnabled())

	return validate.Struct(gs)
}

func (gs *GeneralSettings) ToWriteOps() (ret []clientv3.Op, err error) {

	if err := gs.Validate(); err != nil {
		return nil, err
	}

	b, _ := json.Marshal(gs.HelpMail)
	ret = append(ret, clientv3.OpPut(helpMailKey, string(b)))

	b, _ = json.Marshal(gs.ExternalAddress)
	ret = append(ret, clientv3.OpPut(externalAddressKey, string(b)))

	b, _ = json.Marshal(gs.DNS)
	ret = append(ret, clientv3.OpPut(dnsKey, string(b)))

	b, _ = json.Marshal(gs.WireguardConfigFilename)
	ret = append(ret, clientv3.OpPut(defaultWGFileNameKey, string(b)))

	b, _ = json.Marshal(gs.CheckUpdates)
	ret = append(ret, clientv3.OpPut(checkUpdatesKey, string(b)))

	return
}

func GetLoginSettings() (s LoginSettings, err error) {
	txn := etcd.Txn(context.Background())
	response, err := txn.Then(
		clientv3.OpGet(InactivityTimeoutKey),
		clientv3.OpGet(SessionLifetimeKey),
		clientv3.OpGet(LockoutKey),
		clientv3.OpGet(DefaultMFAMethodKey),
		clientv3.OpGet(MFAMethodsEnabledKey),
		clientv3.OpGet(IssuerKey),
		clientv3.OpGet(OidcDetailsKey),
		clientv3.OpGet(PamDetailsKey)).Commit()
	if err != nil {
		return s, err
	}

	if response.Responses[0].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[0].GetResponseRange().Kvs[0].Value, &s.SessionInactivityTimeoutMinutes)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[1].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[1].GetResponseRange().Kvs[0].Value, &s.MaxSessionLifetimeMinutes)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[2].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[2].GetResponseRange().Kvs[0].Value, &s.Lockout)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[3].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[3].GetResponseRange().Kvs[0].Value, &s.DefaultMFAMethod)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[4].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[4].GetResponseRange().Kvs[0].Value, &s.EnabledMFAMethods)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[5].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[5].GetResponseRange().Kvs[0].Value, &s.Issuer)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[6].GetResponseRange().Count == 1 {
		s.OidcDetails.GroupsClaimName = "groups"
		err := json.Unmarshal(response.Responses[6].GetResponseRange().Kvs[0].Value, &s.OidcDetails)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[7].GetResponseRange().Count == 1 {
		err := json.Unmarshal(response.Responses[7].GetResponseRange().Kvs[0].Value, &s.PamDetails)
		if err != nil {
			return s, err
		}
	}

	return
}

func GetGeneralSettings() (s GeneralSettings, err error) {
	txn := etcd.Txn(context.Background())
	response, err := txn.Then(clientv3.OpGet(helpMailKey),
		clientv3.OpGet(externalAddressKey),
		clientv3.OpGet(dnsKey),
		clientv3.OpGet(defaultWGFileNameKey),
		clientv3.OpGet(checkUpdatesKey)).Commit()
	if err != nil {
		return s, err
	}

	if response.Responses[0].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[0].GetResponseRange().Kvs[0].Value, &s.HelpMail)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[1].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[1].GetResponseRange().Kvs[0].Value, &s.ExternalAddress)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[2].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[2].GetResponseRange().Kvs[0].Value, &s.DNS)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[3].GetResponseRange().Count == 1 {
		err := json.Unmarshal(response.Responses[3].GetResponseRange().Kvs[0].Value, &s.WireguardConfigFilename)
		if err != nil {
			return s, err
		}
	}

	if response.Responses[4].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[4].GetResponseRange().Kvs[0].Value, &s.CheckUpdates)
		if err != nil {
			return s, err
		}
	}

	return
}

func SetLoginSettings(loginSettings LoginSettings) error {

	writeOps, err := loginSettings.ToWriteOps()
	if err != nil {
		return err
	}

	txn := etcd.Txn(context.Background())
	_, err = txn.Then(writeOps...).Commit()
	return err
}

func SetGeneralSettings(generalSettings GeneralSettings) error {
	txn := etcd.Txn(context.Background())
	writeOPs, err := generalSettings.ToWriteOps()
	if err != nil {
		return err
	}
	_, err = txn.Then(writeOPs...).Commit()
	return err
}

func SetSessionLifetimeMinutes(lifetimeMinutes int) error {
	data, _ := json.Marshal(lifetimeMinutes)
	_, err := etcd.Put(context.Background(), SessionLifetimeKey, string(data))
	return err
}

// If value is below 0 that means the max session is infinite (i.e disabled)
func GetSessionLifetimeMinutes() (int, error) {
	sessionLifeTime, err := getInt(SessionLifetimeKey)
	if err != nil {
		return 0, err
	}

	return sessionLifeTime, nil
}

func SetSessionInactivityTimeoutMinutes(InactivityTimeout int) error {
	data, _ := json.Marshal(InactivityTimeout)

	_, err := etcd.Put(context.Background(), InactivityTimeoutKey, string(data))
	return err
}

func GetSessionInactivityTimeoutMinutes() (int, error) {
	inactivityTimeout, err := getInt(InactivityTimeoutKey)
	if err != nil {
		return 0, err
	}

	return inactivityTimeout, nil
}

// Get account lockout threshold setting
func GetLockout() (int, error) {
	lockout, err := getInt(LockoutKey)
	if err != nil {
		return 0, err
	}

	return lockout, nil
}

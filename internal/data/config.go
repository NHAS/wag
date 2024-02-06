package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	clientv3 "go.etcd.io/etcd/client/v3"
)

type OIDC struct {
	IssuerURL       string
	ClientSecret    string
	ClientID        string
	GroupsClaimName string
}

type PAM struct {
	ServiceName string
}

type Webauthn struct {
	DisplayName string
	ID          string
	Origin      string
}

const (
	fullJsonConfigKey = "wag-config-full"

	helpMailKey          = "wag-config-general-help-mail"
	defaultWGFileNameKey = "wag-config-general-wg-filename"
	checkUpdatesKey      = "wag-config-general-check-updates"

	InactivityTimeoutKey = "wag-config-authentication-inactivity-timeout"
	SessionLifetimeKey   = "wag-config-authentication-max-session-lifetime"
	LockoutKey           = "wag-config-authentication-lockout"
	IssuerKey            = "wag-config-authentication-issuer"
	DomainKey            = "wag-config-authentication-domain"
	MethodsEnabledKey    = "wag-config-authentication-methods"
	DefaultMFAMethodKey  = "wag-config-authentication-default-method"

	OidcDetailsKey = "wag-config-authentication-oidc"
	PamDetailsKey  = "wag-config-authentication-pam"

	externalAddressKey = "wag-config-network-external-address"
	dnsKey             = "wag-config-network-dns"
)

func getGeneric(key string) (string, error) {
	resp, err := etcd.Get(context.Background(), key)
	if err != nil {
		return "", err
	}

	if len(resp.Kvs) != 1 {
		return "", fmt.Errorf("incorrect number of %s keys", key)
	}

	return string(resp.Kvs[0].Value), nil
}

func SetPAM(details PAM) error {
	d, err := json.Marshal(details)
	if err != nil {
		return err
	}

	_, err = etcd.Put(context.Background(), PamDetailsKey, string(d))
	return err
}

func GetPAM() (details PAM, err error) {

	v, err := getGeneric(PamDetailsKey)
	if err != nil {
		return PAM{}, nil
	}

	err = json.Unmarshal([]byte(v), &details)
	return
}

func SetOidc(details OIDC) error {
	d, err := json.Marshal(details)
	if err != nil {
		return err
	}

	_, err = etcd.Put(context.Background(), OidcDetailsKey, string(d))
	return err
}

func GetOidc() (details OIDC, err error) {

	v, err := getGeneric(OidcDetailsKey)
	if err != nil {
		return OIDC{}, nil
	}

	err = json.Unmarshal([]byte(v), &details)
	return
}

func GetWebauthn() (wba Webauthn, err error) {

	txn := etcd.Txn(context.Background())
	response, err := txn.Then(clientv3.OpGet(IssuerKey),
		clientv3.OpGet(DomainKey)).Commit()
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

	tunnelURL, err := url.Parse(string(response.Responses[1].GetResponseRange().Kvs[0].Value))
	if err != nil {
		return wba, errors.New("unable to parse Authenticators.DomainURL: " + err.Error())
	}

	wba.Origin = tunnelURL.String()
	wba.DisplayName = string(response.Responses[0].GetResponseRange().Kvs[0].Value)
	wba.ID = strings.Split(tunnelURL.Host, ":")[0]

	return
}

func SetWireguardConfigName(wgConfig string) error {
	_, err := etcd.Put(context.Background(), defaultWGFileNameKey, wgConfig)
	return err
}

func GetWireguardConfigName() string {
	k, err := getGeneric(defaultWGFileNameKey)
	if err != nil {
		return "wg0.conf"
	}

	if k == "" {
		return "wg0.conf"
	}

	return k
}

func SetDefaultMfaMethod(method string) error {
	_, err := etcd.Put(context.Background(), DefaultMFAMethodKey, method)
	return err
}

func GetDefaultMfaMethod() (string, error) {
	return getGeneric(DefaultMFAMethodKey)
}

func SetAuthenticationMethods(methods []string) error {
	data, _ := json.Marshal(methods)
	_, err := etcd.Put(context.Background(), MethodsEnabledKey, string(data))
	return err
}

func GetAuthenicationMethods() (result []string, err error) {

	val, err := getGeneric(MethodsEnabledKey)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(val), &result)

	return
}

func SetCheckUpdates(doChecks bool) error {
	_, err := etcd.Put(context.Background(), checkUpdatesKey, strconv.FormatBool(doChecks))
	return err
}

func CheckUpdates() (bool, error) {

	val, err := getGeneric(checkUpdatesKey)
	if err != nil {
		return false, err
	}

	return val == "true", nil
}

func SetDomain(domain string) error {
	_, err := etcd.Put(context.Background(), DomainKey, domain)
	return err
}

func GetDomain() (string, error) {
	return getGeneric(DomainKey)
}

func SetIssuer(issuer string) error {
	_, err := etcd.Put(context.Background(), IssuerKey, issuer)
	return err
}

func GetIssuer() (string, error) {
	return getGeneric(IssuerKey)
}

func SetHelpMail(helpMail string) error {
	_, err := etcd.Put(context.Background(), helpMailKey, helpMail)
	return err
}

func GetHelpMail() string {

	mail, err := getGeneric(helpMailKey)
	if err != nil {
		return "Server Error"
	}

	return mail
}

func SetExternalAddress(externalAddress string) error {
	_, err := etcd.Put(context.Background(), externalAddressKey, externalAddress)
	return err
}

func GetExternalAddress() (string, error) {
	return getGeneric(externalAddressKey)
}

func SetDNS(dns []string) error {
	jsonData, _ := json.Marshal(dns)
	_, err := etcd.Put(context.Background(), dnsKey, string(jsonData))
	return err
}

func GetDNS() ([]string, error) {

	jsonData, err := getGeneric(dnsKey)
	if err != nil {
		return nil, err
	}

	var servers []string
	err = json.Unmarshal([]byte(jsonData), &servers)
	if err != nil {
		return nil, err
	}

	return servers, nil
}

type Settings struct {
	ExternalAddress                 string
	Lockout                         int
	Issuer                          string
	Domain                          string
	SessionInactivityTimeoutMinutes int
	MaxSessionLifetimeMinutes       int
	HelpMail                        string
	DNS                             []string
}

func GetAllSettings() (s Settings, err error) {

	txn := etcd.Txn(context.Background())
	response, err := txn.Then(clientv3.OpGet(helpMailKey),
		clientv3.OpGet(externalAddressKey),
		clientv3.OpGet(InactivityTimeoutKey),
		clientv3.OpGet(SessionLifetimeKey),
		clientv3.OpGet(LockoutKey),
		clientv3.OpGet(dnsKey),
		clientv3.OpGet(IssuerKey),
		clientv3.OpGet(DomainKey)).Commit()
	if err != nil {
		return s, err
	}

	if response.Responses[0].GetResponseRange().Count == 1 {
		s.HelpMail = string(response.Responses[0].GetResponseRange().Kvs[0].Value)
	}

	if response.Responses[1].GetResponseRange().Count == 1 {
		s.ExternalAddress = string(response.Responses[1].GetResponseRange().Kvs[0].Value)
	}

	if response.Responses[2].GetResponseRange().Count == 1 {
		s.SessionInactivityTimeoutMinutes, err = strconv.Atoi(string(response.Responses[2].GetResponseRange().Kvs[0].Value))
		if err != nil {
			return
		}
	}

	if response.Responses[3].GetResponseRange().Count == 1 {
		s.MaxSessionLifetimeMinutes, err = strconv.Atoi(string(response.Responses[3].GetResponseRange().Kvs[0].Value))
		if err != nil {
			return
		}
	}

	if response.Responses[4].GetResponseRange().Count == 1 {
		s.Lockout, err = strconv.Atoi(string(response.Responses[4].GetResponseRange().Kvs[0].Value))
		if err != nil {
			return
		}
	}

	if response.Responses[5].GetResponseRange().Count == 1 {
		err = json.Unmarshal(response.Responses[5].GetResponseRange().Kvs[0].Value, &s.DNS)
		if err != nil {
			return s, err
		}

	}

	if response.Responses[6].GetResponseRange().Count == 1 {
		s.Issuer = string(response.Responses[6].GetResponseRange().Kvs[0].Value)
	}

	if response.Responses[7].GetResponseRange().Count == 1 {
		s.Domain = string(response.Responses[7].GetResponseRange().Kvs[0].Value)
	}

	return
}

// Due to how these functions are used there is quite a highlikelihood that splicing will occur
// We need to update these to make it that it checks the key revision against the pulled version
func SetSessionLifetimeMinutes(lifetimeMinutes int) error {
	_, err := etcd.Put(context.Background(), SessionLifetimeKey, strconv.Itoa(lifetimeMinutes))
	return err
}

func GetSessionLifetimeMinutes() (int, error) {
	sessionLifeTime, err := getGeneric(SessionLifetimeKey)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(sessionLifeTime)
}

func SetSessionInactivityTimeoutMinutes(InactivityTimeout int) error {
	_, err := etcd.Put(context.Background(), InactivityTimeoutKey, strconv.Itoa(InactivityTimeout))
	return err
}

func GetSessionInactivityTimeoutMinutes() (int, error) {
	inactivityTimeout, err := getGeneric(InactivityTimeoutKey)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(inactivityTimeout)
}

func SetLockout(accountLockout int) error {
	if accountLockout < 1 {
		return errors.New("cannot set lockout to be below 1 as all accounts would be locked out")
	}
	_, err := etcd.Put(context.Background(), LockoutKey, strconv.Itoa(accountLockout))
	return err
}

func GetLockout() (int, error) {
	lockout, err := getGeneric(LockoutKey)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(lockout)
}

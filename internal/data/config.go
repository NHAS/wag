package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	fullJsonConfigKey    = "wag-config-full"
	helpMailKey          = "wag-config-general-help-mail"
	inactivityTimeoutKey = "wag-config-authentication-inactivity-timeout"
	sessionLifetimeKey   = "wag-config-authentication-max-session-lifetime"
	lockoutKey           = "wag-config-authentication-lockout"
	issuerKey            = "wag-config-authentication-issuer"
	domainKey            = "wag-config-authentication-domain"
	defaultMFAMethodKey  = "wag-config-authentication-default-method"
	externalAddressKey   = "wag-config-network-external-address"
	dnsKey               = "wag-config-network-dns"
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

func SetDomain(domain string) error {
	_, err := etcd.Put(context.Background(), domainKey, domain)
	return err
}

func GetDomain() (string, error) {
	return getGeneric(domainKey)
}

func SetIssuer(issuer string) error {
	_, err := etcd.Put(context.Background(), issuerKey, issuer)
	return err
}

func GetIssuer() (string, error) {
	return getGeneric(issuerKey)
}

func SetHelpMail(helpMail string) error {
	_, err := etcd.Put(context.Background(), helpMailKey, helpMail)
	return err
}

func GetHelpMail() (string, error) {
	return getGeneric(helpMailKey)
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
		clientv3.OpGet(inactivityTimeoutKey),
		clientv3.OpGet(sessionLifetimeKey),
		clientv3.OpGet(lockoutKey),
		clientv3.OpGet(dnsKey),
		clientv3.OpGet(issuerKey),
		clientv3.OpGet(domainKey)).Commit()
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
	_, err := etcd.Put(context.Background(), sessionLifetimeKey, strconv.Itoa(lifetimeMinutes))
	return err
}

func GetSessionLifetimeMinutes() (int, error) {
	sessionLifeTime, err := getGeneric(sessionLifetimeKey)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(sessionLifeTime)
}

func SetSessionInactivityTimeoutMinutes(InactivityTimeout int) error {
	_, err := etcd.Put(context.Background(), inactivityTimeoutKey, strconv.Itoa(InactivityTimeout))
	return err
}

func GetSessionInactivityTimeoutMinutes() (int, error) {
	inactivityTimeout, err := getGeneric(inactivityTimeoutKey)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(inactivityTimeout)
}

func SetLockout(accountLockout int) error {
	if accountLockout < 1 {
		return errors.New("cannot set lockout to be below 1 as all accounts would be locked out")
	}
	_, err := etcd.Put(context.Background(), lockoutKey, strconv.Itoa(accountLockout))
	return err
}

func GetLockout() (int, error) {
	lockout, err := getGeneric(lockoutKey)
	if err != nil {
		return 0, err
	}

	return strconv.Atoi(lockout)
}

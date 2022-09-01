package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"wag/utils"
)

type webserverDetails struct {
	ListenAddress string
	CertPath      string
	KeyPath       string
}

func (wb webserverDetails) SupportsTLS() bool {
	return len(wb.CertPath) > 0 && len(wb.KeyPath) > 0
}

type Acl struct {
	Mfa   []string
	Allow []string
}

type Acls struct {
	Groups       map[string][]string
	rGroupLookup map[string][]string
	Policies     map[string]*Acl
}

type config struct {
	Proxied               bool
	WgDevName             string
	HelpMail              string
	Lockout               int
	ExternalAddress       string
	SessionTimeoutMinutes int
	Webserver             struct {
		Public webserverDetails
		Tunnel webserverDetails
	}
	DatabaseLocation string
	Issuer           string
	VPNRange         *net.IPNet `json:"-"`
	VPNServerAddress net.IP     `json:"-"`

	Acls Acls
}

var (
	valuesLock sync.RWMutex
	values     config
)

func Values() config {
	valuesLock.RLock()
	defer valuesLock.RUnlock()

	v := values

	return v
}

func GetEffectiveAcl(username string) Acl {
	valuesLock.RLock()
	defer valuesLock.RUnlock()

	var dereferencedAcl Acl
	if ptrAcl, ok := values.Acls.Policies["*"]; ok {
		dereferencedAcl = *ptrAcl
	}

	//If the user has any user specific rules, add those
	if acl, ok := values.Acls.Policies[username]; ok {
		dereferencedAcl.Allow = append(dereferencedAcl.Allow, acl.Allow...)
		dereferencedAcl.Mfa = append(dereferencedAcl.Mfa, acl.Mfa...)
	}

	//This may get expensive if the user belongs to a large number of
	for _, groups := range values.Acls.rGroupLookup[username] {
		//If the user belongs to a series of groups, grab those, and add their rules
		if acl, ok := values.Acls.Policies[groups]; ok {
			dereferencedAcl.Allow = append(dereferencedAcl.Allow, acl.Allow...)
			dereferencedAcl.Mfa = append(dereferencedAcl.Mfa, acl.Mfa...)
		}
	}

	return dereferencedAcl
}

func Load(path string) error {
	valuesLock.Lock()
	defer valuesLock.Unlock()

	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	err = json.Unmarshal(configBytes, &values)
	if err != nil {
		return fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	i, err := net.InterfaceByName(values.WgDevName)
	if err == nil {

		addresses, err := i.Addrs()
		if err != nil {
			return fmt.Errorf("Unable to get address for interface %s: %v", values.WgDevName, err)
		}

		if len(addresses) < 1 {
			return errors.New("Wireguard interface does not have an ip address")
		}

		values.VPNServerAddress = net.ParseIP(utils.GetIP(addresses[0].String()))
		if values.VPNServerAddress == nil {
			return fmt.Errorf("Unable to find server address from tunnel interface:  '%s'", utils.GetIP(addresses[0].String()))
		}

		_, values.VPNRange, err = net.ParseCIDR(addresses[0].String())
		if err != nil {
			return errors.New("Unable to parse VPN range from tune device address: " + addresses[0].String() + " : " + err.Error())
		}

	}

	for group, members := range values.Acls.Groups {
		if !strings.HasPrefix(group, "group:") {
			return fmt.Errorf("Group does not have 'group:' prefix: %s", group)
		}

		for _, user := range members {
			values.Acls.rGroupLookup[user] = append(values.Acls.rGroupLookup[user], group)
		}
	}

	globalAcl, ok := values.Acls.Policies["*"]
	if !ok {
		//If there is no default policy default make an empy one so we can add the vpn server address
		values.Acls.Policies["*"] = &Acl{}
		globalAcl = values.Acls.Policies["*"]
	}

	if values.VPNServerAddress != nil {
		globalAcl.Allow = append(globalAcl.Allow, values.VPNServerAddress.String()+"/32")
	}

	for _, acl := range values.Acls.Policies {

		for _, addr := range acl.Allow {
			if net.ParseIP(addr) == nil {
				_, _, err := net.ParseCIDR(addr)
				if err != nil {
					return fmt.Errorf("unable to parse address as ipv4: %s", addr)
				}
			}
		}

		for _, addr := range acl.Mfa {
			if net.ParseIP(addr) == nil {
				_, _, err := net.ParseCIDR(addr)
				if err != nil {
					return fmt.Errorf("unable to parse address as ipv4: %s", addr)
				}
			}
		}
	}

	return nil
}

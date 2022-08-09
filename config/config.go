package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
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
	Groups   map[string][]string
	Policies map[string]*Acl
}

func (a Acls) GetEffectiveAcl(username string) (Acl, bool) {
	if acl, ok := a.Policies[username]; ok {
		return *acl, true
	}

	globalAcl, ok := a.Policies["*"]

	return *globalAcl, ok
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

func addPolicy(username string, acls *Acl) {

	if _, ok := values.Acls.Policies[username]; !ok {
		values.Acls.Policies[username] = &Acl{}
	}

	values.Acls.Policies[username].Allow = append(values.Acls.Policies[username].Allow, acls.Allow...)
	values.Acls.Policies[username].Mfa = append(values.Acls.Policies[username].Mfa, acls.Mfa...)
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

		if len(members) == 0 {
			log.Println("Warning, empty group: ", group)
			continue
		}

		acls, ok := values.Acls.Policies[group]
		if !ok {
			return fmt.Errorf("group defined, but not used: %s", group)
		}

		//Flatten the groups out so each user has fully descriptive acls
		for _, memberName := range members {
			addPolicy(memberName, acls)
		}

		//Remove the group from the policies after we've resolved what each users actual acls are
		delete(values.Acls.Policies, group)

	}

	globalAcl, ok := values.Acls.Policies["*"]
	if !ok {
		values.Acls.Policies["*"] = &Acl{}
		globalAcl = values.Acls.Policies["*"]
	}

	if values.VPNServerAddress != nil {
		globalAcl.Allow = append(globalAcl.Allow, values.VPNServerAddress.String()+"/32")
	}

	for owner, acl := range values.Acls.Policies {

		if owner == "*" {
			continue
		}

		values.Acls.Policies[owner].Allow = append(values.Acls.Policies[owner].Allow, globalAcl.Allow...)

		for _, addr := range acl.Allow {
			if net.ParseIP(addr) == nil {
				_, _, err := net.ParseCIDR(addr)
				if err != nil {
					return fmt.Errorf("unable to parse address as ipv4: %s", addr)
				}
			}
		}

		values.Acls.Policies[owner].Mfa = append(values.Acls.Policies[owner].Mfa, globalAcl.Mfa...)

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

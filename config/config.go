package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
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

//Yes, if clients hold on to the vpnRange or ip value, they could mutate the underlying state. But seriously fuck it.
func SetVpnRange(vpnRange *net.IPNet) {
	valuesLock.RLock()
	defer valuesLock.RUnlock()

	values.VPNRange = vpnRange
}

func SetVpnServerAddress(ip net.IP) {
	valuesLock.RLock()
	defer valuesLock.RUnlock()

	values.VPNServerAddress = ip
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

	globalAcl := values.Acls.Policies["*"]

	for owner, acl := range values.Acls.Policies {

		values.Acls.Policies[owner].Allow = append(values.Acls.Policies[owner].Allow, globalAcl.Allow...)

		for _, addr := range acl.Allow {
			if net.ParseIP(addr) == nil {
				_, _, err := net.ParseCIDR(addr)
				if err != nil {
					return fmt.Errorf("Unable to parse address as ipv4: %s", addr)
				}
			}
		}

		values.Acls.Policies[owner].Mfa = append(values.Acls.Policies[owner].Mfa, globalAcl.Mfa...)

		for _, addr := range acl.Mfa {
			if net.ParseIP(addr) == nil {
				_, _, err := net.ParseCIDR(addr)
				if err != nil {
					return fmt.Errorf("Unable to parse address as ipv4: %s", addr)
				}
			}
		}
	}

	return nil
}

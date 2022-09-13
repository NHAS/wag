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
	path                  string
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

	DNS []string

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

func load(path string) (c config, err error) {
	configBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	err = json.Unmarshal(configBytes, &c)
	if err != nil {
		return c, fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	i, err := net.InterfaceByName(c.WgDevName)
	if err == nil {

		addresses, err := i.Addrs()
		if err != nil {
			return c, fmt.Errorf("Unable to get address for interface %s: %v", c.WgDevName, err)
		}

		if len(addresses) < 1 {
			return c, errors.New("Wireguard interface does not have an ip address")
		}

		c.VPNServerAddress = net.ParseIP(utils.GetIP(addresses[0].String()))
		if c.VPNServerAddress == nil {
			return c, fmt.Errorf("Unable to find server address from tunnel interface:  '%s'", utils.GetIP(addresses[0].String()))
		}

		_, c.VPNRange, err = net.ParseCIDR(addresses[0].String())
		if err != nil {
			return c, errors.New("Unable to parse VPN range from tune device address: " + addresses[0].String() + " : " + err.Error())
		}

	}

	c.Acls.rGroupLookup = map[string][]string{}

	for group, members := range c.Acls.Groups {
		if !strings.HasPrefix(group, "group:") {
			return c, fmt.Errorf("Group does not have 'group:' prefix: %s", group)
		}

		for _, user := range members {
			c.Acls.rGroupLookup[user] = append(c.Acls.rGroupLookup[user], group)
		}
	}

	globalAcl, ok := c.Acls.Policies["*"]
	if !ok {
		//If there is no default policy default make an empy one so we can add the vpn server address
		c.Acls.Policies["*"] = &Acl{}
		globalAcl = c.Acls.Policies["*"]
	}

	if c.VPNServerAddress != nil {
		globalAcl.Allow = append(globalAcl.Allow, c.VPNServerAddress.String()+"/32")
	}

	// Make sure we resolve the dns servers in case someone added them as domains, so that clients dont get stuck trying to use the domain dns servers to look up the dns servers
	for i := 0; i < len(c.DNS); i++ {
		newAddress, err := parseAddress(c.DNS[i])
		if err != nil {
			return c, err
		}

		for ii := range newAddress {

			// For the first new address, replace the domain entry in the Allow'd acls with an IP
			if ii == 0 {
				c.DNS[i] = newAddress[ii]
				continue
			}

			c.DNS = append(c.DNS, newAddress[ii])
		}

		globalAcl.Allow = append(globalAcl.Allow, newAddress...)
	}

	for _, acl := range c.Acls.Policies {

		for i := 0; i < len(acl.Allow); i++ {
			newAddress, err := parseAddress(acl.Allow[i])
			if err != nil {
				return c, err
			}

			// If we get some new addresses it the entry was a domain that was subsequently resolved to some ipv4 addresses
			for ii := range newAddress {

				// For the first new address, replace the domain entry in the Allow'd acls with an IP
				if ii == 0 {
					acl.Allow[i] = newAddress[ii]
					continue
				}

				acl.Allow = append(acl.Allow, newAddress[ii])
			}

		}

		for i := 0; i < len(acl.Mfa); i++ {
			newAddress, err := parseAddress(acl.Mfa[i])
			if err != nil {
				return c, err
			}

			// If we get some new addresses it the entry was a domain that was subsequently resolved to some ipv4 addresses
			for ii := range newAddress {

				// For the first new address, replace the domain entry in the Mfa'd acls with an IP
				if ii == 0 {
					acl.Mfa[i] = newAddress[ii]
					continue
				}

				acl.Mfa = append(acl.Mfa, newAddress[ii])
			}
		}
	}

	return c, nil
}

func Load(path string) error {
	valuesLock.Lock()
	defer valuesLock.Unlock()

	if values.path != "" {
		return errors.New("Configuration has already been loaded, please use 'Reload' instead")
	}

	newConfig, err := load(path)
	if err != nil {
		return err
	}

	values = newConfig
	values.path = path

	return nil
}

func Reload() error {
	valuesLock.Lock()
	defer valuesLock.Unlock()

	previousPath := values.path
	newConfig, err := load(values.path)
	if err != nil {
		return errors.New("Failed to reload configuration file: " + err.Error())
	}
	values = newConfig
	values.path = previousPath

	return nil
}

func parseAddress(address string) ([]string, error) {

	if net.ParseIP(address) == nil {

		_, _, err := net.ParseCIDR(address)
		if err != nil {

			//If we suspect this is a domain
			addresses, err := net.LookupIP(address)
			if err != nil {
				return nil, fmt.Errorf("unable to resolve address from: %s", address)
			}

			if len(addresses) == 0 {
				return nil, fmt.Errorf("no addresses for %s", address)
			}

			output := []string{}
			addedSomething := false
			for _, addr := range addresses {
				if addr.To4() != nil {
					addedSomething = true
					output = append(output, addr.String())
				}
			}

			if !addedSomething {
				return nil, fmt.Errorf("no addresses for domain %s were added, potentially because they were all ipv6 which is unsupported", address)
			}

			return output, nil
		}
	}

	return nil, nil
}

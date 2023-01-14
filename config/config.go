package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/webserver/authenticators"
	"github.com/NHAS/webauthn/webauthn"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var Version string

type webserverDetails struct {
	CertPath string `json:",omitempty"`
	KeyPath  string `json:",omitempty"`
}

type usualWeb struct {
	ListenAddress string
	webserverDetails
}

type tunnelWeb struct {
	webserverDetails
	Port string
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

type Config struct {
	path                            string
	Socket                          string `json:",omitempty"`
	Proxied                         bool
	HelpMail                        string
	Lockout                         int
	ExternalAddress                 string
	MaxSessionLifetimeMinutes       int
	SessionInactivityTimeoutMinutes int
	Webserver                       struct {
		Public usualWeb
		Tunnel tunnelWeb
	}
	Authenticators struct {
		DefaultMethod string `json:",omitempty"`

		Methods   []string `json:",omitempty"`
		DomainURL string

		OIDC struct {
			IssuerURL       string
			ClientSecret    string
			ClientID        string
			GroupsClaimName string `json:",omitempty"`
		} `json:",omitempty"`

		//Not externally configurable
		Webauthn *webauthn.WebAuthn `json:"-"`
	}
	Wireguard struct {
		DevName             string
		ListenPort          int
		PrivateKey          string
		Address             string
		MTU                 int
		PersistentKeepAlive int

		//Not externally configurable
		External      bool       `json:"-"`
		Range         *net.IPNet `json:"-"`
		ServerAddress net.IP     `json:"-"`
	}
	DatabaseLocation string
	Issuer           string

	DNS []string `json:",omitempty"`

	Acls Acls
}

var (
	valuesLock sync.RWMutex
	values     Config
)

func Values() Config {
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

// Used in authentication methods that can specify user groups directly (for the moment just oidc)
// Adds groups to username, even if user does not exist in the config.json file, so GetEffectiveAcls works
func AddVirtualUser(username string, groups []string) {
	valuesLock.Lock()
	defer valuesLock.Unlock()

	values.Acls.rGroupLookup[username] = groups
}

func load(path string) (c Config, err error) {
	configFile, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}
	dec := json.NewDecoder(configFile)
	dec.DisallowUnknownFields()

	err = dec.Decode(&c)
	if err != nil {
		return c, fmt.Errorf("Unable to load configuration file from %s: %v", path, err)
	}

	if c.Socket == "" {
		c.Socket = control.DefaultWagSocket
	}

	i, err := net.InterfaceByName(c.Wireguard.DevName)
	if err == nil {
		//A device already exists, so we're assuming it was externally set up (with something like wg-quick)
		c.Wireguard.External = true

		addresses, err := i.Addrs()
		if err != nil {
			return c, fmt.Errorf("Unable to get address for interface %s: %v", c.Wireguard.DevName, err)
		}

		if len(addresses) < 1 {
			return c, errors.New("Wireguard interface does not have an ip address")
		}

		addr := addresses[0].String()
		for i := len(addr) - 1; i > 0; i-- {
			if addr[i] == ':' || addr[i] == '/' {
				addr = addr[:i]
				break
			}
		}

		c.Wireguard.ServerAddress = net.ParseIP(addr)
		if c.Wireguard.ServerAddress == nil {
			return c, fmt.Errorf("Unable to find server address from tunnel interface:  '%s'", addr)
		}

		_, c.Wireguard.Range, err = net.ParseCIDR(addresses[0].String())
		if err != nil {
			return c, errors.New("Unable to parse VPN range from tune device address: " + addresses[0].String() + " : " + err.Error())
		}

	} else {
		// A device doesnt already exist
		c.Wireguard.ServerAddress, c.Wireguard.Range, err = net.ParseCIDR(c.Wireguard.Address)
		if err != nil {
			return c, errors.New("wireguard address invalid: " + err.Error())
		}

		_, err = wgtypes.ParseKey(c.Wireguard.PrivateKey)
		if err != nil {
			return c, errors.New("cannot parse wireguard key: " + err.Error())
		}

		if c.Wireguard.ListenPort == 0 {
			return c, errors.New("wireguard ListenPort not set")
		}

		if c.Wireguard.MTU == 0 {
			c.Wireguard.MTU = 1420
		}

		if c.Wireguard.PersistentKeepAlive == 0 {
			c.Wireguard.PersistentKeepAlive = 25
		}
	}

	if len(c.Acls.Policies) == 0 {
		return c, errors.New("no policies set under acls.Policies")
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

	if c.Wireguard.ServerAddress != nil {
		globalAcl.Allow = append(globalAcl.Allow, c.Wireguard.ServerAddress.String()+"/32")
	}

	// Make sure we resolve the dns servers in case someone added them as domains, so that clients dont get stuck trying to use the domain dns servers to look up the dns servers
	globalAcl.Allow = append(globalAcl.Allow, c.DNS...)

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

	if len(c.Authenticators.Methods) == 0 {
		for method := range authenticators.MFA {
			c.Authenticators.Methods = append(c.Authenticators.Methods, method)
		}
	}

	resultMFAMap := make(map[string]authenticators.Authenticator)
	for _, method := range c.Authenticators.Methods {
		_, ok := authenticators.MFA[method]
		if !ok {
			return c, errors.New("mfa method invalid: " + method)
		}

		resultMFAMap[method] = authenticators.MFA[method]

		settings := make(map[string]string)
		switch method {

		case "oidc":
			if c.Authenticators.DomainURL == "" {
				return c, errors.New("Authenticators.DomainURL unset, needed for oidc")
			}

			if c.Authenticators.OIDC.GroupsClaimName == "" {
				c.Authenticators.OIDC.GroupsClaimName = "groups"
			}

			if c.Authenticators.OIDC.IssuerURL == "" {
				return c, errors.New("OIDC issuer url is not set, but oidc authentication method is enabled")
			}

			tunnelURL, err := url.Parse(c.Authenticators.OIDC.IssuerURL)
			if err != nil {
				return c, errors.New("unable to parse Authenticators.OIDC.IssuerURL: " + err.Error())
			}

			if tunnelURL.Scheme != "https" && tunnelURL.Scheme != "http" {
				return c, errors.New("Authenticators.OIDC.IssuerURL was not HTTP/HTTPS")
			}

			if tunnelURL.Scheme == "http" {
				log.Println("[WARNING] OIDC issuer url is http, this may be insecure")
			}

			if c.Authenticators.OIDC.ClientSecret == "" {
				return c, errors.New("Authenticators.OIDC.ClientSecret is empty, but oidc authentication method is enabled")
			}

			if c.Authenticators.OIDC.ClientID == "" {
				return c, errors.New("Authenticators.OIDC.ClientID is empty, but oidc authentication method is enabled")
			}

			settings["ClientID"] = c.Authenticators.OIDC.ClientID
			settings["ClientSecret"] = c.Authenticators.OIDC.ClientSecret
			settings["IssuerURL"] = c.Authenticators.OIDC.IssuerURL
			settings["DomainURL"] = c.Authenticators.DomainURL

		case "webauthn":

			if c.Authenticators.DomainURL == "" {
				return c, errors.New("Authenticators.DomainURL unset, needed for webauthn")
			}

			tunnelURL, err := url.Parse(c.Authenticators.DomainURL)
			if err != nil {
				return c, errors.New("unable to parse Authenticators.DomainURL: " + err.Error())
			}

			if !c.Webserver.Tunnel.SupportsTLS() {
				return c, errors.New("Tunnel does not support TLS (no cert/key given)")
			}

			if tunnelURL.Scheme != "https" {
				return c, errors.New("Authenticators.DomainURL was not HTTPS, yet webauthn was enabled (javascript wont be able to access window.PublicKeyCredential)")
			}

			c.Authenticators.Webauthn, err = webauthn.New(&webauthn.Config{
				RPDisplayName: c.Issuer,                              // Display Name for your site
				RPID:          strings.Split(tunnelURL.Host, ":")[0], // Generally the domain name for your site
				RPOrigin:      c.Authenticators.DomainURL,            // The origin URL for WebAuthn requests
			})

			if err != nil {
				return c, errors.New("could not configure webauthn domain: " + err.Error())
			}

		}

		if err := resultMFAMap[method].Init(settings); err != nil {
			return c, err
		}
	}

	if c.Authenticators.DefaultMethod != "" {
		_, ok = resultMFAMap[c.Authenticators.DefaultMethod]
		if !ok {
			return c, errors.New("default mfa method invalid: " + c.Authenticators.DefaultMethod + " valid methods: " + strings.Join(c.Authenticators.Methods, ","))
		}
	}

	if len(c.Authenticators.Methods) == 1 {
		c.Authenticators.DefaultMethod = c.Authenticators.Methods[len(c.Authenticators.Methods)-1]
	}

	// Remove all uneeded MFA methods from the MFA map
	authenticators.MFA = resultMFAMap

	return c, nil
}

func Load(path string) error {
	valuesLock.Lock()
	defer valuesLock.Unlock()

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
	ip := net.ParseIP(address)
	if ip == nil {

		_, cidr, err := net.ParseCIDR(address)
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
					output = append(output, addr.String()+"/32")
				}
			}

			if !addedSomething {
				return nil, fmt.Errorf("no addresses for domain %s were added, potentially because they were all ipv6 which is unsupported", address)
			}

			return output, nil
		}

		return []string{cidr.String()}, nil
	}

	return []string{ip.To4().String() + "/32"}, nil
}

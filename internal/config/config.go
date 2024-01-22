package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/internal/webserver/authenticators"
	"github.com/NHAS/wag/pkg/control"
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

type Acls struct {
	Groups map[string][]string `json:",omitempty"`
	//Username -> groups name
	rGroupLookup map[string]map[string]bool
	Policies     map[string]*acls.Acl
}

type Config struct {
	path          string
	Socket        string `json:",omitempty"`
	GID           *int   `json:",omitempty"`
	CheckUpdates  bool   `json:",omitempty"`
	NumberProxies int
	Proxied       bool
	ExposePorts   []string `json:",omitempty"`
	NAT           *bool

	MFATemplatesDirectory string `json:",omitempty"`

	HelpMail                        string
	Lockout                         int
	ExternalAddress                 string
	MaxSessionLifetimeMinutes       int
	SessionInactivityTimeoutMinutes int

	DownloadConfigFileName string `json:",omitempty"`

	ManagementUI struct {
		usualWeb
		Enabled bool
	} `json:",omitempty"`

	Webserver struct {
		Public usualWeb
		Tunnel tunnelWeb
	}

	Clustering struct {
		Name             string
		ListenAddresses  []string
		Peers            map[string][]string
		DatabaseLocation string
		ETCDLogLevel     string
	}

	Authenticators struct {
		DefaultMethod string `json:",omitempty"`
		Issuer        string
		Methods       []string `json:",omitempty"`
		DomainURL     string

		OIDC struct {
			IssuerURL       string
			ClientSecret    string
			ClientID        string
			GroupsClaimName string `json:",omitempty"`
		} `json:",omitempty"`

		PAM struct {
			ServiceName string
		} `json:",omitempty"`

		//Not externally configurable
		Webauthn *webauthn.WebAuthn `json:"-"`
	}
	Wireguard struct {
		DevName    string
		ListenPort int
		PrivateKey string
		Address    string
		MTU        int

		//Not externally configurable
		External                  bool       `json:"-"`
		Range                     *net.IPNet `json:"-"`
		ServerAddress             net.IP     `json:"-"`
		ServerPersistentKeepAlive int

		DNS []string `json:",omitempty"`
	}

	DatabaseLocation string

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

// Used in authentication methods that can specify user groups directly (for the moment just oidc)
// Adds groups to username, even if user does not exist in the config.json file, so GetEffectiveAcls works
func AddVirtualUser(username string, groups []string) {
	valuesLock.Lock()
	defer valuesLock.Unlock()

	if values.Acls.rGroupLookup[username] == nil {
		values.Acls.rGroupLookup[username] = make(map[string]bool)
	}

	for _, group := range groups {
		values.Acls.rGroupLookup[username][group] = true
	}
}

func load(path string) (c Config, err error) {
	configFile, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("unable to load configuration file from %s: %v", path, err)
	}
	dec := json.NewDecoder(configFile)
	dec.DisallowUnknownFields()

	err = dec.Decode(&c)
	if err != nil {
		return c, fmt.Errorf("unable to load configuration file from %s: %v", path, err)
	}

	if c.Socket == "" {
		c.Socket = control.DefaultWagSocket
	}

	if c.DownloadConfigFileName == "" {
		c.DownloadConfigFileName = "wg0.conf"
	}

	if c.Proxied {
		log.Println("WARNING, Proxied setting is depreciated as it does not indicate how many reverse proxies we're behind (thus we cannot parse x-forwarded-for correctly), this will be removed in the next release")
		log.Println("For no, setting NumberProxies = 1 and hoping that just works for you. Change your config!")

		c.NumberProxies = 1
	}

	i, err := net.InterfaceByName(c.Wireguard.DevName)
	if err == nil {
		//A device already exists, so we're assuming it was externally set up (with something like wg-quick)
		c.Wireguard.External = true

		addresses, err := i.Addrs()
		if err != nil {
			return c, fmt.Errorf("unable to get address for interface %s: %v", c.Wireguard.DevName, err)
		}

		if len(addresses) < 1 {
			return c, errors.New("wireguard interface does not have an ip address")
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
			return c, fmt.Errorf("unable to find server address from tunnel interface:  '%s'", addr)
		}

		_, c.Wireguard.Range, err = net.ParseCIDR(addresses[0].String())
		if err != nil {
			return c, errors.New("unable to parse VPN range from tune device address: " + addresses[0].String() + " : " + err.Error())
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
	}

	if len(c.Acls.Policies) == 0 {
		return c, errors.New("no policies set under acls.Policies")
	}

	if len(c.Authenticators.Issuer) == 0 {
		return c, errors.New("no issuer specified")
	}

	if c.Clustering.Peers == nil {
		c.Clustering.Peers = make(map[string][]string)
	}

	if c.Clustering.Name == "" {
		c.Clustering.Name = "default"
	}

	if c.Clustering.ListenAddresses == nil {
		c.Clustering.ListenAddresses = []string{"http://localhost:2380"}
	}

	if c.NAT == nil {
		c.NAT = new(bool)
		*c.NAT = true
	}

	err = validExternalAddresses(c.ExternalAddress)
	if err != nil {
		return c, err
	}

	if c.Lockout <= 0 {
		return c, errors.New("lockout policy unconfigured")
	}

	if c.HelpMail == "" {
		return c, fmt.Errorf("no help email address specified")
	}

	if c.MaxSessionLifetimeMinutes == 0 {
		return c, errors.New("session max lifetime policy is not set (may be disabled by setting it to -1)")
	}

	if c.SessionInactivityTimeoutMinutes == 0 {
		return c, errors.New("session inactivity timeout policy is not set (may be disabled by setting it to -1)")
	}

	if c.Webserver.Tunnel.Port == "" {
		return c, fmt.Errorf("tunnel listener port is not set (Tunnel.ListenAddress.Port)")
	}

	if c.Webserver.Public.ListenAddress == "" {
		return c, fmt.Errorf("public listen address is not set (Public.ListenAddress)")
	}

	c.Wireguard.DNS, err = validateDns(c.Wireguard.DNS)
	if err != nil {
		return c, err
	}

	if c.NumberProxies > 0 && len(c.ExposePorts) == 0 {
		return c, errors.New("you have set 'NumberProxies' mode which disables adding the tunnel port to iptables but not defined any ExposedPorts (iptables rules added on the wag vpn host) thus clients would not be able to access the MFA portal")
	}

	for _, port := range c.ExposePorts {
		parts := strings.Split(port, "/")
		if len(parts) < 2 {
			return c, errors.New(port + " is not in a valid port format. E.g 80/tcp, 100-200/udp")
		}

		if c.NumberProxies > 0 {
			_, port, _ := net.SplitHostPort(c.Webserver.Public.ListenAddress)
			if port == parts[0] {
				return c, errors.New("you have tried to expose the vpn service (with ExposedPorts) while also having 'Proxied' set to true, this will cause wag to respect X-Forwarded-For from an external source which will result in a security vulnerablity, as such this is an error")
			}
		}

		switch strings.ToLower(parts[1]) {
		case "tcp", "udp":
			scope := strings.Split(parts[0], "-")
			if len(scope) == 2 {
				start, errStart := strconv.Atoi(scope[0])
				end, errEnd := strconv.Atoi(scope[1])
				if (errStart != nil) || (errEnd != nil) {
					return c, errors.New(parts[0] + " Could not convert lower port or upper port to number. E.g 100:200/udp")
				}
				if end < start {
					return c, errors.New(parts[0] + " port have to be smaller than end port . E.g 100-200/udp")
				}
			} else {
				_, err := strconv.Atoi(parts[0])
				if err != nil {
					return c, errors.New(parts[0] + " is not in a valid port number. E.g 80/tcp, 100-200/udp")
				}
			}
		default:
			return c, errors.New(port + " invalid protocol (supports tcp/udp)")
		}
	}

	c.Acls.rGroupLookup = map[string]map[string]bool{}

	for group, members := range c.Acls.Groups {
		if !strings.HasPrefix(group, "group:") {
			return c, fmt.Errorf("group does not have 'group:' prefix: %s", group)
		}

		for _, user := range members {
			if c.Acls.rGroupLookup[user] == nil {
				c.Acls.rGroupLookup[user] = make(map[string]bool)
			}

			c.Acls.rGroupLookup[user][group] = true
		}
	}

	for _, acl := range c.Acls.Policies {
		err = routetypes.ValidateRules(acl.Mfa, acl.Allow, acl.Deny)
		if err != nil {
			return c, fmt.Errorf("policy was invalid: %s", err)
		}
	}

	if len(c.MFATemplatesDirectory) != 0 {
		info, err := os.Stat(c.MFATemplatesDirectory)
		if err != nil {
			return c, fmt.Errorf("could not check MFATemplatesDirectory (%s): %s", c.MFATemplatesDirectory, err)
		}

		if !info.IsDir() {
			return c, fmt.Errorf("MFATemplatesDirectory (%s) was not a directory, please check your configuration", c.MFATemplatesDirectory)
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

			if !c.Webserver.Tunnel.SupportsTLS() && c.NumberProxies == 0 {
				return c, errors.New("tunnel does not support TLS (no cert/key given) required by webauthn")
			}

			if tunnelURL.Scheme != "https" {
				return c, errors.New("Authenticators.DomainURL was not HTTPS, yet webauthn was enabled (javascript wont be able to access window.PublicKeyCredential)")
			}

			c.Authenticators.Webauthn, err = webauthn.New(&webauthn.Config{
				RPDisplayName: c.Authenticators.Issuer,               // Display Name for your site
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
		_, ok := resultMFAMap[c.Authenticators.DefaultMethod]
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

func validateDns(input []string) (newDnsEntries []string, err error) {
	for _, entry := range input {
		newAddresses, err := parseAddress(entry)
		if err != nil {
			return nil, err
		}
		newDnsEntries = append(newDnsEntries, newAddresses...)
	}

	return
}

func validExternalAddresses(ExternalAddress string) error {
	if len(ExternalAddress) == 0 {
		return errors.New("invalid ExternalAddress is empty")
	}

	if net.ParseIP(ExternalAddress) == nil {

		addresses, err := net.LookupIP(ExternalAddress)
		if err != nil {
			return errors.New("invalid ExternalAddress: " + ExternalAddress + " unable to lookup as domain")
		}

		if len(addresses) == 0 {
			return errors.New("invalid ExternalAddress: " + ExternalAddress + " not IPv4 or IPv6 external addresses found")
		}
	}

	return nil
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

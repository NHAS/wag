package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data/validators"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var Version string

type webserverDetails struct {
	ListenAddress   string
	Domain          string
	TLS             bool
	CertificatePath string
	PrivateKeyPath  string
}

type Acls struct {
	Groups map[string][]string `json:",omitempty"`
	//Username -> groups name
	rGroupLookup map[string]map[string]bool
	Policies     map[string]*acls.Acl
}

type ClusteringDetails struct {
	Name             string
	ListenAddresses  []string
	Peers            map[string][]string
	DatabaseLocation string
	ETCDLogLevel     string
	Witness          bool
	ClusterState     string

	TLSManagerStorage   string
	TLSManagerListenURL string
}

type Config struct {
	Socket        string `json:",omitempty"`
	GID           *int   `json:",omitempty"`
	CheckUpdates  bool   `json:",omitempty"`
	NumberProxies int
	Proxied       bool
	DevMode       bool `json:",omitempty"`

	ExposePorts []string `json:",omitempty"`
	NAT         *bool    `json:",omitempty"`

	Webserver struct {
		Acme struct {
			Email              string
			CAProvider         string
			CloudflareDNSToken string
		}

		Public struct {
			webserverDetails
			DownloadConfigFileName string `json:",omitempty"`
			ExternalAddress        string
		}

		Lockout int

		Tunnel struct {
			Port   string
			Domain string
			TLS    bool

			CertificatePath string
			PrivateKeyPath  string

			HelpMail string

			MaxSessionLifetimeMinutes       int
			SessionInactivityTimeoutMinutes int

			DefaultMethod string `json:",omitempty"`
			Issuer        string
			Methods       []string `json:",omitempty"`

			OIDC struct {
				IssuerURL           string
				ClientSecret        string
				ClientID            string
				GroupsClaimName     string   `json:",omitempty"`
				DeviceUsernameClaim string   `json:",omitempty"`
				Scopes              []string `json:",omitempty"`
			} `json:",omitempty"`

			PAM struct {
				ServiceName string
			} `json:",omitempty"`
		}

		Management struct {
			webserverDetails

			Enabled bool

			Password struct {
				Enabled *bool `json:",omitempty"`
			} `json:",omitempty"`

			OIDC struct {
				IssuerURL    string
				ClientSecret string
				ClientID     string
				Enabled      bool
			} `json:",omitempty"`
		} `json:",omitempty"`
	}

	Clustering ClusteringDetails

	Wireguard struct {
		DevName    string
		ListenPort int
		PrivateKey string
		Address    string
		MTU        int

		LogLevel int

		//Not externally configurable
		Range                     *net.IPNet `json:"-"`
		ServerAddress             net.IP     `json:"-"`
		ServerPersistentKeepAlive int

		DNS []string `json:",omitempty"`
	}

	Acls Acls
}

var (
	Values Config
)

func load(path string) (c Config, err error) {
	configFile, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("unable to load configuration file from %s: %v", path, err)
	}
	dec := safedecoder.Decoder(configFile)
	dec.DisallowUnknownFields()

	err = dec.Decode(&c)
	if err != nil {
		return c, fmt.Errorf("unable to load configuration file from %s: %v", path, err)
	}

	if c.Socket == "" {
		c.Socket = control.DefaultWagSocket
	}

	if c.Webserver.Public.DownloadConfigFileName == "" {
		c.Webserver.Public.DownloadConfigFileName = "wg0.conf"
	}

	if c.Proxied {
		log.Println("WARNING, Proxied setting is depreciated as it does not indicate how many reverse proxies we're behind (thus we cannot parse x-forwarded-for correctly), this will be removed in the next release")
		log.Println("For no, setting NumberProxies = 1 and hoping that just works for you. Change your config!")

		c.NumberProxies = 1
	}

	if c.Wireguard.MTU == 0 {
		c.Wireguard.MTU = 1420
	}

	if c.Clustering.TLSManagerStorage == "" {
		c.Clustering.TLSManagerStorage = "certificates"
	}

	if c.Clustering.TLSManagerListenURL == "" {
		c.Clustering.TLSManagerListenURL = "https://127.0.0.1:4455"
		log.Println("WARNING no TLSManagerListenURL specified adding another cluster member will be disabled.")

	}

	if !strings.HasPrefix(c.Clustering.TLSManagerListenURL, "https://") {
		return c, fmt.Errorf("tls manager listen url must be https://")
	}

	_, err = net.InterfaceByName(c.Wireguard.DevName)
	if err == nil {
		return c, fmt.Errorf("interface %q already exists, wag no longer supports external wireguard interfaces", c.Wireguard.DevName)
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

	if c.Clustering.Peers == nil {
		c.Clustering.Peers = make(map[string][]string)
	}

	if c.Clustering.Name == "" {
		c.Clustering.Name = "default"
	}

	if c.Clustering.ListenAddresses == nil {
		c.Clustering.ListenAddresses = []string{"https://localhost:2380"}
	}

	if c.Clustering.ClusterState == "" {
		c.Clustering.ClusterState = "new"
	}

	if c.NAT == nil {
		c.NAT = new(bool)
		*c.NAT = true
	}

	err = validators.ValidExternalAddresses(c.Webserver.Public.ExternalAddress)
	if err != nil {
		return c, err
	}

	if c.Webserver.Lockout <= 0 {
		return c, errors.New("lockout policy unconfigured")
	}

	if c.Webserver.Tunnel.MaxSessionLifetimeMinutes == 0 {
		return c, errors.New("session max lifetime policy is not set (may be disabled by setting it to -1)")
	}

	if c.Webserver.Tunnel.SessionInactivityTimeoutMinutes == 0 {
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

	if len(c.Webserver.Tunnel.Methods) == 1 {
		c.Webserver.Tunnel.DefaultMethod = c.Webserver.Tunnel.Methods[len(c.Webserver.Tunnel.Methods)-1]
	}

	if c.Webserver.Management.Password.Enabled == nil {
		enabled := true
		c.Webserver.Management.Password.Enabled = &enabled
	}

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

func Load(path string) error {

	var err error
	Values, err = load(path)
	return err
}

func parseAddress(address string) ([]string, error) {

	address = strings.TrimSpace(address)
	addr, err := netip.ParseAddr(address)
	if err != nil {
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

			var output []string
			addedSomething := false
			for _, addr := range addresses {
				if addr.To4() != nil {
					addedSomething = true
					output = append(output, addr.String()+"/32")
					continue
				} else if addr.To16() != nil {
					addedSomething = true
					output = append(output, addr.String()+"/128")
					continue
				}
			}

			if !addedSomething {
				return nil, fmt.Errorf("no addresses for domain %s were added, potentially because they were all ipv6 which is unsupported", address)
			}

			return output, nil
		}

		return []string{cidr.String()}, nil
	}

	mask := "/32"
	if addr.Is6() {
		mask = "/128"
	}

	return []string{addr.String() + mask}, nil
}

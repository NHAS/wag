package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data/validators"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
	"go.etcd.io/etcd/client/pkg/v3/types"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var Version string

// use to be WebserverConfiguration
type WebserverDetails struct {
	ListenAddress string `json:"listen_address"`
	Domain        string `json:"domain"`
	TLS           bool   `json:"tls"`
	StaticCerts   bool   `json:"static_certificates"`

	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`

	// These are the user supplied certs, not the ones given by certmagic, which are managed internally
	CertificatePEM string `json:"certificate"`
	PrivateKeyPEM  string `json:"private_key" sensitive:"yes"`
}

func (a *WebserverDetails) Equals(b *WebserverDetails) bool {
	if a == b {
		return true
	}

	if a == nil {
		return false
	}

	return a.Domain == b.Domain && a.TLS == b.TLS && a.ListenAddress == b.ListenAddress && a.CertificatePEM == b.CertificatePEM && a.PrivateKeyPEM == b.PrivateKeyPEM
}

type Acls struct {
	Groups   map[string]map[string]MembershipInfo `json:",omitempty"`
	Policies map[string]*acls.Acl
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

type TunnelOidc struct {
	IssuerURL           string   `json:"issuer" validate:"omitempty,url" `
	ClientSecret        string   `json:"client_secret" validate:"omitempty,min=1,max=255" sensitive:"yes"`
	ClientID            string   `json:"client_id" validate:"omitempty,min=1,max=255"`
	GroupsClaimName     string   `json:"group_claim_name,omitempty"`
	DeviceUsernameClaim string   `json:"device_username_claim,omitempty"`
	Scopes              []string `json:"scopes,omitempty" tetcd:"compress"`
}

func (o *TunnelOidc) Equals(b *TunnelOidc) bool {
	if o == b {
		return true
	}

	if o == nil {
		return false
	}

	return o.IssuerURL == b.IssuerURL && o.ClientSecret == b.ClientSecret && o.ClientID == b.ClientID && o.DeviceUsernameClaim == b.DeviceUsernameClaim && slices.Equal(o.Scopes, b.Scopes)
}

type PAM struct {
	ServiceName string `json:"service_name" validate:"omitempty,min=1"`
}

type CloudflareToken struct {
	APIToken string `json:"api_token" sensitive:"true"`
}

type Config struct {
	Socket        string `json:",omitempty"`
	GID           *int   `json:",omitempty"`
	CheckUpdates  bool   `json:"check_updates,omitempty"`
	NumberProxies int
	DevMode       bool `json:",omitempty"`

	ExposePorts      []string `json:",omitempty" tetcd:"compress"`
	NAT              *bool    `json:",omitempty"`
	NATExcludeRanges []string `json:",omitempty" tetcd:"compress"`

	Webserver struct {
		Acme struct {
			Email              string
			CAProvider         string
			CloudflareDNSToken CloudflareToken `tetcd:"compress"`
		}

		Public struct {
			HTTPSettings           WebserverDetails
			DownloadConfigFileName string `json:"wireguard_config_filename,omitempty" validate:"required"`
			ExternalAddress        string `validate:"required,hostname|hostname_port|ip" json:"external_address"`
		}

		Lockout int `validate:"required,number" json:"lockout"`

		Tunnel struct {
			HTTPSettings WebserverDetails

			HelpMail string `validate:"required,email" json:"help_mail"`

			MaxSessionLifetimeMinutes       int `validate:"required,number" json:"max_session_lifetime_minutes"`
			SessionInactivityTimeoutMinutes int `validate:"required,number" json:"session_inactivity_timeout_minutes"`

			DefaultMethod string   `json:",omitempty"`
			Issuer        string   `validate:"required" json:"issuer"`
			Methods       []string `json:",omitempty" tetcd:"compress"`

			OIDC TunnelOidc `json:"oidc,omitzero" tetcd:"compress"`

			PAM PAM `json:"pam,omitzero"`
		}

		Management struct {
			HTTPSettings WebserverDetails

			Enabled bool

			Password struct {
				Enabled *bool `json:",omitempty"`
			} `json:",omitzero"`

			OIDC struct {
				IssuerURL    string
				ClientSecret string
				ClientID     string
				Enabled      bool
			} `json:",omitzero"`
		}
	}

	Clustering ClusteringDetails `tetcd:"-"`

	RemoteCluster *clientv3.ConfigSpec `tetcd:"-"`

	Wireguard struct {
		DevName    string
		ListenPort int
		PrivateKey string
		Address    string
		MTU        int

		LogLevel int

		//Not externally configurable
		Range                     *net.IPNet `json:"-" tetcd:"-"`
		ServerAddress             net.IP     `json:"-" tetcd:"-"`
		ServerPersistentKeepAlive int

		DNS []string `json:"dns,omitempty" tetcd:"compress" validate:"omitempty,dive,hostname|ip"`
	}

	Acls Acls
}

type Device struct {
	Version        int
	Address        string
	Publickey      string
	Username       string
	PresharedKey   string `sensitive:"yes"`
	Endpoint       *net.UDPAddr
	Attempts       int
	Authorised     time.Time
	Challenge      string `sensitive:"yes"`
	AssociatedNode types.ID
	Tag            string
}

func (d Device) String() string {

	authorised := "no"
	if !d.Authorised.Equal(time.Time{}) {
		authorised = d.Authorised.Format(time.DateTime)
	}

	return fmt.Sprintf("device[%s:%s:%s][attempts: %d, authorised: %s]", d.Username, d.Address, d.AssociatedNode, d.Attempts, authorised)
}

type DeviceSession struct {
	Address  string    `json:"address"`
	Username string    `json:"username"`
	Started  time.Time `json:"session_started"`
}

type DeviceChallenge struct {
	Address   string
	Username  string
	Challenge string `sensitive:"yes"`
}

type UserModel struct {
	Username  string
	Mfa       string `sensitive:"yes"`
	MfaType   string
	Locked    bool
	Enforcing bool
}

type InternalConfig struct {
	RegistrationTokens map[string]control.RegistrationResult

	Devices Devices

	Users map[string]UserModel

	Indexes    Indexes
	References References

	Webhooks Webhooks

	Nodes Nodes
}

type LastRequests struct {
	// this is a bit gross, and may change in the future
	// effectively its map[webhook id] -> data
	// we potentially should make a change to tetcd to express this as map[string]WebhookDetails `tectd:"uncompressed"`

	Data   map[string]string
	Time   map[string]time.Time
	Status map[string]string
}

type WebhookActionType string

const (
	CreateRegistrationToken WebhookActionType = "create_token"
	DeleteDevice            WebhookActionType = "delete_device"
	DeleteUser              WebhookActionType = "delete_user"
)

type Webhook struct {
	ID                 string                  `json:"id" validate:"required"`
	Action             WebhookActionType       `json:"action" validate:"required,oneof=create_token delete_device delete_user"`
	JsonAttributeRoles WebhookAttributeMapping `json:"json_attribute_roles" validate:"required"`
}

type WebhookAttributeMapping struct {
	AsUsername          string `json:"as_username" validate:"omitempty,max=255,min=1"`
	AsDeviceTag         string `json:"as_device_tag" validate:"omitempty,max=255,min=1"`
	AsRegistrationToken string `json:"as_registration_token" validate:"omitempty,max=255,min=1"`
	AsDeviceIP          string `json:"as_device_ip" validate:"omitempty,max=255,min=1"`
}

type Webhooks struct {
	// webhook id -> auth string
	Auth      map[string]string
	Temporary map[string]Webhook
	Active    map[string]Webhook

	LastRequests LastRequests
}

type EventError struct {
	NodeID          string    `json:"node_id"`
	ErrorID         string    `json:"error_id"`
	FailedEventData string    `json:"failed_event_data"`
	Error           string    `json:"error"`
	Time            time.Time `json:"time"`
}

type Nodes struct {
	Errors map[string]EventError

	// node id -> wag version
	Version map[string]string
}

type Devices struct {
	// Username -> Device address -> Device
	Machines map[string]map[string]Device

	// Address -> Session
	Sessions map[string]DeviceSession

	// Username -> Device address -> Challenge
	Challenges map[string]map[string]DeviceChallenge

	DHCP DHCP
}

type GroupInfo struct {
	Group   string
	Created int64
}

type MembershipInfo struct {
	Joined int64
	SSO    bool
}

type Indexes struct {
	Groups         map[string]GroupInfo
	UserMembership map[string]map[string]MembershipInfo
}

type References struct {
	Devices DevicesReferences
}

type DeviceRef struct {
	Username string
	Address  string
}

func (d *DeviceRef) Empty() bool {
	return d.Username == "" || d.Address == ""
}

type DevicesReferences struct {
	// IP Address -> device key
	Address map[string]DeviceRef

	// Wireguard public key -> device key
	PublicKey map[string]DeviceRef

	// Arbitrary tag -> device key
	Tag map[string]DeviceRef
}

type DHCP struct {
	Abandoned map[string]string
	End       string
	// used to lock mutexes for selection
	Locks string
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

	if c.Wireguard.MTU == 0 {
		c.Wireguard.MTU = 1420
	}

	if c.RemoteCluster == nil {

		if c.Clustering.TLSManagerStorage == "" {
			c.Clustering.TLSManagerStorage = "certificates"
		}

		if c.Clustering.TLSManagerListenURL == "" {
			c.Clustering.TLSManagerListenURL = "https://127.0.0.1:4455"
			log.Warn().Msg("no TLSManagerListenURL specified adding another cluster member will be disabled")
		}

		if !strings.HasPrefix(c.Clustering.TLSManagerListenURL, "https://") {
			return c, fmt.Errorf("tls manager listen url must be https://")
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

	if c.Webserver.Public.HTTPSettings.ListenAddress == "" {
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
			_, port, _ := net.SplitHostPort(c.Webserver.Public.HTTPSettings.ListenAddress)
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

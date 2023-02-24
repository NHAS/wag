package ui

type Page struct {
	Description string
	Title       string
	User        string
	WagVersion  string
}

type Dashboard struct {
	Page
	NumUsers           int
	LockedDevices      int
	Devices            int
	RegistrationTokens int

	ActiveSessions int

	Subnet string

	Port, UnenforcedMFA int
	PublicKey           string
	ExternalAddress     string

	LogItems []string
}

type GeneralSettings struct {
	Page
	OidcIdpURL      string
	OidcClientID    string
	OidcGroupsClaim string

	Issuer string
	Domain string

	Lockout                  int
	InactivityTimeoutMinutes int
	SessionLifeTimeMinutes   int

	ExternalAddress string
	HelpMail        string
	DNS             string

	OidcEnabled, WebauthnEnabled, TotpEnabled bool
}

type Login struct {
	ErrorMessage string
}

type ChangePassword struct {
	Page
	Message string
	Type    int
}

type UsersData struct {
	Username  string   `json:"username"`
	Devices   int      `json:"devices"`
	Locked    bool     `json:"locked"`
	DateAdded string   `json:"date_added"`
	MFAType   string   `json:"mfa_type"`
	Groups    []string `json:"groups"`
}

type DevicesData struct {
	Owner      string `json:"owner"`
	Locked     bool   `json:"is_locked"`
	Active     bool   `json:"active"`
	InternalIP string `json:"internal_ip"`

	PublicKey    string `json:"public_key"`
	LastEndpoint string `json:"last_endpoint"`
}

type TokensData struct {
	Token      string   `json:"token"`
	Username   string   `json:"username"`
	Groups     []string `json:"groups"`
	Overwrites string   `json:"overwrites"`
}

type WgDevicesData struct {
	PublicKey         string `json:"public_key"`
	Address           string `json:"address"`
	EndpointAddress   string `json:"last_endpoint"`
	LastHandshakeTime string `json:"last_handshake_time"`
}

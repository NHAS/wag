package ui

type Page struct {
	Description string
	Title       string
	User        string
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
	Enforcing bool     `json:"enforcing_mfa"`
	Locked    bool     `json:"locked"`
	DateAdded string   `json:"date_added"`
	Groups    []string `json:"groups"`
}

type DevicesData struct {
	Owner      string `json:"owner"`
	Locked     bool   `json:"is_locked"`
	InternalIP string `json:"internal_ip"`

	PublicKey    string `json:"public_key"`
	LastEndpoint string `json:"last_endpoint"`
}

type TokensData struct {
	Token      string `json:"token"`
	Username   string `json:"username"`
	Groups     string `json:"groups"`
	Overwrites string `json:"overwrites"`
}

type PolicyData struct {
	Effects         string `json:"effects"`
	NumPublicRoutes int    `json:"public_routes"`
	NumbMfaRoutes   int    `json:"mfa_routes"`
}

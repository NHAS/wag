package ui

type Page struct {
	Description string
	Title       string
	User        string
}

type Dashboard struct {
	Page
	Users, LockedDevices, Devices, ActiveSessions, RegistrationTokens []string

	Port, UnenforcedMFA int
	PublicKey           string
	ExternalAddress     string
}

type UsersData struct {
	Username  string `json:"username"`
	Devices   int    `json:"devices"`
	Enforcing bool   `json:"enforcing_mfa"`
	Locked    bool   `json:"locked"`
	DateAdded string `json:"date_added"`
	Groups    string `json:"groups"`
}

type DevicesData struct {
	Owner      string `json:"owner"`
	Locked     bool   `json:"is_locked"`
	InternalIP string `json:"internal_ip"`

	PublicKey         string `json:"public_key"`
	LastEndpoint      string `json:"last_endpoint"`
	LastHandShakeTime string `json:"last_handshake_time"`
}

type TokensData struct {
	Token      string `json:"token"`
	Username   string `json:"username"`
	Groups     string `json:"groups"`
	Overwrites string `json:"overwrites"`
}

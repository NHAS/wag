package ui

type Page struct {
	Notification
	Description  string
	Title        string
	User         string
	WagVersion   string
	ClusterState string
	ServerID     string
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
	Uses       int      `json:"uses"`
}

type WgDevicesData struct {
	ReceiveBytes      int64  `json:"rx"`
	TransmitBytes     int64  `json:"tx"`
	PublicKey         string `json:"public_key"`
	Address           string `json:"address"`
	EndpointAddress   string `json:"last_endpoint"`
	LastHandshakeTime string `json:"last_handshake_time"`
}

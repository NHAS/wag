package control

type RegistrationResult struct {
	Token      string
	Username   string
	Groups     []string
	Overwrites string
	NumUses    int
}

type PolicyData struct {
	Effects      string   `json:"effects"`
	PublicRoutes []string `json:"public_routes"`
	MfaRoutes    []string `json:"mfa_routes"`
	DenyRoutes   []string `json:"deny_routes"`
}

type GroupData struct {
	Group   string   `json:"group"`
	Members []string `json:"members"`
}

const DefaultWagSocket = "/tmp/wag.sock"

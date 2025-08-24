package control

type RegistrationResult struct {
	Token      string
	Username   string
	Groups     []string
	Overwrites string
	StaticIP   string
	NumUses    int

	Tag string
}

type PolicyData struct {
	Effects      string   `json:"effects"`
	PublicRoutes []string `json:"public_routes"`
	MfaRoutes    []string `json:"mfa_routes"`
	DenyRoutes   []string `json:"deny_routes"`
}

type GroupData struct {
	Group   string       `json:"group"`
	Members []MemberInfo `json:"members"`
}

type MemberInfo struct {
	SSO    bool   `json:"sso"`
	Name   string `json:"name"`
	Joined int64  `json:"joined"`
}

type GroupCreateData struct {
	Group        string   `json:"group"`
	AddedMembers []string `json:"added"`
}

type GroupEditData struct {
	GroupCreateData
	RemovedMembers []string `json:"removed"`
}

type PutReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

const DefaultWagSocket = "/tmp/wag.sock"

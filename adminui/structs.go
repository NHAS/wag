package adminui

import (
	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"go.etcd.io/etcd/client/pkg/v3/types"
)

type Page struct {
	Description string
	Title       string
}

type ServerInfoDTO struct {
	Subnet string `json:"subnet"`

	Port            int    `json:"port"`
	PublicKey       string `json:"public_key"`
	ExternalAddress string `json:"external_address"`
	Version         string `json:"version"`
}

type LogLinesDTO struct {
	LogItems []string `json:"log_lines"`
}

type ChangePasswordRequestDTO struct {
	CurrentPassword string
	NewPassword     string
}

type ChangePasswordResponseDTO struct {
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

type AclsTestRequestDTO struct {
	Username string `json:"username"`
}

type AclsTestResponseDTO struct {
	Username string    `json:"username"`
	Message  string    `json:"message"`
	Acls     *acls.Acl `json:"acls"`
}

type LoginRequestDTO struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponsetDTO struct {
	Success    bool              `json:"success"`
	User       data.AdminUserDTO `json:"user"`
	CsrfToken  string            `json:"csrfToken"`
	CsrfHeader string            `json:"csrfHeader"`
}

type EventsResponseDTO struct {
	EventLog []string          `json:"events"`
	Errors   []data.EventError `json:"errors"`
}

type GenericFailureResponseDTO struct {
	Message string `json:"failure_message"`
}

type MembershipDTO struct {
	ID   types.ID `json:"id"`
	Name string   `json:"name"`

	IsDrained     bool `json:"drained"`
	IsWitness     bool `json:"witness"`
	IsLeader      bool `json:"leader"`
	IsLearner     bool `json:"learner"`
	IsCurrentNode bool `json:"current_node"`

	Version string `json:"version"`
	Ping    string `json:"last_ping"`
	Status  string `json:"status"`

	PeerUrls []string `json:"peer_urls"`
}

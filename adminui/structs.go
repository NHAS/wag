package adminui

import (
	"time"

	"github.com/NHAS/wag/internal/acls"
	"github.com/NHAS/wag/internal/data"
	"github.com/go-playground/validator/v10"
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
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type RegistrationTokenRequestDTO struct {
	Username   string
	Token      string
	Overwrites string
	Groups     []string
	Uses       int
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
	Username string   `json:"username"`
	Message  string   `json:"message"`
	Success  bool     `json:"success"`
	Acls     acls.Acl `json:"acls"`
}

type FirewallTestRequestDTO struct {
	Address  string `json:"address" validate:"required,ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol" validate:"required"`
	Target   string `json:"target" validate:"required,ip"`
}

func (fwt *FirewallTestRequestDTO) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	return validate.Struct(fwt)
}

type FirewallResponseDTO struct {
	Username string   `json:"username"`
	Message  string   `json:"message"`
	Success  bool     `json:"success"`
	Acls     acls.Acl `json:"acls"`
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
	EventLog []data.GeneralEvent `json:"events"`
	Errors   []data.EventError   `json:"errors"`
}

type GenericResponseDTO struct {
	Message string `json:"message"`
	Success bool   `json:"success"`
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

type EditUsersDTO struct {
	Action    string   `json:"action"`
	Usernames []string `json:"usernames"`
}

type EditDevicesDTO struct {
	Action    string   `json:"action"`
	Addresses []string `json:"addresses"`
}

type MFAMethodDTO struct {
	FriendlyName string `json:"friendly_name"`
	Method       string `json:"method"`
}

type NotificationDTO struct {
	ID         string    `json:"id"`
	Heading    string    `json:"heading"`
	Message    []string  `json:"message"`
	Url        string    `json:"url"`
	Time       time.Time `json:"time"`
	Color      string    `json:"color"`
	OpenNewTab bool      `json:"open_new_tab"`
}

type TestNotificationsRequestDTO struct {
	Message string `json:"message"`
}

type AcknowledgeErrorResponseDTO struct {
	ErrorID string `json:"error_id"`
}

type NewNodeRequestDTO struct {
	NodeName      string `json:"node_name"`
	ConnectionURL string `json:"connection_url"`
	ManagerURL    string `json:"manager_url"`
}

type NewNodeResponseDTO struct {
	JoinToken    string `json:"join_token"`
	ErrorMessage error  `json:"error_message"`
}

type NodeControlRequestDTO struct {
	Node   string `json:"node"`
	Action string `json:"actions"`
}

type ConfigResponseDTO struct {
	SSO      bool `json:"sso"`
	Password bool `json:"password"`
}

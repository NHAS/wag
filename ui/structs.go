package ui

import (
	"encoding/json"
	"html"
)

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

func (d *UsersData) MarshalJSON() ([]byte, error) {

	var escd UsersData
	escd.Username = html.EscapeString(d.Username)

	escd.Devices = d.Devices
	escd.Locked = d.Locked

	escd.DateAdded = html.EscapeString(d.DateAdded)
	escd.MFAType = html.EscapeString(d.MFAType)

	for _, g := range d.Groups {
		escd.Groups = append(escd.Groups, html.EscapeString(g))
	}

	return json.Marshal(escd)
}

type DevicesData struct {
	Owner      string `json:"owner"`
	Locked     bool   `json:"is_locked"`
	Active     bool   `json:"active"`
	InternalIP string `json:"internal_ip"`

	PublicKey    string `json:"public_key"`
	LastEndpoint string `json:"last_endpoint"`
}

func (d *DevicesData) MarshalJSON() ([]byte, error) {

	var escd DevicesData
	escd.Owner = html.EscapeString(d.Owner)

	escd.Locked = d.Locked
	escd.Active = d.Active

	escd.InternalIP = html.EscapeString(d.InternalIP)
	escd.PublicKey = html.EscapeString(d.PublicKey)
	escd.LastEndpoint = html.EscapeString(d.LastEndpoint)

	return json.Marshal(escd)
}

type TokensData struct {
	Token      string   `json:"token"`
	Username   string   `json:"username"`
	Groups     []string `json:"groups"`
	Overwrites string   `json:"overwrites"`
}

func (d *TokensData) MarshalJSON() ([]byte, error) {

	var escd TokensData
	escd.Token = html.EscapeString(d.Token)

	escd.Username = html.EscapeString(d.Username)

	for _, g := range d.Groups {
		escd.Groups = append(escd.Groups, html.EscapeString(g))
	}

	escd.Overwrites = html.EscapeString(d.Overwrites)

	return json.Marshal(escd)
}

type WgDevicesData struct {
	PublicKey         string `json:"public_key"`
	Address           string `json:"address"`
	EndpointAddress   string `json:"last_endpoint"`
	LastHandshakeTime string `json:"last_handshake_time"`
}

func (d *WgDevicesData) MarshalJSON() ([]byte, error) {

	var escd WgDevicesData
	escd.PublicKey = html.EscapeString(d.PublicKey)

	escd.Address = html.EscapeString(d.PublicKey)
	escd.EndpointAddress = html.EscapeString(d.EndpointAddress)

	escd.LastHandshakeTime = html.EscapeString(d.LastHandshakeTime)

	return json.Marshal(escd)
}

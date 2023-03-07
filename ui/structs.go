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

func (d *UsersData) UnmarshalJSON(data []byte) error {

	var ud struct {
		Username  string   `json:"username"`
		Devices   int      `json:"devices"`
		Locked    bool     `json:"locked"`
		DateAdded string   `json:"date_added"`
		MFAType   string   `json:"mfa_type"`
		Groups    []string `json:"groups"`
	}

	err := json.Unmarshal(data, &ud)
	if err != nil {
		return err
	}

	d.Username = html.UnescapeString(ud.Username)

	d.Devices = ud.Devices
	d.Locked = ud.Locked

	d.DateAdded = html.UnescapeString(ud.DateAdded)
	d.MFAType = html.UnescapeString(ud.MFAType)

	for _, g := range ud.Groups {
		d.Groups = append(d.Groups, html.UnescapeString(g))
	}

	return nil
}

func (d *UsersData) MarshalJSON() ([]byte, error) {

	var escd struct {
		Username  string   `json:"username"`
		Devices   int      `json:"devices"`
		Locked    bool     `json:"locked"`
		DateAdded string   `json:"date_added"`
		MFAType   string   `json:"mfa_type"`
		Groups    []string `json:"groups"`
	}
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

func (d *DevicesData) UnmarshalJSON(data []byte) error {

	var dd struct {
		Owner      string `json:"owner"`
		Locked     bool   `json:"is_locked"`
		Active     bool   `json:"active"`
		InternalIP string `json:"internal_ip"`

		PublicKey    string `json:"public_key"`
		LastEndpoint string `json:"last_endpoint"`
	}

	err := json.Unmarshal(data, &dd)
	if err != nil {
		return err
	}

	d.Owner = html.UnescapeString(dd.Owner)

	d.Locked = dd.Locked
	d.Active = dd.Active

	d.InternalIP = html.UnescapeString(dd.InternalIP)
	d.PublicKey = html.UnescapeString(dd.PublicKey)
	d.LastEndpoint = html.UnescapeString(dd.LastEndpoint)

	return nil
}

func (d *DevicesData) MarshalJSON() ([]byte, error) {

	var escd struct {
		Owner      string `json:"owner"`
		Locked     bool   `json:"is_locked"`
		Active     bool   `json:"active"`
		InternalIP string `json:"internal_ip"`

		PublicKey    string `json:"public_key"`
		LastEndpoint string `json:"last_endpoint"`
	}

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

func (d *TokensData) UnmarshalJSON(data []byte) error {

	var td struct {
		Token      string   `json:"token"`
		Username   string   `json:"username"`
		Groups     []string `json:"groups"`
		Overwrites string   `json:"overwrites"`
	}

	err := json.Unmarshal(data, &td)
	if err != nil {
		return err
	}

	d.Token = html.UnescapeString(td.Token)

	d.Username = html.UnescapeString(td.Username)

	for _, g := range td.Groups {
		d.Groups = append(d.Groups, html.UnescapeString(g))
	}

	d.Overwrites = html.UnescapeString(td.Overwrites)

	return nil
}

func (d *TokensData) MarshalJSON() ([]byte, error) {

	var escd struct {
		Token      string   `json:"token"`
		Username   string   `json:"username"`
		Groups     []string `json:"groups"`
		Overwrites string   `json:"overwrites"`
	}

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

func (d *WgDevicesData) UnmarshalJSON(data []byte) error {

	var td struct {
		PublicKey         string `json:"public_key"`
		Address           string `json:"address"`
		EndpointAddress   string `json:"last_endpoint"`
		LastHandshakeTime string `json:"last_handshake_time"`
	}

	err := json.Unmarshal(data, &td)
	if err != nil {
		return err
	}

	d.PublicKey = html.UnescapeString(td.PublicKey)

	d.Address = html.UnescapeString(td.PublicKey)
	d.EndpointAddress = html.UnescapeString(td.EndpointAddress)

	d.LastHandshakeTime = html.UnescapeString(td.LastHandshakeTime)

	return nil
}

func (d *WgDevicesData) MarshalJSON() ([]byte, error) {

	var escd struct {
		PublicKey         string `json:"public_key"`
		Address           string `json:"address"`
		EndpointAddress   string `json:"last_endpoint"`
		LastHandshakeTime string `json:"last_handshake_time"`
	}
	escd.PublicKey = html.EscapeString(d.PublicKey)

	escd.Address = html.EscapeString(d.PublicKey)
	escd.EndpointAddress = html.EscapeString(d.EndpointAddress)

	escd.LastHandshakeTime = html.EscapeString(d.LastHandshakeTime)

	return json.Marshal(escd)
}

package control

import (
	"encoding/json"
	"html"
)

type RegistrationResult struct {
	Token      string
	Username   string
	Groups     []string
	Overwrites string
}

type PolicyData struct {
	Effects      string   `json:"effects"`
	PublicRoutes []string `json:"public_routes"`
	MfaRoutes    []string `json:"mfa_routes"`
}

func (d *PolicyData) UnmarshalJSON(data []byte) error {

	var ud struct {
		Effects      string   `json:"effects"`
		PublicRoutes []string `json:"public_routes"`
		MfaRoutes    []string `json:"mfa_routes"`
	}

	err := json.Unmarshal(data, &ud)
	if err != nil {
		return err
	}

	d.Effects = html.UnescapeString(ud.Effects)

	for _, g := range ud.PublicRoutes {
		d.PublicRoutes = append(d.PublicRoutes, html.UnescapeString(g))
	}

	for _, g := range ud.MfaRoutes {
		d.MfaRoutes = append(d.MfaRoutes, html.UnescapeString(g))
	}

	return nil
}

func (d *PolicyData) MarshalJSON() ([]byte, error) {

	var escd struct {
		Effects      string   `json:"effects"`
		PublicRoutes []string `json:"public_routes"`
		MfaRoutes    []string `json:"mfa_routes"`
	}

	escd.Effects = html.EscapeString(d.Effects)

	for _, g := range d.PublicRoutes {
		escd.PublicRoutes = append(escd.PublicRoutes, html.EscapeString(g))
	}

	for _, g := range d.MfaRoutes {
		escd.MfaRoutes = append(escd.MfaRoutes, html.EscapeString(g))
	}

	return json.Marshal(escd)
}

type GroupData struct {
	Group   string   `json:"group"`
	Members []string `json:"members"`
}

func (d *GroupData) UnmarshalJSON(data []byte) error {

	var ud struct {
		Group   string   `json:"group"`
		Members []string `json:"members"`
	}

	err := json.Unmarshal(data, &ud)
	if err != nil {
		return err
	}

	d.Group = html.UnescapeString(ud.Group)

	for _, g := range ud.Members {
		d.Members = append(d.Members, html.UnescapeString(g))
	}

	return nil
}

func (d *GroupData) MarshalJSON() ([]byte, error) {

	var escd struct {
		Group   string   `json:"group"`
		Members []string `json:"members"`
	}

	escd.Group = html.EscapeString(d.Group)

	for _, g := range d.Members {
		escd.Members = append(escd.Members, html.EscapeString(g))
	}

	return json.Marshal(escd)
}

const DefaultWagSocket = "/tmp/wag.sock"

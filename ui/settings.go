package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/data"
)

func adminUsersUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{
		Update:       getUpdate(),
		Description:  "Wag settings",
		Title:        "Settings - Admin Users",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	err := renderDefaults(w, r, d, "settings/management_users.html")

	if err != nil {
		log.Println("unable to render management_users: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func adminUsersData(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	adminUsers, err := ctrl.ListAdminUsers("")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	b, err := json.Marshal(adminUsers)
	if err != nil {
		log.Println("unable to marshal management users data: ", err)
		http.Error(w, "Server error", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func clusteringUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{
		Update:       getUpdate(),
		Description:  "Clustering Management Page",
		Title:        "Clustering",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	err := renderDefaults(w, r, d, "management/clustering.html")

	if err != nil {
		log.Println("unable to render clustering page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func generalSettingsUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	datastoreSettings, err := data.GetAllSettings()
	if err != nil {
		log.Println("could not get settings from datastore: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	d := GeneralSettings{
		Page: Page{
			Update:       getUpdate(),
			Description:  "Wag settings",
			Title:        "Settings - General",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},

		ExternalAddress:          datastoreSettings.ExternalAddress,
		Lockout:                  datastoreSettings.Lockout,
		Issuer:                   datastoreSettings.Issuer,
		Domain:                   datastoreSettings.Domain,
		InactivityTimeoutMinutes: datastoreSettings.SessionInactivityTimeoutMinutes,
		SessionLifeTimeMinutes:   datastoreSettings.MaxSessionLifetimeMinutes,
		HelpMail:                 datastoreSettings.HelpMail,
		DNS:                      strings.Join(datastoreSettings.DNS, "\n"),
		TotpEnabled:              true,
		OidcEnabled:              false,
		WebauthnEnabled:          false,
	}

	err = renderDefaults(w, r, d, "settings/general.html")
	if err != nil {
		log.Println("unable to render general: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func generalSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	switch r.URL.Query().Get("type") {
	case "general":

		var general = struct {
			HelpMail        string   `json:"help_mail"`
			ExternalAddress string   `json:"external_address"`
			DNS             []string `json:"dns"`
		}{}

		if err := json.NewDecoder(r.Body).Decode(&general); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		if err := data.SetHelpMail(general.HelpMail); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetExternalAddress(general.ExternalAddress); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetDNS(general.DNS); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))
		return
	case "login":

		var login = struct {
			SessionLifetime   int `json:"session_lifetime"`
			InactivityTimeout int `json:"session_inactivity"`
			Lockout           int `json:"lockout"`
		}{}

		if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		if err := data.SetSessionLifetimeMinutes(login.SessionLifetime); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetSessionInactivityTimeoutMinutes(login.InactivityTimeout); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetLockout(login.Lockout); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))
		return
	default:
		http.NotFound(w, r)
		return
	}

}

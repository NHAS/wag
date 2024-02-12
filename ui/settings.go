package ui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
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
		Notification: getUpdate(),
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

	d := struct {
		Page
		Members     []*membership.Member
		Leader      types.ID
		CurrentNode string
	}{
		Page: Page{
			Notification: getUpdate(),
			Description:  "Clustering Management Page",
			Title:        "Clustering",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},
		Members:     data.GetMembers(),
		Leader:      data.GetLeader(),
		CurrentNode: data.GetServerID(),
	}

	err := renderDefaults(w, r, d, "settings/clustering.html")

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

	d := struct {
		Page
		Settings   data.AllSettings
		MFAMethods []authenticators.Authenticator
	}{
		Page: Page{
			Notification: getUpdate(),
			Description:  "Wag settings",
			Title:        "Settings - General",
			User:         u.Username,
			WagVersion:   WagVersion,
			ServerID:     serverID,
			ClusterState: clusterState,
		},

		Settings:   datastoreSettings,
		MFAMethods: authenticators.GetAllAvaliableMethods(),
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

		var generalSettings data.GeneralSettings
		if err := json.NewDecoder(r.Body).Decode(&generalSettings); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		if err := data.SetGeneralSettings(generalSettings); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))
		return
	case "login":

		var loginSettings data.LoginSettings
		if err := json.NewDecoder(r.Body).Decode(&loginSettings); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		if err := data.SetLoginSettings(loginSettings); err != nil {
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

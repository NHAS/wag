package ui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/webserver/authenticators"
)

func adminUsersUI(w http.ResponseWriter, r *http.Request) {
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{

		Description: "Wag settings",
		Title:       "Settings - Admin Users",
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
	adminUsers, err := ctrl.ListAdminUsers("")
	if err != nil {
		log.Println("failed to get list of admin users: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(adminUsers)
	if err != nil {
		log.Println("unable to marshal management users data: ", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func generalSettingsUI(w http.ResponseWriter, r *http.Request) {
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

			Description: "Wag settings",
			Title:       "Settings - General",
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
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	switch r.URL.Query().Get("type") {
	case "general":

		var generalSettings data.GeneralSettings
		if err := json.NewDecoder(r.Body).Decode(&generalSettings); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err := data.SetGeneralSettings(generalSettings); err != nil {
			log.Println("failed to set general settings: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return
	case "login":

		var loginSettings data.LoginSettings
		if err := json.NewDecoder(r.Body).Decode(&loginSettings); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if err := data.SetLoginSettings(loginSettings); err != nil {
			log.Println("failed to set login settings: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return
	default:
		http.NotFound(w, r)
		return
	}

}

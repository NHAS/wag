package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
)

func (au *AdminUI) adminUsersData(w http.ResponseWriter, r *http.Request) {
	adminUsers, err := au.ctrl.ListAdminUsers("")
	if err != nil {
		log.Println("failed to get list of admin users: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(adminUsers)
}

func (au *AdminUI) getGeneralSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := au.ctrl.GetGeneralSettings()
	if err != nil {
		log.Println("failed to get list of admin users: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (au *AdminUI) updateGeneralSettings(w http.ResponseWriter, r *http.Request) {
	var (
		generalSettings data.GeneralSettings
		err             error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&generalSettings)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetGeneralSettings(generalSettings)
	if err != nil {
		log.Println("failed to get general settings: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) getLoginSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := au.ctrl.GetLoginSettings()
	if err != nil {
		log.Println("failed to get login settings: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (au *AdminUI) updateLoginSettings(w http.ResponseWriter, r *http.Request) {
	var (
		loginSettings data.LoginSettings
		err           error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&loginSettings)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetLoginSettings(loginSettings)
	if err != nil {
		log.Println("failed to set login settings: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) getAllMfaMethods(w http.ResponseWriter, r *http.Request) {

	resp := []MFAMethodDTO{}

	authenticators := authenticators.GetAllAvaliableMethods()
	for _, a := range authenticators {
		resp = append(resp, MFAMethodDTO{FriendlyName: a.FriendlyName(), Method: a.Type()})
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

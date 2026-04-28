package server

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

func (wsg *WagControlSocketServer) getAdminUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	user, err := wsg.db.GetAdminUser(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

}

func (wsg *WagControlSocketServer) getOidcAdminUser(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")

	user, err := wsg.db.GetOidcAdminUser(subject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

}

func (wsg *WagControlSocketServer) listAdminUsers(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	if username != "" {
		user, err := wsg.db.GetAdminUser(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		b, err := json.Marshal(user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)

		return
	}

	currentAdminUsers, err := wsg.db.GetAllAdminUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(currentAdminUsers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) lockAdminUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	err = wsg.db.SetAdminUserLock(username)
	if err != nil {
		http.Error(w, "could not lock admin user: "+err.Error(), http.StatusNotFound)
		return
	}

	log.Info().Str("admin_username", username).Str("action", "locked").Send()

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) unlockAdminUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	err = wsg.db.SetAdminUserUnlock(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Str("admin_username", username).Str("action", "unlocked").Send()

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) deleteAdminUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	err = wsg.db.DeleteAdminUser(username)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), http.StatusNotFound)
		return
	}

	log.Info().Str("admin_username", username).Str("action", "deleted").Send()

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) resetAdminUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	err = wsg.db.SetAdminPassword(username, password)
	if err != nil {
		http.Error(w, "unable to set admin user password: "+err.Error(), http.StatusNotFound)
		return
	}

	log.Info().Str("admin_username", username).Str("action", "password reset").Send()

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) addAdminUser(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	shouldChange := r.FormValue("change") == "true"

	err = wsg.db.CreateLocalAdminUser(username, password, shouldChange)
	if err != nil {
		http.Error(w, "unable to create admin user: "+err.Error(), http.StatusNotFound)
		return
	}

	log.Info().Str("admin_username", username).Str("action", "added").Send()

	w.Write([]byte("OK"))
}

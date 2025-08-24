package server

import (
	"encoding/json"
	"log"
	"net/http"
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
		http.Error(w, "could not lock admin user: "+err.Error(), 404)
		return
	}

	log.Println(username, "admin locked")

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

	log.Println(username, "admin unlocked")

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
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	log.Println(username, "admin deleted")

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
		http.Error(w, "unable to set admin user password: "+err.Error(), 404)
		return
	}

	log.Println(username, "admin password reset")

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
		http.Error(w, "unable to create admin user: "+err.Error(), 404)
		return
	}

	log.Println(username, "admin added")

	w.Write([]byte("OK"))
}

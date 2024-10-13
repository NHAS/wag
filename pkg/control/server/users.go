package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/users"
)

func (wsg *WagControlSocketServer) listUsers(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	if username != "" {

		user, err := users.GetUser(username)
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

	currentUsers, err := data.GetAllUsers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(currentUsers)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) getUserGroups(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "No user specified", http.StatusNotFound)
		return
	}

	user, err := data.GetUserGroupMembership(username)
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

func (wsg *WagControlSocketServer) lockUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	user, err := users.GetUser(username)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	err = user.Lock()
	if err != nil {
		http.Error(w, "lock found: "+err.Error(), 404)
		return
	}

	log.Println(username, "locked")

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) unlockUser(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	user, err := users.GetUser(username)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	err = user.Unlock()
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	log.Println(username, "unlocked")

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) deleteUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	user, err := users.GetUser(username)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	err = user.Delete()
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	log.Println(username, "deleted")

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) listAdminUsers(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	if username != "" {

		user, err := data.GetAdminUser(username)
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

	currentAdminUsers, err := data.GetAllAdminUsers()
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

	err = data.SetAdminUserLock(username)
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

	err = data.SetAdminUserUnlock(username)
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

	err = data.DeleteAdminUser(username)
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

	err = data.SetAdminPassword(username, password)
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

	err = data.CreateLocalAdminUser(username, password, shouldChange)
	if err != nil {
		http.Error(w, "unable to create admin user: "+err.Error(), 404)
		return
	}

	log.Println(username, "admin added")

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) resetMfaUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	user, err := users.GetUser(username)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	err = user.ResetMfa()
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	log.Println(username, "MFA has been reset and will be shown")

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) getUserAcl(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	if username == "" {
		http.Error(w, "No username specified", http.StatusNotFound)
		return
	}

	acl := data.GetEffectiveAcl(username)

	b, err := json.Marshal(acl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

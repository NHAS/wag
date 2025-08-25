package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (wsg *WagControlSocketServer) listUsers(w http.ResponseWriter, r *http.Request) {

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	if username != "" {

		user, err := wsg.db.GetUserData(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		users := []data.UserModel{user}
		b, err := json.Marshal(users)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)

		return
	}

	currentUsers, err := wsg.db.GetAllUsers()
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

	user, err := wsg.db.GetUserGroupMembership(username)
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

	user, err := users.GetUser(wsg.db, username)
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

	user, err := users.GetUser(wsg.db, username)
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

	user, err := users.GetUser(wsg.db, username)
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

func (wsg *WagControlSocketServer) resetMfaUser(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	user, err := users.GetUser(wsg.db, username)
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

	acl := wsg.db.GetEffectiveAcl(username)

	b, err := json.Marshal(acl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) addUser(w http.ResponseWriter, r *http.Request) {

	var (
		username string
	)

	err := safedecoder.Decoder(r.Body).Decode(&username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	usermodel, err := wsg.db.CreateUserDataAccount(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usermodel)
}

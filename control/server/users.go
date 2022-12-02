package server

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/users"
)

func listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	username := r.FormValue("username")

	if username != "" {

		user, err := users.GetUser(username)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		b, err := json.Marshal(user)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)

		return
	}

	users, err := data.GetAllUsers()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	b, err := json.Marshal(users)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func lockUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
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

func unlockUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
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

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
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

func resetMfaUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
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

package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/NHAS/wag/control"
	"github.com/NHAS/wag/data"
)

func listRegistrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	result, err := data.GetRegistrationTokens()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(b)
}

func newRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	token := r.FormValue("token")
	username := r.FormValue("username")
	overwrite := r.FormValue("overwrite")

	resp := control.RegistrationResult{Token: token, Username: username}

	if token != "" {
		err := data.AddRegistrationToken(token, username, overwrite)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		b, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Write(b)
		return
	}

	token, err = data.GenerateToken(username, overwrite)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	resp.Token = token

	b, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(b)
}

func deleteRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	id := r.FormValue("id")

	err = data.DeleteRegistrationToken(id)
	if err != nil {

		http.Error(w, errors.New("Could not delete token: "+err.Error()).Error(), 500)
		return
	}

	w.Write([]byte("OK"))
}

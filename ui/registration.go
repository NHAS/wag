package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func registrationUI(w http.ResponseWriter, r *http.Request) {
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
		Description:  "Registration Tokens Management Page",
		Title:        "Registration",
		User:         u.Username,
		WagVersion:   WagVersion,
		ServerID:     serverID,
		ClusterState: clusterState,
	}

	err := renderDefaults(w, r, d, "management/registration_tokens.html", "delete_modal.html")
	if err != nil {
		log.Println("unable to render registration_tokens page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func registrationTokens(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":

		registrations, err := ctrl.Registrations()
		if err != nil {
			log.Println("error getting registrations: ", err)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		data := []TokensData{}

		for _, reg := range registrations {
			data = append(data, TokensData{
				Username:   reg.Username,
				Token:      reg.Token,
				Groups:     reg.Groups,
				Overwrites: reg.Overwrites,
				Uses:       reg.NumUses,
			})
		}

		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal registration_tokens data: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return

	case "DELETE":

		var tokens []string

		err := json.NewDecoder(r.Body).Decode(&tokens)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, token := range tokens {
			err := ctrl.DeleteRegistration(token)
			if err != nil {
				log.Println("Error deleting registration token: ", token, "err:", err)
			}
		}
		w.Write([]byte("OK"))

	case "POST":

		var b struct {
			Username   string
			Token      string
			Overwrites string
			Groups     string
			Uses       string
		}

		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		uses, err := strconv.Atoi(b.Uses)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if uses <= 0 {
			http.Error(w, "cannot create token with <= 0 uses", 400)
			return
		}

		var groups []string
		if len(b.Groups) > 0 {
			groups = strings.Split(b.Groups, ",")
		}

		_, err = ctrl.NewRegistration(b.Token, b.Username, b.Overwrites, uses, groups...)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))

	default:
		http.NotFound(w, r)
	}

}

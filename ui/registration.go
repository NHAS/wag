package ui

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func registrationUI(w http.ResponseWriter, r *http.Request) {
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{

		Description: "Registration Tokens Management Page",
		Title:       "Registration",
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
	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	switch r.Method {
	case "GET":

		registrations, err := ctrl.Registrations()
		if err != nil {
			log.Println("error getting registrations: ", err)

			w.WriteHeader(http.StatusInternalServerError)
			renderDefaults(w, r, nil, "error.html")
			return
		}

		tokens := []TokensData{}

		for _, reg := range registrations {
			tokens = append(tokens, TokensData{
				Username:   reg.Username,
				Token:      reg.Token,
				Groups:     reg.Groups,
				Overwrites: reg.Overwrites,
				Uses:       reg.NumUses,
			})
		}

		b, err := json.Marshal(tokens)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return

	case "DELETE":

		var tokens []string

		err := json.NewDecoder(r.Body).Decode(&tokens)
		if err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		errs := ""
		for _, token := range tokens {
			err := ctrl.DeleteRegistration(token)
			if err != nil {
				log.Println("Error deleting registration token: ", token, "err:", err)
				errs = errs + "\n" + err.Error()
			}
		}

		if len(errs) > 0 {
			http.Error(w, errs, http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return

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
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		b.Username = strings.TrimSpace(b.Username)
		b.Overwrites = strings.TrimSpace(b.Overwrites)

		uses, err := strconv.Atoi(b.Uses)
		if err != nil {
			log.Println("client sent invalid number for token number of usees")
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		if uses <= 0 {
			http.Error(w, "cannot create token with <= 0 uses", http.StatusBadRequest)
			return
		}

		var groups []string
		if len(b.Groups) > 0 {
			groups = strings.Split(b.Groups, ",")
		}

		_, err = ctrl.NewRegistration(b.Token, b.Username, b.Overwrites, uses, groups...)
		if err != nil {
			log.Println("unable to create new registration token: ", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("OK"))
		return

	default:
		http.NotFound(w, r)
	}

}

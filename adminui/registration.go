package adminui

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/pkg/control"
)

func (au *AdminUI) getAllRegistrationTokens(w http.ResponseWriter, r *http.Request) {
	registrations, err := au.ctrl.Registrations()
	if err != nil {
		log.Println("error getting registrations: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tokens := []TokensData{}

	for _, reg := range registrations {
		tokens = append(tokens, TokensData{
			Username:   reg.Username,
			Token:      reg.Token,
			Groups:     reg.Groups,
			StaticIP:   reg.StaticIP,
			Overwrites: reg.Overwrites,
			Uses:       reg.NumUses,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (au *AdminUI) createRegistrationToken(w http.ResponseWriter, r *http.Request) {
	var (
		req        RegistrationTokenRequestDTO
		res        control.RegistrationResult
		err        error
		successMsg string
	)

	defer func() { au.respondSuccess(err, successMsg, w) }()
	defer r.Body.Close()
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Overwrites = strings.TrimSpace(req.Overwrites)

	if req.Uses <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		err = errors.New("cannot create token with <= 0 uses")
		return
	}

	res, err = au.ctrl.NewRegistration(req.Token, req.Username, req.Overwrites, req.StaticIP, req.Uses, req.Groups...)
	if err != nil {
		log.Println("unable to create new registration token: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	successMsg = res.Token
}

func (au *AdminUI) deleteRegistrationTokens(w http.ResponseWriter, r *http.Request) {
	var (
		err    error
		tokens []string
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&tokens)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var errs []error
	for _, token := range tokens {
		err := au.ctrl.DeleteRegistration(token)
		if err != nil {
			errs = append(errs, err)
		}
	}
	err = errors.Join(errs...)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

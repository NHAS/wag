package server

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/control"
)

func (wsg *WagControlSocketServer) listRegistrations(w http.ResponseWriter, r *http.Request) {

	result, err := data.GetRegistrationTokens()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func (wsg *WagControlSocketServer) newRegistration(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	token := r.FormValue("token")
	username := r.FormValue("username")
	overwrite := r.FormValue("overwrite")
	staticIp := r.FormValue("static_ip")

	groupsString := r.FormValue("groups")
	usesString := r.FormValue("uses")

	var groups []string = nil
	err = json.Unmarshal([]byte(groupsString), &groups)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(groups) > 0 {

		for _, group := range groups {
			if !strings.HasPrefix(group, "group:") {
				http.Error(w, "group did not have the 'group:' prefix '"+group+"'", http.StatusInternalServerError)
				return
			}
		}

	}

	uses, err := strconv.Atoi(usesString)
	if err != nil {
		http.Error(w, "invalid number of uses for registration token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if uses <= 0 {
		http.Error(w, "invalid number of uses for registration token: "+usesString, http.StatusBadRequest)
		return
	}

	if ip := net.ParseIP(staticIp); staticIp != "" && ip != nil && !config.Values.Wireguard.Range.Contains(ip) {
		http.Error(w, "static ip address is not within vpn range", http.StatusBadRequest)
		return
	}

	resp := control.RegistrationResult{
		Token:      token,
		Username:   username,
		Groups:     groups,
		NumUses:    uses,
		Overwrites: overwrite,
		StaticIP:   staticIp,
	}

	tokenType := "registration"
	if overwrite != "" {
		tokenType = "overwrite"
	}

	if token != "" {
		err := data.AddRegistrationToken(token, username, overwrite, staticIp, groups, uses)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		b, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Println(tokenType, "token for ", username, "created.")

		w.Write(b)
		return
	}

	token, err = data.GenerateToken(username, overwrite, staticIp, groups, uses)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp.Token = token

	b, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println(tokenType, "token for ", username, "created")
	w.Write(b)
}

func (wsg *WagControlSocketServer) deleteRegistration(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id := r.FormValue("id")

	err = data.DeleteRegistrationToken(id)
	if err != nil {

		http.Error(w, errors.New("Could not delete token: "+err.Error()).Error(), http.StatusInternalServerError)
		return
	}

	log.Println("registration token deleted")

	w.Write([]byte("OK"))
}

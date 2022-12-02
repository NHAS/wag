package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/router"
	"github.com/NHAS/wag/users"
)

func listDevices(w http.ResponseWriter, r *http.Request) {
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

		devices, err := user.GetDevices()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		b, err := json.Marshal(devices)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)

		return
	}

	devices, err := data.GetAllDevices()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	b, err := json.Marshal(devices)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func lockDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	address := r.FormValue("address")
	err = router.Deauthenticate(address)
	if err != nil {
		http.Error(w, "not found in firewall: "+err.Error(), 404)
		return
	}

	user, err := users.GetUserFromAddress(net.ParseIP(address))
	if err != nil {
		http.Error(w, "not found in database: "+err.Error(), 404)

		return
	}

	err = user.SetDeviceAuthAttempts(address, config.Values().Lockout+1)
	if err != nil {
		http.Error(w, "could not lock device in db: "+err.Error(), 404)
		return
	}

	log.Println(user.Username, " device", address, "has been locked")

	w.Write([]byte("OK"))
}

func unlockDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	address, err := url.QueryUnescape(r.FormValue("address"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	user, err := users.GetUserFromAddress(net.ParseIP(address))
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)

		return
	}

	err = user.ResetDeviceAuthAttempts(address)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Println(user.Username, " device", address, "has been unlocked")

	w.Write([]byte("OK"))
}

func sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	sessions, err := router.GetAllAuthorised()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	result, err := json.Marshal(sessions)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(result)
}

func deleteDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	address := r.FormValue("address")

	user, err := users.GetUserFromAddress(net.ParseIP(address))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = user.DeleteDevice(address)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	log.Println(user.Username, " device", address, "deleted")

	w.Write([]byte("OK"))
}

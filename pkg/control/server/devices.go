package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
)

func listDevices(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	var devices []data.Device
	if username != "" {

		user, err := users.GetUser(username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		devices, err = user.GetDevices()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	} else {

		devices, err = data.GetAllDevices()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	for i := range devices {
		devices[i].Active = router.IsAuthed(devices[i].Address)
	}

	b, err := json.Marshal(devices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func lockDevice(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	address := r.FormValue("address")

	user, err := users.GetUserFromAddress(net.ParseIP(address))
	if err != nil {
		http.Error(w, "not found in database: "+err.Error(), 404)

		return
	}

	lockout, err := data.GetLockout()
	if err != nil {
		http.Error(w, "could not get lockout number: "+err.Error(), 404)
		return
	}

	// This will need to be changed at some point to make it that lockout is a state, rather than a simple int
	err = user.SetDeviceAuthAttempts(address, lockout+1)
	if err != nil {
		http.Error(w, "could not lock device in db: "+err.Error(), 404)
		return
	}

	log.Println(user.Username, " device", address, "has been locked")

	w.Write([]byte("OK"))
}

func unlockDevice(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	address, err := url.QueryUnescape(r.FormValue("address"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user, err := users.GetUserFromAddress(net.ParseIP(address))
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)

		return
	}

	err = user.ResetDeviceAuthAttempts(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println(user.Username, " device", address, "has been unlocked")

	w.Write([]byte("OK"))
}

func sessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessions, err := router.GetAllAuthorised()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := json.Marshal(sessions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(result)
}

func deleteDevice(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	address := r.FormValue("address")

	user, err := users.GetUserFromAddress(net.ParseIP(address))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = user.DeleteDevice(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println(user.Username, " device", address, "deleted")

	w.Write([]byte("OK"))
}

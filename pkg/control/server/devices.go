package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (wsg *WagControlSocketServer) listDevices(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	username := r.FormValue("username")

	var devices []data.Device
	if username != "" {

		user, err := users.GetUser(wsg.db, username)
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

		devices, err = wsg.db.GetAllDevices()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	b, err := json.Marshal(devices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) lockDevice(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	address := r.FormValue("address")

	user, err := users.GetUserFromAddress(wsg.db, net.ParseIP(address))
	if err != nil {
		http.Error(w, "not found in database: "+err.Error(), 404)

		return
	}

	lockout, err := wsg.db.GetLockout()
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

func (wsg *WagControlSocketServer) unlockDevice(w http.ResponseWriter, r *http.Request) {
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

	user, err := users.GetUserFromAddress(wsg.db, net.ParseIP(address))
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

func (wsg *WagControlSocketServer) sessions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sessions, err := wsg.db.GetAllSessions()
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

func (wsg *WagControlSocketServer) addDevice(w http.ResponseWriter, r *http.Request) {

	var (
		input control.CreateDeviceDTO
		err   error
	)

	err = safedecoder.Decoder(r.Body).Decode(&input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	device, err := wsg.db.AddDevice(input.Username, input.Publickey, input.StaticIp, input.Tag)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println(device.Username, " device", device.Address, "created")

	w.Write([]byte("OK"))
}

func (wsg *WagControlSocketServer) deleteDevice(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	address := r.FormValue("address")

	user, err := users.GetUserFromAddress(wsg.db, net.ParseIP(address))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = wsg.db.DeleteDevice(address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println(user.Username, " device", address, "deleted")

	w.Write([]byte("OK"))
}

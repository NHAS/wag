package adminui

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

func (au *AdminUI) getAllDevices(w http.ResponseWriter, r *http.Request) {
	allDevices, err := au.ctrl.ListDevice("")
	if err != nil {
		log.Println("error getting devices: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	lockout, err := au.ctrl.GetLockout()
	if err != nil {
		log.Println("error getting lockout: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	deviceData := []DevicesData{}

	for _, dev := range allDevices {
		deviceData = append(deviceData, DevicesData{
			Owner:        dev.Username,
			Locked:       dev.Attempts >= lockout,
			InternalIP:   dev.Address,
			PublicKey:    dev.Publickey,
			LastEndpoint: dev.Endpoint.String(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deviceData)
}

func (au *AdminUI) editDevice(w http.ResponseWriter, r *http.Request) {

	var (
		action EditDevicesDTO
		err    error
	)

	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&action)
	if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}

	for _, address := range action.Addresses {
		switch action.Action {
		case "lock":
			err := au.ctrl.LockDevice(address)
			if err != nil {
				log.Println("Error locking device: ", address, " err:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case "unlock":
			err := au.ctrl.UnlockDevice(address)
			if err != nil {
				log.Println("Error unlocking device: ", address, " err:", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		default:
			err = errors.New("invalid request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
}

func (au *AdminUI) deleteDevice(w http.ResponseWriter, r *http.Request) {

	var (
		addresses []string
		err       error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&addresses)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	for _, address := range addresses {
		err := au.ctrl.DeleteDevice(address)
		if err != nil {
			log.Println("Error Deleting device: ", address, "err:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

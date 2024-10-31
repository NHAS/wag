package adminui

import (
	"encoding/json"
	"log"
	"net/http"
)

func (au *AdminUI) devicesMgmtUI(w http.ResponseWriter, r *http.Request) {

	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := Page{

		Description: "Devices Management Page",
		Title:       "Devices",
	}

	err := au.renderDefaults(w, r, d, "management/devices.html", "delete_modal.html")

	if err != nil {
		log.Println("unable to render devices page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		au.renderDefaults(w, r, nil, "error.html")
		return
	}
}

func (au *AdminUI) devicesMgmt(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		allDevices, err := au.ctrl.ListDevice("")
		if err != nil {
			log.Println("error getting devices: ", err)

			w.WriteHeader(http.StatusInternalServerError)
			au.renderDefaults(w, r, nil, "error.html")
			return
		}

		lockout, err := au.ctrl.GetLockout()
		if err != nil {
			log.Println("error getting lockout: ", err)

			w.WriteHeader(http.StatusInternalServerError)
			au.renderDefaults(w, r, nil, "error.html")
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
				Active:       dev.Active,
			})
		}

		b, err := json.Marshal(deviceData)
		if err != nil {

			log.Println("unable to marshal devices data: ", err)
			http.Error(w, "Server error", 500)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "PUT":
		var action struct {
			Action    string   `json:"action"`
			Addresses []string `json:"addresses"`
		}

		err := json.NewDecoder(r.Body).Decode(&action)
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
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			case "unlock":
				err := au.ctrl.UnlockDevice(address)
				if err != nil {
					log.Println("Error unlocking device: ", address, " err:", err)
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			default:
				http.Error(w, "invalid action", 400)
				return
			}
		}

		w.Write([]byte("OK"))

	case "DELETE":
		var addresses []string

		err := json.NewDecoder(r.Body).Decode(&addresses)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, address := range addresses {
			err := au.ctrl.DeleteDevice(address)
			if err != nil {
				log.Println("Error Deleting device: ", address, "err:", err)

				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Write([]byte("OK"))

	default:
		http.NotFound(w, r)
	}

}

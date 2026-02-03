package adminui

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/wag/pkg/safedecoder"
)

func (au *AdminUI) getAllDevices(w http.ResponseWriter, r *http.Request) {
	allDevices, err := au.ctrl.ListDevice("")
	if err != nil {
		log.Error().Err(err).Msg("failed to get all devices")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	lockout, err := au.ctrl.GetLockout()
	if err != nil {
		log.Error().Err(err).Msg("failed to get lockout")
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
			Tag:          dev.Tag,
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

	err = safedecoder.Decoder(r.Body).Decode(&action)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		log.Warn().Err(err).Msg("failed to json body")

		return
	}

	succeeded := 0
	for _, address := range action.Addresses {
		switch action.Action {
		case "lock":
			err := au.ctrl.LockDevice(address)
			if err != nil {
				log.Error().Err(err).Str("address", address).Msg("failed to lock device")

				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case "unlock":
			err := au.ctrl.UnlockDevice(address)
			if err != nil {
				log.Error().Err(err).Str("address", address).Msg("failed to unlock device")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		default:
			log.Warn().Str("action", action.Action).Msg("invalid device edit action")

			err = errors.New("invalid request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}

	logEvent := log.Info()
	if succeeded != len(action.Addresses) {
		logEvent = log.Error()
	}

	logEvent.Str("action", action.Action).Int("succeeded", succeeded).Int("total", len(action.Addresses)).Msg("device/s edited")
}

func (au *AdminUI) deleteDevice(w http.ResponseWriter, r *http.Request) {

	var (
		addresses []string
		err       error
	)
	defer func() { au.respond(err, w) }()

	err = safedecoder.Decoder(r.Body).Decode(&addresses)
	if err != nil {
		log.Warn().Err(err).Msg("failed to json body")

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	for _, address := range addresses {
		err := au.ctrl.DeleteDevice(address)
		if err != nil {
			log.Error().Err(err).Str("address", address).Msg("Error Deleting device")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

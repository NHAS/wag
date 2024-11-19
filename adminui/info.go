package adminui

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/config"
)

func (au *AdminUI) serverInfo(w http.ResponseWriter, r *http.Request) {

	pubkey, port, err := au.firewall.ServerDetails()
	if err != nil {
		log.Println("error getting server details: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	s, err := au.ctrl.GetAllSettings()
	if err != nil {
		log.Println("error getting server settings: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	d := ServerInfoDTO{
		PublicKey:       pubkey.String(),
		ExternalAddress: s.ExternalAddress,
		Subnet:          config.Values.Wireguard.Range.String(),
		Port:            port,
		Version:         au.wagVersion,
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(d)
}

func (au *AdminUI) consoleLog(w http.ResponseWriter, r *http.Request) {
	d := LogLinesDTO{
		LogItems: au.logQueue.ReadAll(),
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(d)
}

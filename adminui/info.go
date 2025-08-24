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

	s, err := au.ctrl.GetGeneralSettings()
	if err != nil {
		log.Println("error getting server settings: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	d := ServerInfoDTO{
		PublicKey:                pubkey.String(),
		ExternalAddress:          s.ExternalAddress,
		Subnet:                   config.Values.Wireguard.Range.String(),
		Port:                     port,
		Version:                  au.wagVersion,
		ClusterManagementEnabled: au.db.ClusterManagementEnabled(),
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(d)
}

func (au *AdminUI) consoleLog(w http.ResponseWriter, r *http.Request) {
	d := LogLinesDTO{}

	for _, li := range au.logQueue.w.ReadAll() {
		d.LogItems = append(d.LogItems, string(li))
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(d)
}

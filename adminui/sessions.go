package adminui

import (
	"encoding/json"
	"log"
	"net/http"
)

func (au *AdminUI) getSessions(w http.ResponseWriter, r *http.Request) {
	allSessions, err := au.ctrl.Sessions()
	if err != nil {
		log.Println("error getting sessions: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allSessions)
}

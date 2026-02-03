package adminui

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"
)

func (au *AdminUI) getSessions(w http.ResponseWriter, r *http.Request) {
	allSessions, err := au.ctrl.Sessions()
	if err != nil {
		log.Error().Err(err).Msg("error getting active device sessions")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(allSessions)
}

package server

import (
	"encoding/json"
	"net/http"

	"github.com/NHAS/wag/internal/data"
)

func (wsg *WagControlSocketServer) getAllSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := data.GetAllSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(settings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) getLockout(w http.ResponseWriter, r *http.Request) {
	lockout, err := data.GetLockout()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(lockout)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

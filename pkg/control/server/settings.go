package server

import (
	"encoding/json"
	"net/http"
)

func (wsg *WagControlSocketServer) getGeneralSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := wsg.db.GetGeneralSettings()
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

func (wsg *WagControlSocketServer) getLoginSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := wsg.db.GetLoginSettings()
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
	lockout, err := wsg.db.GetLockout()
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

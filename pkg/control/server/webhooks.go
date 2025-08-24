package server

import (
	"encoding/json"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/safedecoder"
)

func (wsg *WagControlSocketServer) createTempWebhook(w http.ResponseWriter, r *http.Request) {

	id, authHeader, err := wsg.db.CreateTempWebhook()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var t control.TempWebhookResponseDTO
	t.ID = id
	t.Auth = authHeader

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

func (wsg *WagControlSocketServer) getWebhooks(w http.ResponseWriter, r *http.Request) {

	user, err := wsg.db.GetWebhooks()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

}

func (wsg *WagControlSocketServer) getWebhookLastRequest(w http.ResponseWriter, r *http.Request) {

	id := r.URL.Query().Get("id")

	hook, err := wsg.db.GetWebhookLastRequest(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(hook)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)

}

func (wsg *WagControlSocketServer) createWebhook(w http.ResponseWriter, r *http.Request) {

	var (
		hook data.WebhookCreateRequestDTO
	)

	err := safedecoder.Decoder(r.Body).Decode(&hook)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.CreateWebhook(hook)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) deleteWebhooks(w http.ResponseWriter, r *http.Request) {

	var (
		ids []string
	)

	err := safedecoder.Decoder(r.Body).Decode(&ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.DeleteWebhooks(ids)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("OK!"))
}

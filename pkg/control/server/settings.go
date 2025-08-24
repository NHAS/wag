package server

import (
	"encoding/json"
	"net/http"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/pkg/safedecoder"
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

func (wsg *WagControlSocketServer) setGeneralSettings(w http.ResponseWriter, r *http.Request) {
	var (
		generalSettings data.GeneralSettings
		err             error
	)

	err = safedecoder.Decoder(r.Body).Decode(&generalSettings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.SetGeneralSettings(generalSettings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK!"))
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

func (wsg *WagControlSocketServer) setLoginSettings(w http.ResponseWriter, r *http.Request) {
	var (
		loginSettings data.LoginSettings
		err           error
	)

	err = safedecoder.Decoder(r.Body).Decode(&loginSettings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.SetLoginSettings(loginSettings)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK!"))
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

func (wsg *WagControlSocketServer) getAllWebserversSettings(w http.ResponseWriter, r *http.Request) {

	confs, err := wsg.db.GetAllWebserverConfigs()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(confs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) getSingleWebserverSettings(w http.ResponseWriter, r *http.Request) {

	webserverName := r.URL.Query().Get("name")
	if webserverName == "" {
		http.Error(w, "no web server name specified", http.StatusBadRequest)
		return
	}

	confs, err := wsg.db.GetWebserverConfig(data.Webserver(webserverName))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(confs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) setSingleWebserverSettings(w http.ResponseWriter, r *http.Request) {
	var (
		ws  data.WebserverConfiguration
		err error
	)

	webserverName := r.URL.Query().Get("name")
	if webserverName == "" {
		http.Error(w, "no web server name specified", http.StatusBadRequest)
		return
	}

	err = safedecoder.Decoder(r.Body).Decode(&ws)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.SetWebserverConfig(data.Webserver(webserverName), ws)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) getCloudflareToken(w http.ResponseWriter, r *http.Request) {

	token, err := wsg.db.GetAcmeDNS01CloudflareToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) setCloudflareToken(w http.ResponseWriter, r *http.Request) {

	var (
		token string
	)

	err := safedecoder.Decoder(r.Body).Decode(&token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.SetAcmeDNS01CloudflareToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) getAcmeProvider(w http.ResponseWriter, r *http.Request) {

	provider, err := wsg.db.GetAcmeProvider()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) setAcmeProvider(w http.ResponseWriter, r *http.Request) {

	var (
		provider string
	)

	err := safedecoder.Decoder(r.Body).Decode(&provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.SetAcmeProvider(provider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("OK!"))
}

func (wsg *WagControlSocketServer) getAcmeEmail(w http.ResponseWriter, r *http.Request) {

	email, err := wsg.db.GetAcmeEmail()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, err := json.Marshal(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (wsg *WagControlSocketServer) setAcmeEmail(w http.ResponseWriter, r *http.Request) {

	var (
		email string
	)

	err := safedecoder.Decoder(r.Body).Decode(&email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = wsg.db.SetAcmeEmail(email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write([]byte("OK!"))
}

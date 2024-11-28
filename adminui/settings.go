package adminui

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
)

func (au *AdminUI) adminUsersData(w http.ResponseWriter, r *http.Request) {
	adminUsers, err := au.ctrl.ListAdminUsers("")
	if err != nil {
		log.Println("failed to get list of admin users: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(adminUsers)
}

func (au *AdminUI) getGeneralSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := au.ctrl.GetGeneralSettings()
	if err != nil {
		log.Println("failed to get list of admin users: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (au *AdminUI) updateGeneralSettings(w http.ResponseWriter, r *http.Request) {
	var (
		generalSettings data.GeneralSettings
		err             error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&generalSettings)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetGeneralSettings(generalSettings)
	if err != nil {
		log.Println("failed to get general settings: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) getLoginSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := au.ctrl.GetLoginSettings()
	if err != nil {
		log.Println("failed to get login settings: ", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (au *AdminUI) updateLoginSettings(w http.ResponseWriter, r *http.Request) {
	var (
		loginSettings data.LoginSettings
		err           error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&loginSettings)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetLoginSettings(loginSettings)
	if err != nil {
		log.Println("failed to set login settings: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) getAllMfaMethods(w http.ResponseWriter, r *http.Request) {

	resp := []MFAMethodDTO{}

	authenticators := authenticators.GetAllAvaliableMethods()
	for _, a := range authenticators {
		resp = append(resp, MFAMethodDTO{FriendlyName: a.FriendlyName(), Method: a.Type()})
	}

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (au *AdminUI) getAllWebserverConfigs(w http.ResponseWriter, _ *http.Request) {

	confs, err := data.GetAllWebserverConfigs()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var results []WebServerConfigDTO

	for name, conf := range confs {
		results = append(results, WebServerConfigDTO{ServerName: name, WebserverConfiguration: conf})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ServerName < results[j].ServerName
	})

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (au *AdminUI) editWebserverConfig(w http.ResponseWriter, r *http.Request) {

	var (
		s   WebServerConfigDTO
		err error
	)
	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&s)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	host, port, err := net.SplitHostPort(s.ListenAddress)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = fmt.Errorf("listen address was not in host:port format: %q", s.ListenAddress)
		return
	}

	if s.ServerName == string(data.Tunnel) {
		var (
			details    data.WebserverConfiguration
			storedHost string
		)
		details, err = data.GetWebserverConfig(data.Tunnel)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			err = fmt.Errorf("unable to get tunnel webserver configuration to check ip: %w", err)
			return
		}

		storedHost, _, err = net.SplitHostPort(details.ListenAddress)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if storedHost != host {
			w.WriteHeader(http.StatusBadRequest)
			err = fmt.Errorf("cannot change tunnel address")
			return
		}

		s.ListenAddress = storedHost + ":" + port

	}

	err = data.SetWebserverConfig(data.Webserver(s.ServerName), s.WebserverConfiguration)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (au *AdminUI) getAcmeDetails(w http.ResponseWriter, _ *http.Request) {

	var (
		results AcmeDetailsResponseDTO
		err     error
	)

	cfToken, err := data.GetAcmeDNS01CloudflareToken()
	results.CloudflareToken = (err == nil && cfToken.APIToken != "")

	results.ProviderURL, _ = data.GetAcmeProvider()

	results.Email, _ = data.GetAcmeEmail()

	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func (au *AdminUI) editAcmeEmail(w http.ResponseWriter, r *http.Request) {

	var (
		email StringDTO
		err   error
	)

	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&email)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetAcmeEmail(email.Data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

func (au *AdminUI) editAcmeProvider(w http.ResponseWriter, r *http.Request) {

	var (
		provider StringDTO
		err      error
	)

	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&provider)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetAcmeProvider(provider.Data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

func (au *AdminUI) editCloudflareApiToken(w http.ResponseWriter, r *http.Request) {

	var (
		token StringDTO
		err   error
	)

	defer func() { au.respond(err, w) }()

	err = json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.SetAcmeDNS01CloudflareToken(token.Data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

package mfaportal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"

	"github.com/NHAS/wag/internal/autotls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/resources"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
)

type MfaPortal struct {
	firewall *router.Firewall

	listenerKeys struct {
		Oidc       string
		Domain     string
		MFAMethods string
		Issuer     string
	}
}

func (mp *MfaPortal) Close() {

	autotls.Do.Close(data.Public)

	mp.deregisterListeners()

	log.Println("Stopped MFA portal")
}

func New(firewall *router.Firewall, errChan chan<- error) (m *MfaPortal, err error) {
	if firewall == nil {
		panic("firewall was nil")
	}

	var mfaPortal MfaPortal
	mfaPortal.firewall = firewall

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("GET /status/", mfaPortal.status)
	tunnel.HandleFunc("GET /routes/", mfaPortal.routes)

	tunnel.HandleFunc("GET /logout/", mfaPortal.logout)

	if config.Values.MFATemplatesDirectory != "" {
		fs := http.FileServer(http.Dir(path.Join(config.Values.MFATemplatesDirectory, "static")))
		tunnel.Handle("/custom/", http.StripPrefix("/custom/", fs))
	}

	tunnel.HandleFunc("GET /static/", utils.EmbeddedStatic(resources.Static))

	// Do inital state setup for our authentication methods
	err = authenticators.AddMFARoutes(tunnel, mfaPortal.firewall)
	if err != nil {
		return nil, fmt.Errorf("failed to add mfa routes: %s", err)
	}

	// For any change to the authentication config re-up
	err = mfaPortal.registerListeners()
	if err != nil {
		return nil, fmt.Errorf("failed ot register listeners: %s", err)
	}

	// TODO split these out to their own post/get endpoints
	tunnel.HandleFunc("GET /authorise/", mfaPortal.authorise)
	tunnel.HandleFunc("POST /authorise/", mfaPortal.authorise)
	tunnel.HandleFunc("GET /register_mfa/", mfaPortal.registerMFA)
	tunnel.HandleFunc("POST /register_mfa/", mfaPortal.registerMFA)

	tunnel.HandleFunc("GET /public_key/", mfaPortal.publicKey)

	tunnel.HandleFunc("GET /challenge/", mfaPortal.firewall.Verifier.WS)

	tunnel.HandleFunc("/", mfaPortal.index)

	if err := autotls.Do.DynamicListener(data.Tunnel, utils.SetSecurityHeaders(tunnel)); err != nil {
		return nil, err
	}

	log.Println("[PORTAL] Captive portal started listening")
	return m, nil
}

func (mp *MfaPortal) index(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if mp.firewall.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if user.IsEnforcingMFA() {
		http.Redirect(w, r, "/authorise/", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/register_mfa/", http.StatusSeeOther)
}

func (mp *MfaPortal) registerMFA(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)

	if mp.firewall.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	method := r.URL.Query().Get("method")
	if method == "" {
		method, err = data.GetDefaultMfaMethod()
		if err != nil {
			method = ""
		}
	}

	if method == "" || method == "select" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var menu resources.Menu

		for _, method := range authenticators.GetAllEnabledMethods() {

			menu.MFAMethods = append(menu.MFAMethods, resources.MenuEntry{
				Path:         method.Type(),
				FriendlyName: method.FriendlyName(),
			})
		}

		menu.LastElement = len(menu.MFAMethods) - 1

		err = resources.Render("register_mfa.html", w, &menu)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to build template:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}

		return
	}

	mfaMethod, ok := authenticators.GetMethod(method)
	if !ok {
		log.Println(user.Username, clientTunnelIp, "Invalid MFA type requested: ", method)
		http.NotFound(w, r)
		return
	}

	mfaMethod.RegistrationUI(w, r, user.Username, clientTunnelIp.String())
}

func (mp *MfaPortal) authorise(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if mp.firewall.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	mfaMethod, ok := authenticators.GetMethod(user.GetMFAType())
	if !ok {
		log.Println(user.Username, clientTunnelIp, "Invalid MFA type requested: ", user.GetMFAType())

		http.NotFound(w, r)
		return
	}

	mfaMethod.MFAPromptUI(w, r, user.Username, clientTunnelIp.String())
}

func (mp *MfaPortal) logout(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if !mp.firewall.IsAuthed(clientTunnelIp.String()) {
		http.NotFound(w, r)
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	err = user.Deauthenticate(clientTunnelIp.String())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "could not deauthenticate:", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	method, ok := authenticators.GetMethod(user.GetMFAType())
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, method.LogoutPath(), http.StatusSeeOther)
}

func (mp *MfaPortal) routes(w http.ResponseWriter, r *http.Request) {
	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println("unknown", remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	routes, err := mp.firewall.GetRoutes(user.Username)
	if err != nil {
		log.Println(user.Username, remoteAddress, "Getting routes from firewall failed: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(strings.Join(routes, ", ")))

}

func (mp *MfaPortal) status(w http.ResponseWriter, r *http.Request) {
	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println("unknown", remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	acl := data.GetEffectiveAcl(user.Username)

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "application/json")
	status := struct {
		IsAuthorised bool
		MFA          []string
		Public       []string
	}{
		IsAuthorised: mp.firewall.IsAuthed(remoteAddress.String()),
		MFA:          acl.Mfa,
		Public:       acl.Allow,
	}

	result, err := json.Marshal(&status)
	if err != nil {
		log.Println(user.Username, remoteAddress, "error marshalling status")
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Write(result)
}

func (mp *MfaPortal) publicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=pubkey")
	w.Header().Set("Content-Type", "text/plain")

	wgPublicKey, _, err := mp.firewall.ServerDetails()
	if err != nil {
		log.Println("unable access wireguard device: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(wgPublicKey.String()))
}

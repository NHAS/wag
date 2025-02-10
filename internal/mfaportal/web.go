package mfaportal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/autotls"
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

	// Do inital state setup for our authentication methods
	err = authenticators.AddMFARoutes(tunnel, mfaPortal.firewall)
	if err != nil {
		return nil, fmt.Errorf("failed to add mfa routes: %s", err)
	}

	// TODO split these out to their own post/get endpoints
	tunnel.HandleFunc("GET /authorise/", mfaPortal.authorise)
	tunnel.HandleFunc("POST /authorise/", mfaPortal.authorise)
	tunnel.HandleFunc("GET /register_mfa/", mfaPortal.registerMFA)
	tunnel.HandleFunc("POST /register_mfa/", mfaPortal.registerMFA)

	tunnel.HandleFunc("GET /api/pam", mfaPortal.authorise)
	tunnel.HandleFunc("GET /api/totp", mfaPortal.authorise)

	tunnel.HandleFunc("GET /api/webauthn/register", mfaPortal.authorise)
	tunnel.HandleFunc("GET /api/webauthn/authorise", mfaPortal.authorise)

	tunnel.HandleFunc("GET /api/challenge", mfaPortal.firewall.Verifier.WS)

	tunnel.HandleFunc("GET /api/public_key", mfaPortal.publicKey)
	tunnel.HandleFunc("GET /api/status", mfaPortal.status)
	tunnel.HandleFunc("GET /api/userinfo", mfaPortal.userinfo)
	tunnel.HandleFunc("GET /api/routes", mfaPortal.routes)
	tunnel.HandleFunc("GET /api/logout", mfaPortal.logout)

	tunnel.HandleFunc("GET /logout/", mfaPortal.logout)

	tunnel.HandleFunc("/", utils.EmbeddedStatic(resources.Static))

	if err := autotls.Do.DynamicListener(data.Tunnel, utils.SetSecurityHeaders(fetchState(tunnel, mfaPortal.firewall))); err != nil {
		return nil, err
	}

	log.Println("[PORTAL] Captive portal started listening")

	// For any change to the authentication config re-up
	// This should always be done at the bottom
	err = mfaPortal.registerListeners()
	if err != nil {
		return nil, fmt.Errorf("failed ot register listeners: %s", err)
	}

	return m, nil
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

	if !Authed(r.Context()) {
		http.NotFound(w, r)
		return
	}

	clientTunnelIp := utils.GetIPFromRequest(r)

	user := users.GetUserFromContext(r.Context())

	err := user.Deauthenticate(clientTunnelIp.String())
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
	user := users.GetUserFromContext(r.Context())

	routes, err := mp.firewall.GetRoutes(user.Username)
	if err != nil {
		log.Println(user.Username, "Getting routes from firewall failed: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(strings.Join(routes, ", ")))
}

func (mp *MfaPortal) status(w http.ResponseWriter, r *http.Request) {
	user := users.GetUserFromContext(r.Context())

	acl := data.GetEffectiveAcl(user.Username)

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "application/json")
	status := StatusDTO{
		IsAuthorised: Authed(r.Context()),
		MFA:          acl.Mfa,
		Public:       acl.Allow,
		Deny:         acl.Deny,
	}

	json.NewEncoder(w).Encode(status)
}

func (mp *MfaPortal) userinfo(w http.ResponseWriter, r *http.Request) {

	u := users.GetUserFromContext(r.Context())

	authenticators := authenticators.GetAllEnabledMethods()
	names := []MFAMethod{}
	for _, a := range authenticators {
		names = append(names, MFAMethod{
			FriendlyName: a.FriendlyName(),
			Method:       a.Type(),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	info := UserInfoDTO{
		HelpMail:            data.GetHelpMail(),
		AvailableMfaMethods: names,
		Locked:              u.Locked,
		Registered:          u.Enforcing,
		Username:            u.Username,
		Authorised:          Authed(r.Context()),
	}

	json.NewEncoder(w).Encode(info)
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

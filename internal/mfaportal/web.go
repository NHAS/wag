package mfaportal

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/resources"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/httputils"
)

type MfaPortal struct {
	tunnelHTTPServ *http.Server
	tunnelTLSServ  *http.Server

	firewall *router.Firewall

	listenerKeys struct {
		Oidc       string
		Domain     string
		MFAMethods string
		Issuer     string
	}
}

func (mp *MfaPortal) Close() {

	if mp.tunnelHTTPServ != nil {
		mp.tunnelHTTPServ.Close()
	}

	if mp.tunnelTLSServ != nil {
		mp.tunnelTLSServ.Close()
	}

	mp.deregisterListeners()

	log.Println("Stopped MFA portal")
}

func New(firewall *router.Firewall, errChan chan<- error) (m *MfaPortal, err error) {
	if firewall == nil {
		panic("firewall was nil")
	}

	var mfaPortal MfaPortal
	mfaPortal.firewall = firewall

	//https://blog.cloudflare.com/exposing-go-on-the-internet/
	tlsConfig := &tls.Config{
		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	tunnel := httputils.NewMux()

	tunnel.Get("/status/", mfaPortal.status)
	tunnel.Get("/routes/", mfaPortal.routes)

	tunnel.Get("/logout/", mfaPortal.logout)

	if config.Values.MFATemplatesDirectory != "" {
		fs := http.FileServer(http.Dir(path.Join(config.Values.MFATemplatesDirectory, "static")))
		tunnel.Handle("/custom/", http.StripPrefix("/custom/", fs))
	}

	tunnel.Get("/static/", utils.EmbeddedStatic(resources.Static))

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

	tunnel.GetOrPost("/authorise/", mfaPortal.authorise)
	tunnel.GetOrPost("/register_mfa/", mfaPortal.registerMFA)

	tunnel.Get("/public_key/", mfaPortal.publicKey)

	tunnel.Get("/challenge/", mfaPortal.firewall.Verifier.WS)

	tunnel.GetOrPost("/", mfaPortal.index)

	address := config.Values.Wireguard.ServerAddress.String()
	if config.Values.Wireguard.ServerAddress.To4() == nil && config.Values.Wireguard.ServerAddress.To16() != nil {
		address = "[" + address + "]"
	}

	tunnelListenAddress := address + ":" + config.Values.Webserver.Tunnel.Port
	if config.Values.Webserver.Tunnel.SupportsTLS() {

		go func() {

			mfaPortal.tunnelTLSServ = &http.Server{
				Addr:         tunnelListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      utils.SetSecurityHeaders(tunnel),
			}
			if err := mfaPortal.tunnelTLSServ.ListenAndServeTLS(config.Values.Webserver.Tunnel.CertPath, config.Values.Webserver.Tunnel.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("TLS webserver tunnel listener failed: %v", err)
			}

		}()

		if config.Values.NumberProxies == 0 {
			go func() {

				port := ":" + config.Values.Webserver.Tunnel.Port
				if port == "443" {
					port = ""
				}

				mfaPortal.tunnelHTTPServ = &http.Server{
					Addr:         address + ":80",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      utils.SetSecurityHeaders(utils.SetRedirectHandler(port)),
				}

				log.Printf("HTTP redirect to TLS webserver tunnel listener failed: %v", mfaPortal.tunnelHTTPServ.ListenAndServe())
			}()
		}
	} else {
		go func() {
			mfaPortal.tunnelHTTPServ = &http.Server{
				Addr:         tunnelListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      utils.SetSecurityHeaders(tunnel),
			}

			if err := mfaPortal.tunnelHTTPServ.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("webserver tunnel listener failed: %v", err)
			}

		}()
	}

	//Group the print statement so that multithreading won't disorder them
	log.Println("[PORTAL] Captive portal started listening: ", tunnelListenAddress)
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
		http.Redirect(w, r, "/authorise/", http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, "/register_mfa/", http.StatusTemporaryRedirect)
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
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
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
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, method.LogoutPath(), http.StatusTemporaryRedirect)
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

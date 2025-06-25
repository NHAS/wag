package mfaportal

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/autotls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/mfaportal/authenticators"
	"github.com/NHAS/wag/internal/mfaportal/resources"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
)

type MfaPortal struct {
	firewall *router.Firewall
	session  *Challenger

	watchers []io.Closer
	db       interfaces.Database
}

func (mp *MfaPortal) Close() {

	autotls.Do.Close(data.Public)
	if mp.session != nil {
		mp.session.Close()
	}

	for _, w := range mp.watchers {
		w.Close()
	}

	log.Println("Stopped MFA portal")
}

func New(db interfaces.Database, firewall *router.Firewall, errChan chan<- error) (m *MfaPortal, err error) {
	if firewall == nil {
		panic("firewall was nil")
	}

	var mfaPortal MfaPortal
	mfaPortal.db = db
	mfaPortal.firewall = firewall

	mfaPortal.session, err = NewChallenger(db, firewall)
	if err != nil {
		return nil, err
	}

	tunnel := http.NewServeMux()

	// Do inital state setup for our authentication methods
	err = authenticators.AddMFARoutes(db, tunnel, mfaPortal.firewall)
	if err != nil {
		return nil, fmt.Errorf("failed to add mfa routes: %s", err)
	}

	tunnel.HandleFunc("GET /api/session", mfaPortal.session.WS)

	// legacy
	tunnel.HandleFunc("GET /public_key", mfaPortal.publicKey)
	tunnel.HandleFunc("GET /status", mfaPortal.status)
	tunnel.HandleFunc("GET /routes", mfaPortal.routes)

	// as of v9.0.0
	tunnel.HandleFunc("GET /api/public_key", mfaPortal.publicKey)
	tunnel.HandleFunc("GET /api/status", mfaPortal.status)
	tunnel.HandleFunc("GET /api/routes", mfaPortal.routes)

	tunnel.HandleFunc("POST /api/logout", mfaPortal.logout)

	tunnel.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		resources.Assets(w, r)
	})

	if err := autotls.Do.DynamicListener(data.Tunnel, utils.SetSecurityHeaders(fetchState(tunnel, db, mfaPortal.firewall))); err != nil {
		return nil, err
	}

	log.Println("[PORTAL] Captive portal started listening, port", config.Values.Webserver.Tunnel.Port)

	// For any change to the authentication config re-up
	// This should always be done at the bottom
	err = mfaPortal.registerListeners()
	if err != nil {
		return nil, fmt.Errorf("failed ot register listeners: %s", err)
	}

	return m, nil
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

	w.WriteHeader(http.StatusNoContent)
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

	acl := mp.db.GetEffectiveAcl(user.Username)

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

package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/router"
)

func (wsg *WagControlSocketServer) firewallRules(w http.ResponseWriter, r *http.Request) {

	rules, err := wsg.firewall.GetRules()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	result, err := json.Marshal(rules)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(result)
}

func (wsg *WagControlSocketServer) version(w http.ResponseWriter, r *http.Request) {
	if config.Version == "" {
		config.Version = "DEBUG (git tag not injected)"
	}

	w.Write([]byte(config.Version))
}

func (wsg *WagControlSocketServer) shutdown(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//We need to remove the unix control socket at the very least
	returnCode := 0
	if r.FormValue("cleanup") == "false" {
		returnCode = 3
	}

	w.Write([]byte("OK"))

	wsg.TearDown()

	os.Exit(returnCode)
}

type WagControlSocketServer struct {
	socket net.Listener

	firewall *router.Firewall
	httpSrv  *http.Server

	db interfaces.Database
}

func NewControlServer(database interfaces.Database, firewall *router.Firewall) (*WagControlSocketServer, error) {
	if firewall == nil {
		panic("firewall is nil")
	}

	var srvSock WagControlSocketServer
	srvSock.firewall = firewall
	srvSock.db = database

	if _, err := os.Stat(config.Values.Socket); err == nil {

		conn, err := net.DialTimeout("unix", config.Values.Socket, 200*time.Millisecond)
		if err != nil {
			err = os.Remove(config.Values.Socket)
			if err != nil {
				return nil, fmt.Errorf("failed to create unix socket %q for control server: %w", config.Values.Socket, err)
			}
		} else {
			conn.Close()
			return nil, fmt.Errorf("failed to create unix socket %q for control server, Wag is already running", config.Values.Socket)
		}
	}

	l, err := net.Listen("unix", config.Values.Socket)
	if err != nil {
		return nil, fmt.Errorf("failed to create unix socket %q for control server: %w", config.Values.Socket, err)
	}
	srvSock.socket = l

	//Yes I know this is doubling up on the umask, but meh
	if err := os.Chmod(config.Values.Socket, 0760); err != nil {
		return nil, fmt.Errorf("failed to chmod control socket %q to allow group control: %s", config.Values.Socket, err)
	}

	if config.Values.GID != nil {
		if err := os.Chown(config.Values.Socket, -1, *config.Values.GID); err != nil {
			return nil, fmt.Errorf("failed to chown control socket %q to group %d: %s", config.Values.Socket, *config.Values.GID, err)
		}
	}

	log.Println("[CONTROL] Started socket: ", config.Values.Socket)

	controlMux := http.NewServeMux()

	controlMux.HandleFunc("GET /device/sessions", srvSock.sessions)

	controlMux.HandleFunc("GET /device/list", srvSock.listDevices)
	controlMux.HandleFunc("POST /device/lock", srvSock.lockDevice)
	controlMux.HandleFunc("POST /device/unlock", srvSock.unlockDevice)
	controlMux.HandleFunc("POST /device/delete", srvSock.deleteDevice)
	controlMux.HandleFunc("POST /devices", srvSock.addDevice)

	controlMux.HandleFunc("GET /users/acls", srvSock.getUserAcl)
	controlMux.HandleFunc("GET /users/groups", srvSock.getUserGroups)
	controlMux.HandleFunc("GET /users/list", srvSock.listUsers)
	controlMux.HandleFunc("POST /users/lock", srvSock.lockUser)
	controlMux.HandleFunc("POST /users/unlock", srvSock.unlockUser)
	controlMux.HandleFunc("POST /users/delete", srvSock.deleteUser)
	controlMux.HandleFunc("POST /users/reset", srvSock.resetMfaUser)
	controlMux.HandleFunc("POST /users", srvSock.addUser)

	controlMux.HandleFunc("GET /groups/list", srvSock.listGroups)

	controlMux.HandleFunc("GET /webadmin/user", srvSock.getAdminUser)
	controlMux.HandleFunc("GET /webadmin/list", srvSock.listAdminUsers)
	controlMux.HandleFunc("POST /webadmin/lock", srvSock.lockAdminUser)
	controlMux.HandleFunc("POST /webadmin/unlock", srvSock.unlockAdminUser)
	controlMux.HandleFunc("POST /webadmin/delete", srvSock.deleteAdminUser)
	controlMux.HandleFunc("POST /webadmin/reset", srvSock.resetAdminUser)
	controlMux.HandleFunc("POST /webadmin/add", srvSock.addAdminUser)

	controlMux.HandleFunc("GET /webhooks/temp", srvSock.createTempWebhook)
	controlMux.HandleFunc("GET /webhooks", srvSock.getWebhooks)
	controlMux.HandleFunc("POST /webhooks", srvSock.createWebhook)
	controlMux.HandleFunc("DELETE /webhooks", srvSock.deleteWebhooks)

	controlMux.HandleFunc("GET /webhook/last_request", srvSock.getWebhookLastRequest)

	controlMux.HandleFunc("GET /firewall/list", srvSock.firewallRules)
	controlMux.HandleFunc("GET /config/policies/list", srvSock.policies)
	controlMux.HandleFunc("POST /config/policy/edit", srvSock.editPolicy)
	controlMux.HandleFunc("POST /config/policy/create", srvSock.newPolicy)
	controlMux.HandleFunc("POST /config/policies/delete", srvSock.deletePolicies)

	controlMux.HandleFunc("GET /config/group/list", srvSock.groups)
	controlMux.HandleFunc("POST /config/group/edit", srvSock.editGroup)
	controlMux.HandleFunc("POST /config/group/create", srvSock.newGroup)
	controlMux.HandleFunc("POST /config/group/delete", srvSock.deleteGroup)

	controlMux.HandleFunc("POST /db/get", srvSock.getDBKey)
	controlMux.HandleFunc("POST /db/put", srvSock.putDBKey)

	controlMux.HandleFunc("GET /config/settings/general", srvSock.getGeneralSettings)
	controlMux.HandleFunc("POST /config/settings/general", srvSock.setGeneralSettings)
	controlMux.HandleFunc("GET /config/settings/login", srvSock.getLoginSettings)
	controlMux.HandleFunc("POST /config/settings/login", srvSock.setLoginSettings)
	controlMux.HandleFunc("GET /config/settings/webservers", srvSock.getAllWebserversSettings)
	controlMux.HandleFunc("GET /config/settings/webserver", srvSock.getSingleWebserverSettings)
	controlMux.HandleFunc("POST /config/settings/webserver", srvSock.setSingleWebserverSettings)
	controlMux.HandleFunc("GET /config/settings/acme/cloudflare/dns01token", srvSock.getCloudflareToken)
	controlMux.HandleFunc("POST /config/settings/acme/cloudflare/dns01token", srvSock.setCloudflareToken)
	controlMux.HandleFunc("GET /config/settings/acme/provider", srvSock.getAcmeProvider)
	controlMux.HandleFunc("POST /config/settings/acme/provider", srvSock.setAcmeProvider)
	controlMux.HandleFunc("GET /config/settings/acme/email", srvSock.getAcmeEmail)
	controlMux.HandleFunc("POST /config/settings/acme/email", srvSock.setAcmeEmail)

	controlMux.HandleFunc("GET /config/settings/lockout", srvSock.getLockout)

	controlMux.HandleFunc("GET /version", srvSock.version)

	controlMux.HandleFunc("POST /shutdown", srvSock.shutdown)

	controlMux.HandleFunc("GET /registration/list", srvSock.listRegistrations)
	controlMux.HandleFunc("POST /registration/create", srvSock.newRegistration)
	controlMux.HandleFunc("POST /registration/delete", srvSock.deleteRegistration)

	if srvSock.db.ClusterManagementEnabled() {
		controlMux.HandleFunc("GET /clustering/errors", srvSock.listErrors)
		controlMux.HandleFunc("GET /clustering/members", srvSock.listMembers)
		controlMux.HandleFunc("GET /clustering/ping", srvSock.getLastMemberPing)
	}
	srvSock.httpSrv = &http.Server{
		Handler: controlMux,
	}

	go func() {
		err := srvSock.httpSrv.Serve(srvSock.socket)
		if err != nil && err != http.ErrServerClosed {
			log.Println("failed to serve control socket: ", err)
		}
	}()

	return &srvSock, nil
}

func (wsg *WagControlSocketServer) TearDown() error {

	// contains an implicit wsg.socket.Close(), which will remove the unix socket
	err := wsg.httpSrv.Close()
	if err != nil {
		return fmt.Errorf("failed to stop (and remove) wag control socket %q this may cause error on next start, delete to start %q: %s", config.Values.Socket, config.Values.Socket, err)
	}

	return nil
}

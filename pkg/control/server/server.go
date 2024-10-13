package server

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/httputils"
)

// func (wsg *WagControlSocketServer) firewallRules(w http.ResponseWriter, r *http.Request) {

// 	rules, err := router.GetRules()
// 	if err != nil {
// 		http.Error(w, err.Error(), 500)
// 		return
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	result, err := json.Marshal(rules)
// 	if err != nil {
// 		http.Error(w, err.Error(), 500)
// 		return
// 	}

// 	w.Write(result)
// }

func (wsg *WagControlSocketServer) version(w http.ResponseWriter, r *http.Request) {
	if config.Version == "" {
		config.Version = "DEBUG (git tag not injected)"
	}

	w.Write([]byte(config.Version))
}

func (wsg *WagControlSocketServer) shutdown(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
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
}

func NewControlServer(firewall *router.Firewall) (*WagControlSocketServer, error) {
	if firewall == nil {
		panic("firewall is nil")
	}

	var srvSock WagControlSocketServer
	srvSock.firewall = firewall

	l, err := net.Listen("unix", config.Values.Socket)
	if err != nil {
		return nil, fmt.Errorf("failed to create unix socket %q for control server: %s", config.Values.Socket, err)
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

	log.Println("Started control socket: \n\t\t\t", config.Values.Socket)

	controlMux := httputils.NewMux()

	controlMux.Get("/device/list", srvSock.listDevices)
	controlMux.Post("/device/lock", srvSock.lockDevice)
	controlMux.Post("/device/unlock", srvSock.unlockDevice)
	controlMux.Get("/device/sessions", srvSock.sessions)
	controlMux.Post("/device/delete", srvSock.deleteDevice)

	controlMux.Get("/users/groups", srvSock.getUserGroups)
	controlMux.Get("/users/list", srvSock.listUsers)
	controlMux.Post("/users/lock", srvSock.lockUser)
	controlMux.Post("/users/unlock", srvSock.unlockUser)
	controlMux.Post("/users/delete", srvSock.deleteUser)
	controlMux.Post("/users/reset", srvSock.resetMfaUser)
	controlMux.Get("/users/acls", srvSock.getUserAcl)

	controlMux.Get("/groups/list", srvSock.listGroups)

	controlMux.Get("/webadmin/list", srvSock.listAdminUsers)
	controlMux.Post("/webadmin/lock", srvSock.lockAdminUser)
	controlMux.Post("/webadmin/unlock", srvSock.unlockAdminUser)
	controlMux.Post("/webadmin/delete", srvSock.deleteAdminUser)
	controlMux.Post("/webadmin/reset", srvSock.resetAdminUser)
	controlMux.Post("/webadmin/add", srvSock.addAdminUser)

	//controlMux.Get("/firewall/list", firewallRules)
	controlMux.Get("/config/policies/list", srvSock.policies)
	controlMux.Post("/config/policy/edit", srvSock.editPolicy)
	controlMux.Post("/config/policy/create", srvSock.newPolicy)
	controlMux.Post("/config/policies/delete", srvSock.deletePolicies)

	controlMux.Get("/config/group/list", srvSock.groups)
	controlMux.Post("/config/group/edit", srvSock.editGroup)
	controlMux.Post("/config/group/create", srvSock.newGroup)
	controlMux.Post("/config/group/delete", srvSock.deleteGroup)

	controlMux.Get("/config/settings", srvSock.getAllSettings)
	controlMux.Get("/config/settings/lockout", srvSock.getLockout)

	controlMux.Get("/version", srvSock.version)

	controlMux.Post("/shutdown", srvSock.shutdown)

	controlMux.Get("/registration/list", srvSock.listRegistrations)
	controlMux.Post("/registration/create", srvSock.newRegistration)
	controlMux.Post("/registration/delete", srvSock.deleteRegistration)

	controlMux.Get("/clustering/errors", srvSock.listErrors)
	controlMux.Get("/clustering/members", srvSock.listMembers)
	controlMux.Get("/clustering/ping", srvSock.getLastMemberPing)

	srvSock.httpSrv = &http.Server{
		Handler: controlMux,
	}

	go func() {
		err := srvSock.httpSrv.Serve(srvSock.socket)
		if err != nil {
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

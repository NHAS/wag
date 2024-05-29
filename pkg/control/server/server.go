package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/httputils"
)

func firewallRules(w http.ResponseWriter, r *http.Request) {

	rules, err := router.GetRules()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	result, err := json.Marshal(rules)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(result)
}

func version(w http.ResponseWriter, r *http.Request) {
	if config.Version == "" {
		config.Version = "DEBUG (git tag not injected)"
	}

	w.Write([]byte(config.Version))
}

func bpfVersion(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(router.GetBPFHash()))
}

func shutdown(w http.ResponseWriter, r *http.Request) {
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

	TearDown()

	os.Exit(returnCode)
}

func StartControlSocket() error {

	l, err := net.Listen("unix", config.Values.Socket)
	if err != nil {
		return err
	}

	//Yes I know this is doubling up on the umask, but meh
	if err := os.Chmod(config.Values.Socket, 0760); err != nil {
		return err
	}

	if config.Values.GID != nil {
		if err := os.Chown(config.Values.Socket, -1, *config.Values.GID); err != nil {
			return err
		}
	}

	log.Println("Started control socket: \n\t\t\t", config.Values.Socket)

	controlMux := httputils.NewMux()

	controlMux.Get("/device/list", listDevices)
	controlMux.Post("/device/lock", lockDevice)
	controlMux.Post("/device/unlock", unlockDevice)
	controlMux.Get("/device/sessions", sessions)
	controlMux.Post("/device/delete", deleteDevice)

	controlMux.Get("/users/groups", getUserGroups)
	controlMux.Get("/users/list", listUsers)
	controlMux.Post("/users/lock", lockUser)
	controlMux.Post("/users/unlock", unlockUser)
	controlMux.Post("/users/delete", deleteUser)
	controlMux.Post("/users/reset", resetMfaUser)
	controlMux.Get("/users/acls", getUserAcl)

	controlMux.Get("/groups/list", listGroups)

	controlMux.Get("/webadmin/list", listAdminUsers)
	controlMux.Post("/webadmin/lock", lockAdminUser)
	controlMux.Post("/webadmin/unlock", unlockAdminUser)
	controlMux.Post("/webadmin/delete", deleteAdminUser)
	controlMux.Post("/webadmin/reset", resetAdminUser)
	controlMux.Post("/webadmin/add", addAdminUser)

	controlMux.Get("/firewall/list", firewallRules)
	controlMux.Get("/config/policies/list", policies)
	controlMux.Post("/config/policy/edit", editPolicy)
	controlMux.Post("/config/policy/create", newPolicy)
	controlMux.Post("/config/policies/delete", deletePolicies)

	controlMux.Get("/config/group/list", groups)
	controlMux.Post("/config/group/edit", editGroup)
	controlMux.Post("/config/group/create", newGroup)
	controlMux.Post("/config/group/delete", deleteGroup)

	controlMux.Get("/config/settings", getAllSettings)
	controlMux.Get("/config/settings/lockout", getLockout)

	controlMux.Get("/version", version)
	controlMux.Get("/version/bpf", bpfVersion)

	controlMux.Post("/shutdown", shutdown)

	controlMux.Get("/registration/list", listRegistrations)
	controlMux.Post("/registration/create", newRegistration)
	controlMux.Post("/registration/delete", deleteRegistration)

	controlMux.Get("/clustering/errors", listErrors)
	controlMux.Get("/clustering/members", listMembers)
	controlMux.Get("/clustering/ping", getLastMemberPing)

	go func() {
		srv := &http.Server{
			Handler: controlMux,
		}

		log.Println("failed to serve control socket: ", srv.Serve(l))
	}()
	return nil
}

func TearDown() {
	err := os.Remove(config.Values.Socket)
	if err != nil {
		log.Println(err)
	}
}

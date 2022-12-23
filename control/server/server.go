package server

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/router"
)

var socket string

func firewallRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

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

func configReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := config.Reload()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	errs := router.RefreshConfiguration()
	if len(errs) > 0 {
		w.WriteHeader(500)
		w.Header().Set("Content-Type", "text/plain")
		for _, err := range errs {
			w.Write([]byte(err.Error() + "\n"))
		}
		return
	}

	log.Println("Config reloaded")

	w.Write([]byte("OK!"))
}

func version(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	if config.Version == "" {
		config.Version = "UNKNOWN"
	}

	w.Write([]byte(config.Version))
}

func bpfVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	w.Write([]byte(router.GetBPFHash()))
}

func shutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

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

func pinBPF(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	err := router.Pin()
	if err != nil {
		http.Error(w, errors.New("Could not pin ebpf assets: "+err.Error()).Error(), 500)
		return
	}

	w.Write([]byte("OK"))

}

func unpinBPF(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	err := router.Unpin()
	if err != nil {
		http.Error(w, errors.New("Could not unpin ebpf assets: "+err.Error()).Error(), 500)
		return
	}

	w.Write([]byte("OK"))
}

func StartControlSocket() error {

	l, err := net.Listen("unix", config.Values().Socket)
	if err != nil {
		return err
	}

	//Yes I know this is doubling up on the umask, but meh
	if err := os.Chmod(config.Values().Socket, 0760); err != nil {
		return err
	}

	log.Println("Started control socket: \n\t\t\t", config.Values().Socket)

	controlMux := http.NewServeMux()

	controlMux.HandleFunc("/device/list", listDevices)
	controlMux.HandleFunc("/device/lock", lockDevice)
	controlMux.HandleFunc("/device/unlock", unlockDevice)
	controlMux.HandleFunc("/device/sessions", sessions)
	controlMux.HandleFunc("/device/delete", deleteDevice)

	controlMux.HandleFunc("/users/list", listUsers)
	controlMux.HandleFunc("/users/lock", lockUser)
	controlMux.HandleFunc("/users/unlock", unlockUser)
	controlMux.HandleFunc("/users/delete", deleteUser)
	controlMux.HandleFunc("/users/reset", resetMfaUser)

	controlMux.HandleFunc("/firewall/list", firewallRules)

	controlMux.HandleFunc("/config/reload", configReload)

	controlMux.HandleFunc("/version", version)
	controlMux.HandleFunc("/version/bpf", bpfVersion)

	controlMux.HandleFunc("/ebpf/pin", pinBPF)
	controlMux.HandleFunc("/ebpf/unpin", unpinBPF)

	controlMux.HandleFunc("/shutdown", shutdown)

	controlMux.HandleFunc("/registration/list", listRegistrations)
	controlMux.HandleFunc("/registration/create", newRegistration)
	controlMux.HandleFunc("/registration/delete", deleteRegistration)

	go func() {
		srv := &http.Server{
			Handler: controlMux,
		}

		srv.Serve(l)
	}()
	return nil
}

func TearDown() {
	err := os.Remove(config.Values().Socket)
	if err != nil {
		log.Println(err)
	}
}

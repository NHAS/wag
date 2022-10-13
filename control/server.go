package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/database"
	"github.com/NHAS/wag/router"
)

const controlSocket = "/tmp/wag.sock"

func listDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	username := r.FormValue("username")
	if username != "" {
		d, err := database.GetDeviceByUsername(username)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		//Needs to be an array to match the list all option
		ds := []database.Device{d}

		b, err := json.Marshal(ds)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)

		return
	}

	devices, err := database.GetDevices()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	b, err := json.Marshal(devices)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func lockDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	d, err := database.GetDeviceByUsername(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = router.Deauthenticate(d.Address)
	if err != nil {
		http.Error(w, "not found: "+err.Error(), 404)
		return
	}

	err = database.SetAttempts(d.Address, config.Values().Lockout+1)
	if err != nil {
		http.Error(w, "could not lock device in db: "+err.Error(), 404)
		return
	}

	w.Write([]byte("OK"))
}

func unlockDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	username, err := url.QueryUnescape(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	d, err := database.GetDeviceByUsername(username)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = database.SetAttempts(d.Address, 0)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write([]byte("OK"))
}

func sessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	sessions, err := router.GetAllAuthorised()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	result, err := json.Marshal(sessions)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(result)
}

func deleteDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	d, err := database.GetDeviceByUsername(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = router.RemovePeer(d.Address)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}

	err = database.DeleteDevice(d.Address)
	if err != nil {
		http.Error(w, fmt.Sprintf("could not delete device from database: %s", err.Error()), 404)
		return
	}

	w.Write([]byte("OK"))
}

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

func listRegistrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	result, err := database.GetRegistrationTokens()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	b, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(b)
}

func newRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	token := r.FormValue("token")
	username := r.FormValue("username")

	resp := RegistrationResult{Token: token, Username: username}

	if token != "" {
		err := database.AddRegistrationToken(token, username)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		b, err := json.Marshal(resp)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		w.Write(b)
		return
	}

	token, err = database.GenerateToken(username)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	resp.Token = token

	b, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write(b)
}

func deleteRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	id := r.FormValue("id")

	err = database.DeleteRegistrationToken(id)
	if err != nil {

		http.Error(w, errors.New("Could not delete token: "+err.Error()).Error(), 500)
		return
	}

	w.Write([]byte("OK"))
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
	if r.FormValue("cleanup") == "false" {
		err := os.WriteFile("/tmp/wag-no-cleanup", []byte("0"), 0600)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		TearDown()
	}

	w.Write([]byte("OK"))

	os.Exit(0)
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

	err := router.Pin()
	if err != nil {
		http.Error(w, errors.New("Could not unpin ebpf assets: "+err.Error()).Error(), 500)
		return
	}

	w.Write([]byte("OK"))
}

func StartControlSocket() error {
	l, err := net.Listen("unix", controlSocket)
	if err != nil {
		return err
	}

	//Yes I know this is doubling up on the umask, but meh
	if err := os.Chmod(controlSocket, 0760); err != nil {
		return err
	}

	log.Println("Started control socket: \n\t\t\t", controlSocket)

	controlMux := http.NewServeMux()

	controlMux.HandleFunc("/device/list", listDevices)
	controlMux.HandleFunc("/device/lock", lockDevice)
	controlMux.HandleFunc("/device/unlock", unlockDevice)
	controlMux.HandleFunc("/device/sessions", sessions)
	controlMux.HandleFunc("/device/delete", deleteDevice)

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
	err := os.Remove(controlSocket)
	if err != nil {
		log.Println(err)
	}
}

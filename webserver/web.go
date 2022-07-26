package webserver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"strings"
	"time"
	"wag/config"
	"wag/database"
	"wag/firewall"
	"wag/utils"
	"wag/webserver/resources"
	"wag/wireguard_manager"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	sessionTimeoutMinutes int

	wgPort      int
	wgPublicKey string

	externalAddress string

	capturedAddresses []string
)

func Start(config config.Config, publickey string, wgport int, err chan<- error) {

	sessionTimeoutMinutes = config.SessionTimeoutMinutes
	externalAddress = config.ExternalAddress

	wgPort = wgport
	wgPublicKey = publickey

	capturedAddresses = append(config.Routes.Public, config.Routes.AuthRequired...)

	log.Println("Started listening: ")

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("/static/", embeddedStatic)
	tunnel.HandleFunc("/authorise/", authorise)
	tunnel.HandleFunc("/", index)

	go func() {
		log.Println("\tTunnel Listener: ", config.Listen.Tunnel)
		err <- fmt.Errorf("Webserver tunnel listener failed: %v", http.ListenAndServe(config.Listen.Tunnel, tunnel))
	}()

	public := http.NewServeMux()
	public.HandleFunc("/register_device", registerDevice)

	go func() {
		log.Println("\tPublic Listener: ", config.Listen.Public)
		err <- fmt.Errorf("Webserver public listener failed: %v", http.ListenAndServe(config.Listen.Public, public))
	}()

}

func index(w http.ResponseWriter, r *http.Request) {

	mfaFailed := r.URL.Query().Get("success") == "0"

	actualIP := utils.GetIP(r.RemoteAddr)

	if firewall.GetSession(actualIP) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	if database.IsEnforcingMFA(utils.GetIP(actualIP)) {
		data := resources.MfaPrompt{
			ValidationFailed: mfaFailed,
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		err := resources.PromptTmpl.Execute(w, &data)
		if err != nil {
			log.Println("Unable to build template: ", err)
		}

		return
	}

	log.Println(utils.GetIP(r.RemoteAddr), " first use, showing MFA details")

	key, err := database.ShowSecret(actualIP)
	if err != nil {
		log.Println(actualIP, "showing secrete failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	image, err := key.Image(200, 200)
	if err != nil {
		log.Println(actualIP, "generating image failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	var buff bytes.Buffer
	err = png.Encode(&buff, image)
	if err != nil {
		log.Println(actualIP, "encoding mfa secret as png failed", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	data := resources.MfaDisplay{
		ImageData:        "data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes()),
		AccountName:      key.AccountName(),
		Key:              key.Secret(),
		ValidationFailed: mfaFailed,
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	err = resources.DisplayMFATmpl.Execute(w, &data)
	if err != nil {
		log.Println("Unable to build template: ", err)
		http.Error(w, "Server error", 500)
	}

}

func authorise(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/?success=1", http.StatusPermanentRedirect)
		return
	}

	actualIP := utils.GetIP(r.RemoteAddr)

	if firewall.GetSession(actualIP) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Println(actualIP, "client sent a weird form: ", err)

		http.Error(w, "Bad request", 400)
		return
	}

	code := r.FormValue("code")

	err = database.Authenticate(actualIP, code)
	if err != nil {
		log.Println(actualIP, " failed to authorise: ", err.Error())
		http.Redirect(w, r, "/?success=0", http.StatusTemporaryRedirect)
		return
	}

	err = database.SetAttemptsLeft(actualIP, 0)
	if err != nil {
		log.Println(actualIP, "unable to reset number of mfa attempts: ", err)

		http.Error(w, "Server error", 500)
		return
	}

	if !database.IsEnforcingMFA(actualIP) {
		err := database.SetMFAEnforcing(actualIP)
		if err != nil {
			log.Println(actualIP, "failed to set MFA to enforcing", err)
			http.Error(w, "Server error", 500)
		}
	}

	err = firewall.Allow(actualIP, time.Duration(sessionTimeoutMinutes)*time.Minute)
	if err != nil {
		log.Println(actualIP, "unable to allow device", err)

		http.Error(w, "Server error", 500)
		return
	}

	log.Println(actualIP, "authorised")

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write([]byte(resources.MfaSuccess))
}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	key, ok := r.URL.Query()["key"]
	if !ok || len(key[0]) < 1 || len(key) > 1 {
		log.Println("No registration key specified, ignoring")
		http.Error(w, "Server error", 500)
		return
	}

	username, err := database.GetRegistrationToken(key[0])
	if err != nil {
		log.Println(r.RemoteAddr, "failed to get registration key:", err)
		http.Error(w, "Server error", 500)
		return
	}

	var publickey, privatekey wgtypes.Key
	pubkeyParam, ok := r.URL.Query()["pubkey"]
	if len(pubkeyParam) == 1 {
		publickey, err = wgtypes.NewKey([]byte(pubkeyParam[0]))
		if err != nil {
			log.Println(r.RemoteAddr, "failed to unmarshal wireguard public key:", err)
			http.Error(w, "Server error", 500)
			return
		}
	} else {
		privatekey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Println(r.RemoteAddr, "failed to generate wireguard keys:", err)

			return
		}
		publickey = privatekey.PublicKey()
	}

	address, err := wireguard_manager.AddDevice(publickey)
	if err != nil {
		log.Println(r.RemoteAddr, "unable to add device: ", err)

		http.Error(w, "Server Error", 500)
		return
	}

	defer func() {
		if err != nil {
			log.Println(r.RemoteAddr, "removing device (due to registration failure)")
			err := wireguard_manager.RemoveDevice(publickey)
			if err != nil {
				log.Println(r.RemoteAddr, "unable to remove wg device: ", err)
			}
		}

	}()

	err = database.ArmMFAFirstUse(address, publickey.String(), username)
	if err != nil {
		log.Println(r.RemoteAddr, "unable to setup for first use mfa: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=wg0.conf")

	i := resources.Interface{
		ClientPrivateKey:  strings.TrimSpace(privatekey.String()),
		ClientAddress:     address,
		ServerAddress:     fmt.Sprintf("%s:%d", externalAddress, wgPort),
		ServerPublicKey:   wgPublicKey,
		CapturedAddresses: capturedAddresses,
	}

	err = resources.InterfaceTemplate.Execute(w, &i)
	if err != nil {
		http.Error(w, "Server Error", 500)
		return
	}

	//Finish registration process
	err = database.DeleteRegistrationToken(key[0])
	if err != nil {
		log.Println(r.RemoteAddr, "expiring registration token failed:", err)

		http.Error(w, "Server Error", 500)
		return
	}

	log.Println(r.RemoteAddr, "successfully registered as", address, ":", publickey.String())
}

package webserver

import (
	"bytes"
	"crypto/tls"
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

	isProxied bool

	helpMailAddress string
)

func Start(config config.Config, publickey string, wgport int, err chan<- error) {

	sessionTimeoutMinutes = config.SessionTimeoutMinutes
	externalAddress = config.ExternalAddress

	wgPort = wgport
	wgPublicKey = publickey

	isProxied = config.Proxied

	helpMailAddress = config.HelpMail

	capturedAddresses = append(config.Routes.Public, config.Routes.AuthRequired...)

	//https://blog.cloudflare.com/exposing-go-on-the-internet/
	tlsConfig := &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
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

	public := http.NewServeMux()
	public.HandleFunc("/register_device", registerDevice)

	if config.Webserver.Public.SupportsTLS() {

		go func() {

			srv := &http.Server{
				Addr:         config.Webserver.Public.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(public),
			}

			err <- fmt.Errorf("Webserver public listener failed: %v", srv.ListenAndServeTLS(config.Webserver.Public.CertPath, config.Webserver.Public.KeyPath))
		}()
	} else {
		go func() {
			srv := &http.Server{
				Addr:         config.Webserver.Public.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      setSecurityHeaders(public),
			}

			err <- fmt.Errorf("Webserver tunnel listener failed: %v", srv.ListenAndServe())
		}()
	}

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("/static/", embeddedStatic)
	tunnel.HandleFunc("/authorise/", authorise)
	tunnel.HandleFunc("/", index)

	if config.Webserver.Tunnel.SupportsTLS() {

		go func() {

			srv := &http.Server{
				Addr:         config.Webserver.Tunnel.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(tunnel),
			}

			err <- fmt.Errorf("Webserver public listener failed: %v", srv.ListenAndServeTLS(config.Webserver.Tunnel.CertPath, config.Webserver.Tunnel.KeyPath))
		}()
	} else {
		go func() {
			srv := &http.Server{
				Addr:         config.Webserver.Tunnel.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      setSecurityHeaders(tunnel),
			}

			err <- fmt.Errorf("Webserver public listener failed: %v", srv.ListenAndServe())
		}()
	}

	//Group the print statement so that multithreading wont disorder them
	log.Println("Started listening:\n",
		"\t\t\tTunnel Listener: ", config.Webserver.Tunnel.ListenAddress, "\n",
		"\t\t\tPublic Listener: ", config.Webserver.Public.ListenAddress)
}

func index(w http.ResponseWriter, r *http.Request) {

	mfaFailed := r.URL.Query().Get("success") == "0"

	clientTunnelIp := getIPFromRequest(r)

	if firewall.GetAllowedEndpoint(clientTunnelIp) != "" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	if database.IsEnforcingMFA(clientTunnelIp) {
		data := resources.MfaPrompt{
			ValidationFailed: mfaFailed,
			HelpMail:         helpMailAddress,
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		err := resources.PromptTmpl.Execute(w, &data)
		if err != nil {
			log.Println("Unable to build template: ", err)
		}

		return
	}

	log.Println(clientTunnelIp, " first use, showing MFA details")

	key, err := database.ShowSecret(clientTunnelIp)
	if err != nil {
		log.Println(clientTunnelIp, "showing secrete failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	image, err := key.Image(200, 200)
	if err != nil {
		log.Println(clientTunnelIp, "generating image failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	var buff bytes.Buffer
	err = png.Encode(&buff, image)
	if err != nil {
		log.Println(clientTunnelIp, "encoding mfa secret as png failed", err)
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

	clientTunnelIp := getIPFromRequest(r)

	//This must happen before authentication occurs to stop any racy effects, such as the endpoint changing just after a valid client has entered
	//their totp code
	_, endpointAddr, err := wireguard_manager.GetDevice(clientTunnelIp)
	if err != nil {
		log.Println(clientTunnelIp, "unable to find associated device: ", err)
		return
	}

	if firewall.GetAllowedEndpoint(clientTunnelIp) != "" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(clientTunnelIp, "client sent a weird form: ", err)

		http.Error(w, "Bad request", 400)
		return
	}

	code := r.FormValue("code")

	err = database.Authenticate(clientTunnelIp, code)
	if err != nil {
		log.Println(clientTunnelIp, " failed to authorise: ", err.Error())
		http.Redirect(w, r, "/?success=0", http.StatusTemporaryRedirect)
		return
	}

	err = database.SetAttemptsLeft(clientTunnelIp, 0)
	if err != nil {
		log.Println(clientTunnelIp, "unable to reset number of mfa attempts: ", err)

		http.Error(w, "Server error", 500)
		return
	}

	if !database.IsEnforcingMFA(clientTunnelIp) {
		err := database.SetMFAEnforcing(clientTunnelIp)
		if err != nil {
			log.Println(clientTunnelIp, "failed to set MFA to enforcing", err)
			http.Error(w, "Server error", 500)
			return
		}
	}

	err = firewall.Allow(clientTunnelIp, endpointAddr, time.Duration(sessionTimeoutMinutes)*time.Minute)
	if err != nil {
		log.Println(clientTunnelIp, "unable to allow device", err)

		http.Error(w, "Server error", 500)
		return
	}

	log.Println(clientTunnelIp, "authorised")

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

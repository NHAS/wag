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
	"wag/router"
	"wag/webserver/resources"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Start(err chan<- error) {

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

	if config.Values().Webserver.Public.SupportsTLS() {

		go func() {

			srv := &http.Server{
				Addr:         config.Values().Webserver.Public.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(public),
			}

			err <- fmt.Errorf("webserver public listener failed: %v", srv.ListenAndServeTLS(config.Values().Webserver.Public.CertPath, config.Values().Webserver.Public.KeyPath))
		}()
	} else {
		go func() {
			srv := &http.Server{
				Addr:         config.Values().Webserver.Public.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      setSecurityHeaders(public),
			}

			err <- fmt.Errorf("webserver tunnel listener failed: %v", srv.ListenAndServe())
		}()
	}

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("/static/", embeddedStatic)
	tunnel.HandleFunc("/authorise/", authorise)
	tunnel.HandleFunc("/acls/", acls)
	tunnel.HandleFunc("/", index)

	if config.Values().Webserver.Tunnel.SupportsTLS() {

		go func() {

			srv := &http.Server{
				Addr:         config.Values().Webserver.Tunnel.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(tunnel),
			}

			err <- fmt.Errorf("webserver tunnel listener failed: %v", srv.ListenAndServeTLS(config.Values().Webserver.Tunnel.CertPath, config.Values().Webserver.Tunnel.KeyPath))
		}()
	} else {
		go func() {
			srv := &http.Server{
				Addr:         config.Values().Webserver.Tunnel.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      setSecurityHeaders(tunnel),
			}

			err <- fmt.Errorf("webserver tunnel listener failed: %v", srv.ListenAndServe())
		}()
	}

	//Group the print statement so that multithreading wont disorder them
	log.Println("Started listening:\n",
		"\t\t\tTunnel Listener: ", config.Values().Webserver.Tunnel.ListenAddress, "\n",
		"\t\t\tPublic Listener: ", config.Values().Webserver.Public.ListenAddress)
}

func index(w http.ResponseWriter, r *http.Request) {

	mfaFailed := r.URL.Query().Get("success") == "0"

	clientTunnelIp := getIPFromRequest(r)

	if router.IsAlreadyAuthed(clientTunnelIp) != "" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	if database.IsEnforcingMFA(clientTunnelIp) {
		data := resources.MfaPrompt{
			ValidationFailed: mfaFailed,
			HelpMail:         config.Values().HelpMail,
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
	endpointAddr, err := router.GetPeerRealIp(clientTunnelIp)
	if err != nil {
		log.Println(clientTunnelIp, "unable to find associated device: ", err)
		return
	}

	if router.IsAlreadyAuthed(clientTunnelIp) != "" {
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

	username, err := database.Authenticate(clientTunnelIp, code)
	if err != nil {
		log.Println(clientTunnelIp, " failed to authorise: ", err.Error())
		http.Redirect(w, r, "/?success=0", http.StatusTemporaryRedirect)
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

	err = database.SetAttempts(clientTunnelIp, 0)
	if err != nil {
		log.Println(clientTunnelIp, "unable to reset number of mfa attempts: ", err)

		http.Error(w, "Server error", 500)
		return
	}

	err = router.AddAuthorizedRoutes(clientTunnelIp, endpointAddr)
	if err != nil {
		log.Println(username, "(", clientTunnelIp, ") unable to add mfa routes", err)

		http.Error(w, "Server error", 500)
		return
	}

	log.Println(username, "(", clientTunnelIp, ") authorised")

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write([]byte(resources.MfaSuccess))
}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	key := r.URL.Query().Get("key")
	if len(key) == 0 {
		log.Println("No registration key specified, ignoring")
		http.Error(w, "Server error", 500)
		return
	}

	username, err := database.GetRegistrationToken(key)
	if err != nil {
		log.Println(r.RemoteAddr, "failed to get registration key:", err)
		http.Error(w, "Server error", 500)
		return
	}

	var publickey, privatekey wgtypes.Key
	pubkeyParam := r.URL.Query().Get("pubkey")
	if len(pubkeyParam) != 0 {
		publickey, err = wgtypes.NewKey([]byte(pubkeyParam))
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

	address, err := router.AddPeer(publickey)
	if err != nil {
		log.Println(r.RemoteAddr, "unable to add device: ", err)

		http.Error(w, "Server Error", 500)
		return
	}

	defer func() {
		if err != nil {
			log.Println(r.RemoteAddr, "removing device (due to registration failure)")
			err := router.RemovePeer(address)
			if err != nil {
				log.Println(r.RemoteAddr, "unable to remove wg device: ", err)
			}
		}

	}()

	err = database.CreateMFAEntry(address, publickey.String(), username)
	if err != nil {
		log.Println(r.RemoteAddr, "unable to setup for first use mfa: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=wg0.conf")

	acl := config.Values().Acls.GetEffectiveAcl(username)

	wgPublicKey, wgPort, err := router.ServerDetails()
	if err != nil {
		log.Println(r.RemoteAddr, "unable access wireguard device: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	i := resources.Interface{
		ClientPrivateKey:  strings.TrimSpace(privatekey.String()),
		ClientAddress:     address,
		ServerAddress:     fmt.Sprintf("%s:%d", config.Values().ExternalAddress, wgPort),
		ServerPublicKey:   wgPublicKey.String(),
		CapturedAddresses: append(acl.Allow, acl.Mfa...),
	}

	err = resources.InterfaceTemplate.Execute(w, &i)
	if err != nil {
		http.Error(w, "Server Error", 500)
		return
	}

	err = router.AddPublicRoutes(address)
	if err != nil {
		log.Println(r.RemoteAddr, "adding public routes for new device failed:", err)

		http.Error(w, "Server Error", 500)
		return
	}

	//Finish registration process
	err = database.DeleteRegistrationToken(key)
	if err != nil {
		log.Println(r.RemoteAddr, "expiring registration token failed:", err)

		http.Error(w, "Server Error", 500)
		return
	}

	log.Println(r.RemoteAddr, "successfully registered as", address, ":", publickey.String())
}

func acls(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	clientTunnelIp := getIPFromRequest(r)

	if router.IsAlreadyAuthed(clientTunnelIp) == "" {
		http.NotFound(w, r)
		return
	}

	device, err := database.GetDeviceByIP(clientTunnelIp)
	if err != nil {
		log.Println("Could not find device: ", err)
		http.Error(w, "could not find associated device", 500)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "text/plain")

	acl := config.Values().Acls.GetEffectiveAcl(device.Username)

	w.Write([]byte(strings.Join(append(acl.Allow, acl.Mfa...), ", ")))

}

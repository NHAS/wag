package webserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"image/png"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/NHAS/wag/config"
	"github.com/NHAS/wag/data"
	"github.com/NHAS/wag/router"
	"github.com/NHAS/wag/users"
	"github.com/NHAS/wag/webserver/resources"

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
	public.HandleFunc("/reachability", reachability)

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

			err <- fmt.Errorf("TLS webserver public listener failed: %v", srv.ListenAndServeTLS(config.Values().Webserver.Public.CertPath, config.Values().Webserver.Public.KeyPath))
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

			err <- fmt.Errorf("webserver public listener failed: %v", srv.ListenAndServe())
		}()
	}

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("/static/", embeddedStatic)
	tunnel.HandleFunc("/authorise/", authorise)
	tunnel.HandleFunc("/routes/", routes)
	tunnel.HandleFunc("/", index)

	tunnelListenAddress := config.Values().Wireguard.ServerAddress.String() + ":" + config.Values().Webserver.Tunnel.Port
	if config.Values().Webserver.Tunnel.SupportsTLS() {

		go func() {

			srv := &http.Server{
				Addr:         tunnelListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(tunnel),
			}

			err <- fmt.Errorf("TLS webserver tunnel listener failed: %v", srv.ListenAndServeTLS(config.Values().Webserver.Tunnel.CertPath, config.Values().Webserver.Tunnel.KeyPath))
		}()
	} else {
		go func() {
			srv := &http.Server{
				Addr:         tunnelListenAddress,
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
		"\t\t\tTunnel Listener: ", tunnelListenAddress, "\n",
		"\t\t\tPublic Listener: ", config.Values().Webserver.Public.ListenAddress)
}

func index(w http.ResponseWriter, r *http.Request) {
	// The authorise endpoint passes us back here on auth failure/error, so we have to take errant POST's from those endpoints when we 302
	if r.Method != "GET" && r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	clientTunnelIp := getIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", 400)
		return
	}

	msg, _ := strconv.Atoi(r.URL.Query().Get("id"))

	if user.IsEnforcingMFA() {
		data := resources.MfaPrompt{
			Message:  message(msg),
			HelpMail: config.Values().HelpMail,
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		err := resources.PromptTmpl.Execute(w, &data)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to execute template: ", err)
		}

		return
	}

	log.Println(user.Username, clientTunnelIp, "first use, showing MFA details")

	key, err := user.Totp()
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "showing secret failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	image, err := key.Image(200, 200)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "generating image failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	var buff bytes.Buffer
	err = png.Encode(&buff, image)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "encoding mfa secret as png failed:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	data := resources.MfaDisplay{
		ImageData:   "data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes()),
		AccountName: key.AccountName(),
		Key:         key.Secret(),
		Message:     message(msg),
	}

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	err = resources.DisplayMFATmpl.Execute(w, &data)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to build template:", err)
		http.Error(w, "Server error", 500)
	}

}

func authorise(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	clientTunnelIp := getIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.Write([]byte(resources.MfaSuccess))
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", 400)
		return
	}

	err = r.ParseForm()
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "client sent a weird form: ", err)
		http.Error(w, "Bad request", 400)
		return
	}

	code := r.FormValue("code")

	err = user.Authenticate(clientTunnelIp.String(), code)
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
		msg := "1"
		if strings.Contains(err.Error(), "locked") {
			msg = "2"
		}
		http.Redirect(w, r, "/?id="+msg, http.StatusTemporaryRedirect)

		return
	}

	log.Println(user.Username, clientTunnelIp, "authorised")

	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Write([]byte(resources.MfaSuccess))
}

func reachability(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Add("Content-Type", "text/plain")
	w.Write([]byte("OK"))
}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	remoteAddr := getIPFromRequest(r)

	key, err := url.PathUnescape(r.URL.Query().Get("key"))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if len(key) == 0 {
		log.Println("unknown", remoteAddr, "no registration key specified, ignoring")
		http.NotFound(w, r)
		return
	}

	username, overwrites, err := data.GetRegistrationToken(key)
	if err != nil {
		log.Println(username, remoteAddr, "failed to get registration key:", err)
		http.NotFound(w, r)
		return
	}

	var publickey, privatekey wgtypes.Key
	pubkeyParam, err := url.PathUnescape(r.URL.Query().Get("pubkey"))
	if err != nil {
		log.Println(username, remoteAddr, "failed to url decode public key paramter:", err)
		http.NotFound(w, r)
		return
	}

	if len(pubkeyParam) != 0 {
		publickey, err = wgtypes.ParseKey(pubkeyParam)
		if err != nil {
			log.Println(username, remoteAddr, "failed to unmarshal wireguard public key:", err)
			http.Error(w, "Server error", 500)
			return
		}
	} else {
		privatekey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate wireguard keys:", err)
			http.Error(w, "Server error", 500)
			return
		}
		publickey = privatekey.PublicKey()
	}

	user, err := users.GetUser(username)
	if err != nil {
		user, err = users.CreateUser(username)
		if err != nil {
			log.Println(username, remoteAddr, "unable create new user: "+err.Error())
			http.Error(w, "Server Error", 500)
			return
		}
	}

	var address string
	if overwrites != "" {

		err = user.SetDevicePublicKey(publickey.String(), overwrites)
		if err != nil {
			log.Println(username, remoteAddr, "could update '", overwrites, "': ", err)
			http.Error(w, "Server Error", 500)
			return
		}

		address = overwrites

	} else {

		device, err := user.AddDevice(publickey)
		if err != nil {
			log.Println(username, remoteAddr, "unable to add device: ", err)

			http.Error(w, "Server Error", 500)
			return
		}
		address = device.Address

		defer func() {
			if err != nil {
				log.Println(username, remoteAddr, "removing device (due to registration failure)")
				err := router.RemovePeer(device.Address, device.Publickey)
				if err != nil {
					log.Println(username, remoteAddr, "unable to remove wg device: ", err)
				}
			}
		}()
	}

	w.Header().Set("Content-Disposition", "attachment; filename=wg0.conf")

	acl := config.GetEffectiveAcl(username)

	wgPublicKey, wgPort, err := router.ServerDetails()
	if err != nil {
		log.Println(username, remoteAddr, "unable access wireguard device: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	keyStr := privatekey.String()
	//Empty value of a private key in wgtype.Key
	if keyStr == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		keyStr = ""
	}

	i := resources.Interface{
		ClientPrivateKey:  keyStr,
		ClientAddress:     address,
		ServerAddress:     fmt.Sprintf("%s:%d", config.Values().ExternalAddress, wgPort),
		ServerPublicKey:   wgPublicKey.String(),
		CapturedAddresses: append(acl.Allow, acl.Mfa...),
		DNS:               config.Values().DNS,
	}

	err = resources.InterfaceTemplate.Execute(w, &i)
	if err != nil {
		log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
		http.Error(w, "Server Error", 500)
		return
	}

	//Finish registration process
	err = data.DeleteRegistrationToken(key)
	if err != nil {
		log.Println(username, remoteAddr, "expiring registration token failed:", err)
		http.Error(w, "Server Error", 500)
		return
	}

	logMsg := "registered as"
	if overwrites != "" {
		logMsg = "overwrote"
	}
	log.Println(username, remoteAddr, "successfully", logMsg, address, ":", publickey.String())
}

func routes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	remoteAddress := getIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println(user.Username, remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "text/plain")

	acl := config.GetEffectiveAcl(user.Username)

	w.Write([]byte(strings.Join(append(acl.Allow, acl.Mfa...), ", ")))

}

func message(i int) string {
	switch i {
	case 0:
		return ""
	case 1:
		return "Validation failed"
	case 2:
		return "Locked"
	default:
		return "Error"
	}
}

package webserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
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
	"github.com/NHAS/wag/webserver/authenticators"
	"github.com/NHAS/wag/webserver/resources"
	"github.com/NHAS/wag/webserver/session"
	"github.com/NHAS/webauthn/webauthn"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	webAuthN *webauthn.WebAuthn
)

func Start(errChan chan<- error) error {

	url, err := url.Parse(config.Values().Authenticators.DomainURL)
	if err != nil {
		return err
	}

	webAuthN, err = webauthn.New(&webauthn.Config{
		RPDisplayName: config.Values().Issuer,                   // Display Name for your site
		RPID:          strings.Split(url.Host, ":")[0],          // Generally the domain name for your site
		RPOrigin:      config.Values().Authenticators.DomainURL, // The origin URL for WebAuthn requests
	})

	if err != nil {
		return err
	}

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
	public.HandleFunc("/static/", embeddedStatic)
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

			errChan <- fmt.Errorf("TLS webserver public listener failed: %v", srv.ListenAndServeTLS(config.Values().Webserver.Public.CertPath, config.Values().Webserver.Public.KeyPath))
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

			errChan <- fmt.Errorf("webserver public listener failed: %v", srv.ListenAndServe())
		}()
	}

	tunnel := http.NewServeMux()

	tunnel.HandleFunc("/static/", embeddedStatic)

	tunnel.HandleFunc("/authorise/webauthn/", authoriseWebauthn)
	tunnel.HandleFunc("/authorise/totp/", authoriseTotp)
	tunnel.HandleFunc("/authorise/", authorise)

	tunnel.HandleFunc("/routes/", routes)
	tunnel.HandleFunc("/public_key/", publicKey)

	tunnel.HandleFunc("/register_mfa/webauthn/", registerWebauthn)
	tunnel.HandleFunc("/register_mfa/totp/", registerTotp)
	tunnel.HandleFunc("/register_mfa/", registerMFA)

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

			errChan <- fmt.Errorf("TLS webserver tunnel listener failed: %v", srv.ListenAndServeTLS(config.Values().Webserver.Tunnel.CertPath, config.Values().Webserver.Tunnel.KeyPath))
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

			errChan <- fmt.Errorf("webserver tunnel listener failed: %v", srv.ListenAndServe())
		}()
	}

	//Group the print statement so that multithreading wont disorder them
	log.Println("Started listening:\n",
		"\t\t\tTunnel Listener: ", tunnelListenAddress, "\n",
		"\t\t\tPublic Listener: ", config.Values().Webserver.Public.ListenAddress)
	return nil
}

func index(w http.ResponseWriter, r *http.Request) {
	// we have to take errant POST's from endpoints when they 302
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

	if user.IsEnforcingMFA() {
		http.Redirect(w, r, "/authorise/", http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, "/register_mfa/", http.StatusTemporaryRedirect)
}

func registerMFA(w http.ResponseWriter, r *http.Request) {
	// Have to take the errant posts we get from being redirected back here
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

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", 400)
		return
	}

	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	data := resources.Msg{
		Message:  message(id),
		HelpMail: config.Values().HelpMail,
	}

	method := r.URL.Query().Get("method")
	if method == "" {
		method = config.Values().Authenticators.DefaultMethod
	}
	switch method {
	case authenticators.TotpMFA:
		log.Println(user.Username, clientTunnelIp, "registration, showing TOTP (default) details")

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		err = resources.TotpMFATemplate.Execute(w, &data)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to build template:", err)
			http.Error(w, "Server error", 500)
		}

	default:
		log.Println(user.Username, clientTunnelIp, "registration, showing webauthn registration page")

		err = resources.WebauthnMFATemplate.Execute(w, &data)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to build template:", err)
			http.Error(w, "Server error", 500)
		}
	}

}

func registerTotp(w http.ResponseWriter, r *http.Request) {

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

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", 400)
		return
	}

	switch r.Method {
	case "GET":

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      config.Values().Issuer,
			AccountName: user.Username,
		})
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "generate key failed:", err)
			http.Error(w, "Unknown error", 500)
			return
		}

		err = data.SetUserMfa(user.Username, key.URL(), authenticators.TotpMFA)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to save totp key to db:", err)
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

		var mfa = struct {
			ImageData   string
			Key         string
			AccountName string
		}{
			ImageData:   "data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes()),
			Key:         key.Secret(),
			AccountName: key.AccountName(),
		}

		jsonResponse(w, &mfa, 200)

	case "POST":
		err = user.Authenticate(clientTunnelIp.String(), authenticators.Totp(w, r))
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
			msg := "1"
			if strings.Contains(err.Error(), "locked") {
				msg = "2"
			}

			http.Redirect(w, r, "/register_mfa/?id="+msg, http.StatusTemporaryRedirect)

			return
		}

		user.EnforceMFA()

		log.Println(user.Username, clientTunnelIp, "authorised")

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	default:
		http.NotFound(w, r)
		return
	}

}

func registerWebauthn(w http.ResponseWriter, r *http.Request) {

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

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", 400)
		return
	}

	switch r.Method {
	case "GET":

		webauthnUser := authenticators.NewUser(user.Username, user.Username)

		// generate PublicKeyCredentialCreationOptions, session data
		options, sessionData, err := webAuthN.BeginRegistration(
			webauthnUser,
		)

		if err != nil {
			log.Println(user.Username, clientTunnelIp, "error creating registration request for webauthn")
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "registration",
			Value: session.StartSession(sessionData),
			Path:  "/",
		})

		webauthdata, err := webauthnUser.MarshalJSON()
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "cant marshal json from webauthn")
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = data.SetUserMfa(user.Username, string(webauthdata), authenticators.WebauthnMFA)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "cant set user db to webauth user")
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		jsonResponse(w, options, http.StatusOK)
	case "POST":
		err = user.Authenticate(clientTunnelIp.String(), authenticators.WebauthnRegister(w, r, webAuthN))
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
			msg := "Validation Failed"
			if strings.Contains(err.Error(), "locked") {
				msg = "Locked."
			}

			jsonResponse(w, msg, http.StatusBadRequest)

			return
		}
		jsonResponse(w, "Registration Success", http.StatusOK)

		log.Println(user.Username, clientTunnelIp, "registered new webauthn key")

	default:
		http.NotFound(w, r)
		return
	}

}

func authorise(w http.ResponseWriter, r *http.Request) {
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

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	msg, _ := strconv.Atoi(r.URL.Query().Get("id"))

	switch user.GetMFAType() {
	default:

		data := resources.Msg{
			Message:  message(msg),
			HelpMail: config.Values().HelpMail,
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		err := resources.WebauthnMFAPromptTmpl.Execute(w, &data)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to execute template: ", err)
			http.Error(w, "Server Error", 500)
			return
		}

	case authenticators.TotpMFA:
		data := resources.Msg{
			Message:  message(msg),
			HelpMail: config.Values().HelpMail,
		}

		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		err := resources.TotpMFAPromptTmpl.Execute(w, &data)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to execute template: ", err)
			http.Error(w, "Server Error", 500)
			return
		}
	}

}

func authoriseWebauthn(w http.ResponseWriter, r *http.Request) {

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

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	switch r.Method {
	case "GET":

		webauthUserData, err := user.MFA()
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "could not get webauthn MFA details from db:", err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		var webauthnUser authenticators.WebauthnUser
		err = webauthnUser.UnmarshalJSON([]byte(webauthUserData))
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to unmarshal db object:", err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		// generate PublicKeyCredentialRequestOptions, session data
		options, sessionData, err := webAuthN.BeginLogin(webauthnUser)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to generate challenge (webauthn):", err)
			jsonResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "authentication",
			Value: session.StartSession(sessionData),
			Path:  "/",
		})

		jsonResponse(w, options, http.StatusOK)
		log.Println(user.Username, clientTunnelIp, "begun webauthn login process (sent challenge)")
	case "POST":

		err = user.Authenticate(clientTunnelIp.String(), authenticators.WebauthnLogin(w, r, webAuthN))
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
			msg := "Validation Failed"
			if strings.Contains(err.Error(), "locked") {
				msg = "Locked."
			}

			jsonResponse(w, msg, http.StatusBadRequest)

			return
		}

		jsonResponse(w, "Login Success", http.StatusOK)
		log.Println(user.Username, clientTunnelIp, "logged in")
	default:
		http.NotFound(w, r)
		return
	}
}

func authoriseTotp(w http.ResponseWriter, r *http.Request) {
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

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	err = user.Authenticate(clientTunnelIp.String(), authenticators.Totp(w, r))
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

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
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
				err := user.DeleteDevice(device.Address)
				if err != nil {
					log.Println(username, remoteAddr, "unable to remove wg device: ", err)
				}
			}
		}()
	}

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

	if r.URL.Query().Get("type") == "mobile" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var config bytes.Buffer
		err = resources.InterfaceTemplate.Execute(&config, &i)
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", 500)
			return
		}

		image, err := qr.Encode(config.String(), qr.M, qr.Auto)
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate qr code:", err)
			http.Error(w, "Server Error", 500)
		}

		image, err = barcode.Scale(image, 400, 400)
		if err != nil {
			log.Println(username, remoteAddr, "failed to output barcode bytes:", err)
			http.Error(w, "Server Error", 500)
		}

		var buff bytes.Buffer
		err = png.Encode(&buff, image)
		if err != nil {
			log.Println(user.Username, remoteAddr, "encoding mfa secret as png failed:", err)
			http.Error(w, "Unknown error", 500)
			return
		}

		qr := resources.QrCodeRegistrationDisplay{
			ImageData: "data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes()),
			Username:  username,
		}

		err = resources.DisplayRegistrationAsQRCodeTmpl.Execute(w, &qr)
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to show qr code wireguard config:", err)
			http.Error(w, "Server Error", 500)
			return
		}

	} else {
		w.Header().Set("Content-Disposition", "attachment; filename=wg0.conf")
		err = resources.InterfaceTemplate.Execute(w, &i)
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", 500)
			return
		}
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

func publicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=pubkey")
	w.Header().Set("Content-Type", "text/plain")

	wgPublicKey, _, err := router.ServerDetails()
	if err != nil {
		log.Println("unable access wireguard device: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	w.Write([]byte(wgPublicKey.String()))
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

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

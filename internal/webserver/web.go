package webserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image/png"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/routetypes"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/internal/webserver/authenticators"
	"github.com/NHAS/wag/internal/webserver/resources"
	"github.com/NHAS/wag/pkg/httputils"
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	tunnelHTTPServ *http.Server
	tunnelTLSServ  *http.Server

	publicHTTPServ *http.Server
	publicTLSServ  *http.Server
)

func Teardown() {

	if tunnelHTTPServ != nil {
		tunnelHTTPServ.Close()
	}

	if tunnelTLSServ != nil {
		tunnelTLSServ.Close()
	}

	if publicHTTPServ != nil {
		publicHTTPServ.Close()
	}

	if publicTLSServ != nil {
		publicTLSServ.Close()
	}

	log.Println("Stopped MFA portal")
}

func Start(errChan chan<- error) error {
	//https://blog.cloudflare.com/exposing-go-on-the-internet/
	tlsConfig := &tls.Config{
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

	public := httputils.NewMux()
	public.Get("/static/", embeddedStatic)
	public.Get("/register_device", registerDevice)
	public.Get("/reachability", reachability)

	if config.Values.Webserver.Public.SupportsTLS() {

		go func() {

			publicTLSServ = &http.Server{
				Addr:         config.Values.Webserver.Public.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(public),
			}

			if err := publicTLSServ.ListenAndServeTLS(config.Values.Webserver.Public.CertPath, config.Values.Webserver.Public.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("TLS webserver public listener failed: %v", err)
			}
		}()

		if config.Values.NumberProxies == 0 {
			go func() {

				address, port, err := net.SplitHostPort(config.Values.Webserver.Public.ListenAddress)

				if err != nil {
					errChan <- fmt.Errorf("malformed listen address for public listener: %v", err)
					return
				}

				// If we're supporting tls, add a redirection handler from 80 -> tls
				port += ":" + port
				if port == "443" {
					port = ""
				}

				publicHTTPServ = &http.Server{
					Addr:         address + ":80",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      setSecurityHeaders(setRedirectHandler(port)),
				}

				log.Printf("Creating redirection from 80/tcp to TLS webserver public listener failed: %v", publicHTTPServ.ListenAndServe())
			}()
		}

	} else {
		go func() {
			publicHTTPServ = &http.Server{
				Addr:         config.Values.Webserver.Public.ListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      setSecurityHeaders(public),
			}

			if err := publicHTTPServ.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("HTTP webserver public listener failed: %v", err)
			}
		}()
	}

	tunnel := httputils.NewMux()

	tunnel.Get("/status/", status)
	tunnel.Get("/routes/", routes)

	tunnel.Get("/logout/", logout)

	if config.Values.MFATemplatesDirectory != "" {
		fs := http.FileServer(http.Dir(path.Join(config.Values.MFATemplatesDirectory, "static")))
		tunnel.Handle("/custom/", http.StripPrefix("/custom/", fs))
	}

	tunnel.Get("/static/", embeddedStatic)

	// Do inital state setup for our authentication methods
	err := authenticators.AddMFARoutes(tunnel)
	if err != nil {
		return err
	}

	// For any change to the authentication config re-up
	err = registerListeners()
	if err != nil {
		return fmt.Errorf("failed ot register listeners: %s", err)
	}

	tunnel.GetOrPost("/authorise/", authorise)
	tunnel.GetOrPost("/register_mfa/", registerMFA)

	tunnel.Get("/public_key/", publicKey)

	tunnel.Get("/challenge/", router.Verifier.WS)

	tunnel.GetOrPost("/", index)

	tunnelListenAddress := config.Values.Wireguard.ServerAddress.String() + ":" + config.Values.Webserver.Tunnel.Port
	if config.Values.Webserver.Tunnel.SupportsTLS() {

		go func() {

			tunnelTLSServ = &http.Server{
				Addr:         tunnelListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				TLSConfig:    tlsConfig,
				Handler:      setSecurityHeaders(tunnel),
			}
			if err := tunnelTLSServ.ListenAndServeTLS(config.Values.Webserver.Tunnel.CertPath, config.Values.Webserver.Tunnel.KeyPath); err != nil && errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("TLS webserver tunnel listener failed: %v", err)
			}

		}()

		if config.Values.NumberProxies == 0 {
			go func() {

				port := ":" + config.Values.Webserver.Tunnel.Port
				if port == "443" {
					port = ""
				}

				tunnelHTTPServ = &http.Server{
					Addr:         config.Values.Wireguard.ServerAddress.String() + ":80",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      setSecurityHeaders(setRedirectHandler(port)),
				}

				log.Printf("HTTP redirect to TLS webserver tunnel listener failed: %v", tunnelHTTPServ.ListenAndServe())
			}()
		}
	} else {
		go func() {
			tunnelHTTPServ = &http.Server{
				Addr:         tunnelListenAddress,
				ReadTimeout:  5 * time.Second,
				WriteTimeout: 10 * time.Second,
				IdleTimeout:  120 * time.Second,
				Handler:      setSecurityHeaders(tunnel),
			}

			if err := tunnelHTTPServ.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
				errChan <- fmt.Errorf("webserver tunnel listener failed: %v", err)
			}

		}()
	}

	//Group the print statement so that multithreading won't disorder them
	log.Println("Started listening:\n",
		"\t\t\tTunnel Listener: ", tunnelListenAddress, "\n",
		"\t\t\tPublic Listener: ", config.Values.Webserver.Public.ListenAddress)
	return nil
}

func index(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if user.IsEnforcingMFA() {
		http.Redirect(w, r, "/authorise/", http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, "/register_mfa/", http.StatusTemporaryRedirect)
}

func registerMFA(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if user.IsEnforcingMFA() {
		log.Println(user.Username, clientTunnelIp, "tried to re-register mfa despite already being registered")

		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	method := r.URL.Query().Get("method")
	if method == "" {
		method, err = data.GetDefaultMfaMethod()
		if err != nil {
			method = ""
		}
	}

	if method == "" || method == "select" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var menu resources.Menu

		for _, method := range authenticators.GetAllEnabledMethods() {

			menu.MFAMethods = append(menu.MFAMethods, resources.MenuEntry{
				Path:         method.Type(),
				FriendlyName: method.FriendlyName(),
			})
		}

		menu.LastElement = len(menu.MFAMethods) - 1

		err = resources.Render("register_mfa.html", w, &menu)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to build template:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
		}

		return
	}

	mfaMethod, ok := authenticators.GetMethod(method)
	if !ok {
		log.Println(user.Username, clientTunnelIp, "Invalid MFA type requested: ", method)
		http.NotFound(w, r)
		return
	}

	mfaMethod.RegistrationUI(w, r, user.Username, clientTunnelIp.String())
}

func authorise(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	mfaMethod, ok := authenticators.GetMethod(user.GetMFAType())
	if !ok {
		log.Println(user.Username, clientTunnelIp, "Invalid MFA type requested: ", user.GetMFAType())

		http.NotFound(w, r)
		return
	}

	mfaMethod.MFAPromptUI(w, r, user.Username, clientTunnelIp.String())
}

func reachability(w http.ResponseWriter, _ *http.Request) {
	w.Header().Add("Content-Type", "text/plain")

	isDrained, err := data.IsDrained(data.GetServerID().String())
	if err != nil {
		http.Error(w, "Failed to fetch state", http.StatusInternalServerError)
		return
	}

	if !isDrained {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	w.WriteHeader(http.StatusGone)
	w.Write([]byte("Drained"))

}

func registerDevice(w http.ResponseWriter, r *http.Request) {
	remoteAddr := utils.GetIPFromRequest(r)

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

	username, overwrites, groups, err := data.GetRegistrationToken(key)
	if err != nil {
		log.Println(username, remoteAddr, "failed to get registration key:", err)
		http.NotFound(w, r)
		return
	}

	if len(groups) != 0 {
		err := data.SetUserGroupMembership(username, groups)
		if err != nil {
			log.Println(username, remoteAddr, "could not set user membership from registration token:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
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
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
	} else {
		privatekey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate wireguard keys:", err)
			http.Error(w, "Server error", http.StatusInternalServerError)
			return
		}
		publickey = privatekey.PublicKey()
	}

	user, err := users.GetUser(username)
	if err != nil {
		user, err = users.CreateUser(username)
		if err != nil {
			log.Println(username, remoteAddr, "unable create new user: "+err.Error())
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	var (
		address string
	)
	if overwrites != "" {

		err = user.SetDevicePublicKey(publickey.String(), overwrites)
		if err != nil {
			log.Println(username, remoteAddr, "could update '", overwrites, "': ", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		address = overwrites

	} else {

		// Make sure not to accidentally shadow the global err here as we're using a defer to monitor failures to delete the device
		var device data.Device
		device, err = user.AddDevice(publickey)
		if err != nil {
			log.Println(username, remoteAddr, "unable to add device: ", err)

			http.Error(w, "Server Error", http.StatusInternalServerError)
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

	acl := data.GetEffectiveAcl(username)

	wgPublicKey, wgPort, err := router.ServerDetails()
	if err != nil {
		log.Println(username, remoteAddr, "unable access wireguard device: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	keyStr := privatekey.String()
	//Empty value of a private key in wgtype.Key
	if keyStr == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		keyStr = ""
	}

	presharedKey, err := user.GetDevicePresharedKey(address)
	if err != nil {
		log.Println(username, remoteAddr, "unable access device preshared key: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	dnsWithOutSubnet, err := data.GetDNS()
	if err != nil {
		log.Println(username, remoteAddr, "unable get dns: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	for i := 0; i < len(dnsWithOutSubnet); i++ {
		dnsWithOutSubnet[i] = strings.TrimSuffix(dnsWithOutSubnet[i], "/32")
	}

	routes, err := routetypes.AclsToRoutes(append(acl.Allow, acl.Mfa...))
	if err != nil {
		log.Println(username, remoteAddr, "unable access parse acls to produce routes: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	wireguardInterface := resources.Interface{
		ClientPrivateKey:   keyStr,
		ClientAddress:      address,
		ServerPublicKey:    wgPublicKey.String(),
		CapturedAddresses:  routes,
		DNS:                dnsWithOutSubnet,
		ClientPresharedKey: presharedKey,
	}

	externalAddress, err := data.GetExternalAddress()
	if err != nil {
		log.Println(username, remoteAddr, "unable to get server external address from datastore: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	// If the external address defined in the config has a port, use that, otherwise defaultly add the same port as the wireguard device
	_, _, err = net.SplitHostPort(externalAddress)
	if err != nil {
		externalAddress = fmt.Sprintf("%s:%d", externalAddress, wgPort)
	}

	wireguardInterface.ServerAddress = externalAddress

	if r.URL.Query().Get("type") == "mobile" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var wireguardProfile bytes.Buffer
		err = resources.RenderWithFuncs("interface.tmpl", &wireguardProfile, &wireguardInterface, template.FuncMap{
			"StringsJoin": strings.Join,
			"Unescape":    func(s string) template.HTML { return template.HTML(s) },
		})
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		image, err := qr.Encode(wireguardProfile.String(), qr.M, qr.Auto)
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate qr code:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		image, err = barcode.Scale(image, 400, 400)
		if err != nil {
			log.Println(username, remoteAddr, "failed to output barcode bytes:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

		var buff bytes.Buffer
		err = png.Encode(&buff, image)
		if err != nil {
			log.Println(user.Username, remoteAddr, "encoding mfa secret as png failed:", err)
			http.Error(w, "Unknown error", http.StatusInternalServerError)
			return
		}

		qrCodeBytes := resources.QrCodeRegistrationDisplay{
			ImageData: template.URL("data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes())),
			Username:  username,
		}

		err = resources.Render("qrcode_registration.html", w, &qrCodeBytes)
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to show qr code wireguard config:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}

	} else {

		w.Header().Set("Content-Disposition", "attachment; filename="+data.GetWireguardConfigName())

		err = resources.RenderWithFuncs("interface.tmpl", w, &wireguardInterface, template.FuncMap{
			"StringsJoin": strings.Join,
			"Unescape":    func(s string) template.HTML { return template.HTML(s) },
		})
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return
		}
	}

	//Finish registration process
	err = data.FinaliseRegistration(key)
	if err != nil {
		log.Println(username, remoteAddr, "expiring registration token failed:", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	logMsg := "registered as"
	if overwrites != "" {
		logMsg = "overwrote"
	}
	log.Println(username, remoteAddr, "successfully", logMsg, address, ":", publickey.String())
}

func logout(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)

	if !router.IsAuthed(clientTunnelIp.String()) {
		http.NotFound(w, r)
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	err = user.Deauthenticate(clientTunnelIp.String())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "could not deauthenticate:", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	method, ok := authenticators.GetMethod(user.GetMFAType())
	if !ok {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	http.Redirect(w, r, method.LogoutPath(), http.StatusTemporaryRedirect)
}

func routes(w http.ResponseWriter, r *http.Request) {
	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println("unknown", remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	routes, err := router.GetRoutes(user.Username)
	if err != nil {
		log.Println(user.Username, remoteAddress, "Getting routes from xdp failed: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(strings.Join(routes, ", ")))

}

func status(w http.ResponseWriter, r *http.Request) {
	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println("unknown", remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	acl := data.GetEffectiveAcl(user.Username)

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "application/json")
	status := struct {
		IsAuthorised bool
		MFA          []string
		Public       []string
	}{
		IsAuthorised: router.IsAuthed(remoteAddress.String()),
		MFA:          acl.Mfa,
		Public:       acl.Allow,
	}

	result, err := json.Marshal(&status)
	if err != nil {
		log.Println(user.Username, remoteAddress, "error marshalling status")
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Write(result)
}

func publicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Disposition", "attachment; filename=pubkey")
	w.Header().Set("Content-Type", "text/plain")

	wgPublicKey, _, err := router.ServerDetails()
	if err != nil {
		log.Println("unable access wireguard device: ", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(wgPublicKey.String()))
}

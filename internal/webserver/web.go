package webserver

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"image/png"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
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
	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	_ "github.com/NHAS/wag/internal/webserver/authenticators/methods"
)

func Start(errChan chan<- error) error {
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

		if config.Values().NumberProxies == 0 {
			go func() {

				address, port, err := net.SplitHostPort(config.Values().Webserver.Public.ListenAddress)

				if err != nil {
					errChan <- fmt.Errorf("Malformed listen address for public listener: %v", err)
					return
				}

				// If we're supporting tls, add a redirection handler from 80 -> tls
				port += ":" + port
				if port == "443" {
					port = ""
				}

				srv := &http.Server{
					Addr:         address + ":80",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      setSecurityHeaders(setRedirectHandler(port)),
				}

				log.Printf("Creating redirection from 80/tcp to TLS webserver public listener failed: %v", srv.ListenAndServe())
			}()
		}

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

	tunnel.HandleFunc("/status/", status)
	tunnel.HandleFunc("/routes/", routes)

	tunnel.HandleFunc("/logout/", logout)

	if config.Values().MFATemplatesDirectory != "" {
		fs := http.FileServer(http.Dir(path.Join(config.Values().MFATemplatesDirectory, "static")))
		tunnel.Handle("/custom/", http.StripPrefix("/custom/", fs))
	}

	tunnel.HandleFunc("/static/", embeddedStatic)

	for method, handler := range authenticators.MFA {
		tunnel.HandleFunc("/authorise/"+method+"/", handler.AuthorisationAPI)
		tunnel.HandleFunc("/register_mfa/"+method+"/", handler.RegistrationAPI)

	}
	tunnel.HandleFunc("/authorise/", authorise)
	tunnel.HandleFunc("/register_mfa/", registerMFA)

	tunnel.HandleFunc("/public_key/", publicKey)

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

		if config.Values().NumberProxies == 0 {
			go func() {

				port := ":" + config.Values().Webserver.Tunnel.Port
				if port == "443" {
					port = ""
				}

				srv := &http.Server{
					Addr:         config.Values().Wireguard.ServerAddress.String() + ":80",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      setSecurityHeaders(setRedirectHandler(port)),
				}

				log.Printf("HTTP redirect to TLS webserver tunnel listener failed: %v", srv.ListenAndServe())
			}()
		}
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

	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

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

	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

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

	method := r.URL.Query().Get("method")
	if method == "" {
		method = config.Values().Authenticators.DefaultMethod
	}

	if method == "" || method == "select" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var menu resources.Menu

		keys := make([]string, 0, len(authenticators.MFA))
		for k := range authenticators.MFA {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, method := range keys {
			menu.MFAMethods = append(menu.MFAMethods, resources.MenuEntry{
				Path:         authenticators.MFA[method].Type(),
				FriendlyName: authenticators.MFA[method].FriendlyName(),
			})
		}

		menu.LastElement = len(menu.MFAMethods) - 1

		err = resources.Render("register_mfa.html", w, &menu)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to build template:", err)
			http.Error(w, "Server error", 500)
		}

		return
	}

	mfaMethod, ok := authenticators.MFA[method]
	if !ok {
		log.Println(user.Username, clientTunnelIp, "Invalid MFA type requested: ", method)
		http.NotFound(w, r)
		return
	}

	mfaMethod.RegistrationUI(w, r, user.Username, clientTunnelIp.String())
}

func authorise(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	clientTunnelIp := utils.GetIPFromRequest(r)

	if router.IsAuthed(clientTunnelIp.String()) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		resources.Render("success.html", w, nil)

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

	mfaMethod, ok := authenticators.MFA[user.GetMFAType()]
	if !ok {
		log.Println(user.Username, clientTunnelIp, "Invalid MFA type requested: ", user.GetMFAType())

		http.NotFound(w, r)
		return
	}

	mfaMethod.MFAPromptUI(w, r, user.Username, clientTunnelIp.String())
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
		config.AddVirtualUser(username, groups)
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

	acl := data.GetEffectiveAcl(username)

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

	presharedKey, err := user.GetDevicePresharedKey(address)
	if err != nil {
		log.Println(username, remoteAddr, "unable access device preshared key: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	dnsWithOutSubnet := config.Values().Wireguard.DNS

	for i := 0; i < len(dnsWithOutSubnet); i++ {
		dnsWithOutSubnet[i] = strings.TrimSuffix(dnsWithOutSubnet[i], "/32")
	}

	routes, err := routetypes.AclsToRoutes(append(acl.Allow, acl.Mfa...))
	if err != nil {
		log.Println(username, remoteAddr, "unable access parse acls to produce routes: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	wireguardInterface := resources.Interface{
		ClientPrivateKey:   keyStr,
		ClientAddress:      address,
		ServerAddress:      fmt.Sprintf("%s:%d", config.Values().ExternalAddress, wgPort),
		ServerPublicKey:    wgPublicKey.String(),
		CapturedAddresses:  routes,
		DNS:                dnsWithOutSubnet,
		ClientPresharedKey: presharedKey,
	}

	if r.URL.Query().Get("type") == "mobile" {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")

		var config bytes.Buffer
		err = resources.RenderWithFuncs("interface.tmpl", &config, &wireguardInterface, template.FuncMap{
			"StringsJoin": strings.Join,
			"Unescape":    func(s string) template.HTML { return template.HTML(s) },
		})
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", 500)
			return
		}

		image, err := qr.Encode(config.String(), qr.M, qr.Auto)
		if err != nil {
			log.Println(username, remoteAddr, "failed to generate qr code:", err)
			http.Error(w, "Server Error", 500)
			return
		}

		image, err = barcode.Scale(image, 400, 400)
		if err != nil {
			log.Println(username, remoteAddr, "failed to output barcode bytes:", err)
			http.Error(w, "Server Error", 500)
			return
		}

		var buff bytes.Buffer
		err = png.Encode(&buff, image)
		if err != nil {
			log.Println(user.Username, remoteAddr, "encoding mfa secret as png failed:", err)
			http.Error(w, "Unknown error", 500)
			return
		}

		qr := resources.QrCodeRegistrationDisplay{
			ImageData: template.URL("data:image/png;base64, " + base64.StdEncoding.EncodeToString(buff.Bytes())),
			Username:  username,
		}

		err = resources.Render("qrcode_registration.html", w, &qr)
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to show qr code wireguard config:", err)
			http.Error(w, "Server Error", 500)
			return
		}

	} else {
		w.Header().Set("Content-Disposition", "attachment; filename="+config.Values().DownloadConfigFileName)

		err = resources.RenderWithFuncs("interface.tmpl", w, &wireguardInterface, template.FuncMap{
			"StringsJoin": strings.Join,
			"Unescape":    func(s string) template.HTML { return template.HTML(s) },
		})
		if err != nil {
			log.Println(username, remoteAddr, "failed to execute template to generate wireguard config:", err)
			http.Error(w, "Server Error", 500)
			return
		}
	}

	//Finish registration process
	err = data.FinaliseRegistration(key)
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

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	clientTunnelIp := utils.GetIPFromRequest(r)

	if !router.IsAuthed(clientTunnelIp.String()) {
		http.NotFound(w, r)
		return
	}

	user, err := users.GetUserFromAddress(clientTunnelIp)
	if err != nil {
		log.Println("unknown", clientTunnelIp, "could not get associated device:", err)
		http.Error(w, "Bad request", 400)
		return
	}

	user.Deauthenticate(clientTunnelIp.String())

	method, ok := authenticators.MFA[user.GetMFAType()]
	if !ok {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	}

	http.Redirect(w, r, method.LogoutPath(), http.StatusTemporaryRedirect)

}

func routes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println(user.Username, remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	routes, err := router.GetRoutes(user.Username)
	if err != nil {
		log.Println(user.Username, remoteAddress, "Getting routes from xdp failed: ", err)
		http.Error(w, "Server Error", 500)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=acl")
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(strings.Join(routes, ", ")))

}

func status(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	remoteAddress := utils.GetIPFromRequest(r)
	user, err := users.GetUserFromAddress(remoteAddress)
	if err != nil {
		log.Println(user.Username, remoteAddress, "Could not find user: ", err)
		http.Error(w, "Server Error", 500)
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

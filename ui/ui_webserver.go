package ui

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/NHAS/session"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/control"
	"github.com/NHAS/wag/pkg/control/wagctl"
)

var (
	sessionManager *session.SessionStore[data.AdminModel]
	ctrl           *wagctl.CtrlClient

	WagVersion string

	LogQueue = NewQueue(40)
)

func renderDefaults(w http.ResponseWriter, r *http.Request, model interface{}, content ...string) error {

	contentPath := []string{"templates/menus.html"}
	for _, path := range content {
		contentPath = append(contentPath, "templates/"+path)
	}

	return render(w, r, model, contentPath...)

}

func render(w http.ResponseWriter, r *http.Request, model interface{}, content ...string) error {

	name := ""
	if len(content) > 0 {
		name = filepath.Base(content[0])
	}

	parsed, err := template.New(name).Funcs(template.FuncMap{
		"csrfToken": func() template.HTML {
			t, _ := sessionManager.GenerateCSRFTokenTemplateHTML(r)

			return t
		},
	}).ParseFS(templatesContent, content...)
	if err != nil {
		return fmt.Errorf("parse %s: %v", content, err)
	}

	if err := parsed.Execute(w, model); err != nil {
		return fmt.Errorf("execute %s: %v", content, err)
	}

	return nil
}

func doLogin(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":

		err := render(w, r, nil, "templates/login.html")

		if err != nil {
			log.Println("unable to render login template:", err)
			renderDefaults(w, r, nil, "error.html")

			return
		}
	case "POST":
		err := r.ParseForm()
		if err != nil {
			log.Println("bad form value: ", err)

			render(w, r, Login{ErrorMessage: "Unable to login"}, "templates/login.html")
			return
		}

		err = data.IncrementAdminAuthenticationAttempt(r.Form.Get("username"))
		if err != nil {
			log.Println("admin login failed for user", r.Form.Get("username"), ": ", err)

			render(w, r, Login{ErrorMessage: "Unable to login"}, "templates/login.html")
			return
		}

		err = data.CompareAdminKeys(r.Form.Get("username"), r.Form.Get("password"))
		if err != nil {
			log.Println("admin login failed for user", r.Form.Get("username"), ": ", err)

			render(w, r, Login{ErrorMessage: "Unable to login"}, "templates/login.html")
			return
		}

		if err := data.SetLastLoginInformation(r.Form.Get("username"), r.RemoteAddr); err != nil {
			log.Println("unable to login: ", err)

			render(w, r, Login{ErrorMessage: "Unable to login"}, "templates/login.html")
			return
		}

		adminDetails, err := data.GetAdminUser(r.Form.Get("username"))
		if err != nil {
			log.Println("unable to login: ", err)

			render(w, r, Login{ErrorMessage: "Unable to login"}, "templates/login.html")
			return
		}

		sessionManager.StartSession(w, r, adminDetails, nil)

		log.Println(r.Form.Get("username"), r.RemoteAddr, "admin logged in")

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

	default:
		http.NotFound(w, r)
	}

}

func populateDashboard(w http.ResponseWriter, r *http.Request) {

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	allUsers, err := ctrl.ListUsers("")
	if err != nil {
		log.Println("error getting users: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	unenforcedMFA := 0
	for _, u := range allUsers {
		if !u.Enforcing {
			unenforcedMFA++
		}

	}

	allDevices, err := ctrl.ListDevice("")
	if err != nil {
		log.Println("error getting devices: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	lockout, err := data.GetLockout()
	if err != nil {
		log.Println("error getting lockout: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	lockedDevices := 0
	activeSessions := 0
	for _, d := range allDevices {
		if d.Attempts >= lockout {
			lockedDevices++
		}

		if d.Active {
			activeSessions++
		}
	}

	registrations, err := ctrl.Registrations()
	if err != nil {
		log.Println("error getting registrations: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	pubkey, port, err := router.ServerDetails()
	if err != nil {
		log.Println("error getting server details: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	s, err := data.GetAllSettings()
	if err != nil {
		log.Println("error getting server settings: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}

	d := Dashboard{
		Page: Page{
			Update:      getUpdate(),
			Description: "Dashboard",
			Title:       "Dashboard",
			User:        u.Username,
			WagVersion:  WagVersion,
		},

		Port:            port,
		PublicKey:       pubkey.String(),
		ExternalAddress: s.ExternalAddress,
		Subnet:          config.Values().Wireguard.Range.String(),

		NumUsers:           len(allUsers),
		ActiveSessions:     activeSessions,
		RegistrationTokens: len(registrations),
		Devices:            len(allDevices),
		LockedDevices:      lockedDevices,
		UnenforcedMFA:      unenforcedMFA,
		LogItems:           LogQueue.ReadAll(),
	}

	err = renderDefaults(w, r, d, "management/dashboard.html")

	if err != nil {
		log.Println("unable to render dashboard page: ", err)

		w.WriteHeader(http.StatusInternalServerError)
		renderDefaults(w, r, nil, "error.html")
		return
	}
}

func StartWebServer(errs chan<- error) error {

	if !config.Values().ManagementUI.Enabled {
		log.Println("Management Web UI is disabled")
		return nil
	}

	ctrl = wagctl.NewControlClient(config.Values().Socket)

	var err error
	WagVersion, err = ctrl.GetVersion()
	if err != nil {
		return err
	}

	admins, err := ctrl.ListAdminUsers("")
	if err != nil {
		return err
	}

	if len(admins) == 0 {
		log.Println("[INFO] *************** Web interface enabled but no administrator users exist, generating new ones CREDENTIALS FOLLOW ***************")

		b := make([]byte, 16)
		_, err := rand.Read(b)
		if err != nil {
			return err
		}

		password := hex.EncodeToString(b)

		_, err = rand.Read(b[:8])
		if err != nil {
			return err
		}

		username := hex.EncodeToString(b[:8])

		log.Println("Username: ", username)
		log.Println("Password: ", password)

		log.Println("This information will not be shown again. ")

		err = ctrl.AddAdminUser(username, password, true)
		if err != nil {
			return err
		}
	}

	sessionManager, err = session.NewStore[data.AdminModel]("admin", "WAG-CSRF", 1*time.Hour, 28800, false)
	if err != nil {
		return err
	}

	log.SetOutput(io.MultiWriter(os.Stdout, &LogQueue))

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

	go func() {

		static := http.FileServer(http.FS(staticContent))

		protectedRoutes := http.NewServeMux()
		allRoutes := http.NewServeMux()
		allRoutes.HandleFunc("/login", doLogin)

		allRoutes.Handle("/js/", static)
		allRoutes.Handle("/css/", static)
		allRoutes.Handle("/img/", static)
		allRoutes.Handle("/fonts/", static)
		allRoutes.Handle("/vendor/", static)

		allRoutes.Handle("/", sessionManager.AuthorisationChecks(protectedRoutes, "/login", func(w http.ResponseWriter, r *http.Request, dAdmin data.AdminModel) bool {

			key, _ := sessionManager.GetSessionFromRequest(r)

			d, err := data.GetAdminUser(dAdmin.Username)
			if err != nil {
				sessionManager.DeleteSession(w, r)
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return false
			}

			sessionManager.UpdateSession(key, d)

			return true
		}))

		protectedRoutes.HandleFunc("/dashboard", populateDashboard)

		protectedRoutes.HandleFunc("/diag/wg", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Update:      getUpdate(),
				Description: "Wireguard Devices",
				Title:       "wg",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			renderDefaults(w, r, d, "diagnostics/wireguard_peers.html")
		})

		protectedRoutes.HandleFunc("/diag/wg/data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			peers, err := router.ListPeers()
			if err != nil {
				log.Println("unable to list wg peers: ", err)
				http.Error(w, "Server error", 500)
				return
			}

			data := []WgDevicesData{}

			for _, peer := range peers {
				ip := "-"
				if len(peer.AllowedIPs) > 0 {
					ip = peer.AllowedIPs[0].String()
				}

				data = append(data, WgDevicesData{
					PublicKey:         peer.PublicKey.String(),
					Address:           ip,
					EndpointAddress:   peer.Endpoint.String(),
					LastHandshakeTime: peer.LastHandshakeTime.Format(time.RFC1123),
				})
			}

			result, err := json.Marshal(data)
			if err != nil {
				log.Println("unable to marshal peers data: ", err)
				http.Error(w, "Server error", 500)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(result)

		})

		protectedRoutes.HandleFunc("/diag/firewall", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			rules, err := ctrl.FirewallRules()
			if err != nil {
				log.Println("error getting firewall rules data", err)
				http.Error(w, "Server Error", 500)
				return
			}

			result, err := json.MarshalIndent(rules, "", "    ")
			if err != nil {
				log.Println("error marshalling data", err)
				http.Error(w, "Server Error", 500)
				return
			}

			d := struct {
				Page
				XDPState string
			}{
				Page: Page{
					Update:      getUpdate(),
					Description: "Firewall state page",
					Title:       "Firewall",
					User:        u.Username,
					WagVersion:  WagVersion,
				},
				XDPState: string(result),
			}

			err = renderDefaults(w, r, d, "diagnostics/firewall_state.html")

			if err != nil {
				log.Println("unable to render firewall page: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}

		})

		protectedRoutes.HandleFunc("/management/users/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Update:      getUpdate(),
				Description: "Users Management Page",
				Title:       "Users",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			err := renderDefaults(w, r, d, "management/users.html", "delete_modal.html")

			if err != nil {
				log.Println("unable to render users page: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/management/users/data", contentType(manageUsers, JSON))

		protectedRoutes.HandleFunc("/management/devices/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Update:      getUpdate(),
				Description: "Devices Management Page",
				Title:       "Devices",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			err := renderDefaults(w, r, d, "management/devices.html", "delete_modal.html")

			if err != nil {
				log.Println("unable to render devices page: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/management/devices/data", contentType(devicesMgmt, JSON))

		protectedRoutes.HandleFunc("/management/registration_tokens/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Update:      getUpdate(),
				Description: "Registration Tokens Management Page",
				Title:       "Registration",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			err := renderDefaults(w, r, d, "management/registration_tokens.html", "delete_modal.html")
			if err != nil {
				log.Println("unable to render registration_tokens page: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/management/registration_tokens/data", contentType(registrationTokens, JSON))

		protectedRoutes.HandleFunc("/policy/rules/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}
			d := Page{
				Update:      getUpdate(),
				Description: "Firewall rules",
				Title:       "Rules",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			err := renderDefaults(w, r, d, "policy/rules.html", "delete_modal.html")

			if err != nil {
				log.Println("unable to render rules page: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/policy/rules/data", contentType(policies, JSON))

		protectedRoutes.HandleFunc("/policy/groups/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Update:      getUpdate(),
				Description: "Groups",
				Title:       "Groups",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			err := renderDefaults(w, r, d, "policy/groups.html", "delete_modal.html")

			if err != nil {
				log.Println("unable to render groups page: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/policy/groups/data", contentType(groups, JSON))

		protectedRoutes.HandleFunc("/settings/general", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			datastoreSettings, err := data.GetAllSettings()
			if err != nil {
				log.Println("could not get settings from datastore: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}

			d := GeneralSettings{
				Page: Page{
					Update:      getUpdate(),
					Description: "Wag settings",
					Title:       "Settings - General",
					User:        u.Username,
					WagVersion:  WagVersion,
				},

				ExternalAddress:          datastoreSettings.ExternalAddress,
				Lockout:                  datastoreSettings.Lockout,
				Issuer:                   datastoreSettings.Issuer,
				Domain:                   datastoreSettings.Domain,
				InactivityTimeoutMinutes: datastoreSettings.SessionInactivityTimeoutMinutes,
				SessionLifeTimeMinutes:   datastoreSettings.MaxSessionLifetimeMinutes,
				HelpMail:                 datastoreSettings.HelpMail,
				DNS:                      strings.Join(datastoreSettings.DNS, "\n"),
				TotpEnabled:              true,
				OidcEnabled:              false,
				WebauthnEnabled:          false,
			}

			err = renderDefaults(w, r, d, "settings/general.html")
			if err != nil {
				log.Println("unable to render general: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/settings/general/data", contentType(general, JSON))

		protectedRoutes.HandleFunc("/settings/management_users", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			_, u := sessionManager.GetSessionFromRequest(r)
			if u == nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Update:      getUpdate(),
				Description: "Wag settings",
				Title:       "Settings - Admin Users",
				User:        u.Username,
				WagVersion:  WagVersion,
			}

			err := renderDefaults(w, r, d, "settings/management_users.html")

			if err != nil {
				log.Println("unable to render management_users: ", err)

				w.WriteHeader(http.StatusInternalServerError)
				renderDefaults(w, r, nil, "error.html")
				return
			}
		})

		protectedRoutes.HandleFunc("/settings/management_users/data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			adminUsers, err := ctrl.ListAdminUsers("")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			b, err := json.Marshal(adminUsers)
			if err != nil {
				log.Println("unable to marshal management users data: ", err)
				http.Error(w, "Server error", 500)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})

		protectedRoutes.HandleFunc("/change_password", changePassword)

		protectedRoutes.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
			sessionManager.DeleteSession(w, r)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		})

		protectedRoutes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		})

		if config.Values().ManagementUI.SupportsTLS() {

			go func() {

				srv := &http.Server{
					Addr:         config.Values().ManagementUI.ListenAddress,
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					TLSConfig:    tlsConfig,
					Handler:      setSecurityHeaders(allRoutes),
				}

				errs <- fmt.Errorf("TLS management listener failed: %v", srv.ListenAndServeTLS(config.Values().ManagementUI.CertPath, config.Values().ManagementUI.KeyPath))
			}()
		} else {
			go func() {
				srv := &http.Server{
					Addr:         config.Values().ManagementUI.ListenAddress,
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      setSecurityHeaders(allRoutes),
				}

				errs <- fmt.Errorf("webserver management listener failed: %v", srv.ListenAndServe())
			}()
		}
	}()

	log.Println("Started Managemnt UI:\n\t\t\tListening:", config.Values().ManagementUI.ListenAddress)

	return nil
}

func changePassword(w http.ResponseWriter, r *http.Request) {

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	d := ChangePassword{
		Page: Page{
			Update:      getUpdate(),
			Description: "Change password page",
			Title:       "Change password",
			User:        u.Username,
			WagVersion:  WagVersion,
		},
	}

	switch r.Method {
	case "GET":

		err := renderDefaults(w, r, d, "change_password.html")
		if err != nil {
			log.Println("unable to render change password page: ", err)
			renderDefaults(w, r, nil, "error.html")
			return
		}

		return
	case "POST":
		d.Type = 0
		d.Message = "Success!"

		err := r.ParseForm()
		if err != nil {
			log.Println("bad form: ", err)

			d.Message = "Error"
			d.Type = 1

			renderDefaults(w, r, d, "change_password.html")
			return
		}

		err = data.CompareAdminKeys(u.Username, r.FormValue("current_password"))
		if err != nil {
			log.Println("bad password for admin")

			d.Message = "Current password is incorrect"
			d.Type = 1

			renderDefaults(w, r, d, "change_password.html")
			return
		}

		if r.FormValue("password1") != r.FormValue("password2") {
			log.Println("passwords do not match")

			d.Message = "New passwords do not match"
			d.Type = 1

			renderDefaults(w, r, d, "change_password.html")
			return
		}

		err = data.SetAdminPassword(u.Username, r.FormValue("password2"))
		if err != nil {
			log.Println("unable to set new admin password for ", u.Username)

			d.Message = "Error: " + err.Error()
			d.Type = 1

			renderDefaults(w, r, d, "change_password.html")
			return
		}

		renderDefaults(w, r, ChangePassword{Message: "Success!", Type: 0}, "change_password.html")
	}

}

func general(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	switch r.URL.Query().Get("type") {
	case "general":

		var general = struct {
			HelpMail        string   `json:"help_mail"`
			ExternalAddress string   `json:"external_address"`
			DNS             []string `json:"dns"`
		}{}

		if err := json.NewDecoder(r.Body).Decode(&general); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		if err := data.SetHelpMail(general.HelpMail); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetExternalAddress(general.ExternalAddress); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetDNS(general.DNS); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))
		return
	case "login":

		var login = struct {
			SessionLifetime   int `json:"session_lifetime"`
			InactivityTimeout int `json:"session_inactivity"`
			Lockout           int `json:"lockout"`
		}{}

		if err := json.NewDecoder(r.Body).Decode(&login); err != nil {
			http.Error(w, "Bad Request", 400)
			return
		}

		if err := data.SetSessionLifetimeMinutes(login.SessionLifetime); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetSessionInactivityTimeoutMinutes(login.InactivityTimeout); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if err := data.SetLockout(login.Lockout); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))
		return
	default:
		http.NotFound(w, r)
		return
	}

}

func groups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, err := ctrl.GetGroups()
		if err != nil {
			log.Println("unable to marshal rules data: ", err)
			http.Error(w, "Server error", 500)
			return
		}
		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal groups data: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	case "DELETE":
		var groupsToRemove []string
		err := json.NewDecoder(r.Body).Decode(&groupsToRemove)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group names to remove: ", err)
			return
		}

		if err := ctrl.RemoveGroup(groupsToRemove); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error removing groups: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "PUT":
		var group control.GroupData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group data to edit new group/s: ", err)
			return
		}

		if err := ctrl.EditGroup(group); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error editing group: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "POST":
		var group control.GroupData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group data to add new group: ", err)
			return
		}

		if err := ctrl.AddGroup(group); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error adding group: ", err)
			return
		}

		w.Write([]byte("OK"))
	default:
		http.NotFound(w, r)
		return
	}

}

func policies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		data, err := ctrl.GetPolicies()
		if err != nil {
			log.Println("unable to get policies: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal policies data: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return
	case "DELETE":
		var policiesToRemove []string
		err := json.NewDecoder(r.Body).Decode(&policiesToRemove)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding policy names to remove: ", err)
			return
		}

		if err := ctrl.RemovePolicies(policiesToRemove); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error removing policy: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "PUT":
		var group control.PolicyData
		err := json.NewDecoder(r.Body).Decode(&group)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding policy data to edit new group/s: ", err)
			return
		}

		if err := ctrl.EditPolicies(group); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error editing policy: ", err)
			return
		}

		w.Write([]byte("OK"))
	case "POST":
		var policy control.PolicyData
		err := json.NewDecoder(r.Body).Decode(&policy)
		if err != nil {
			http.Error(w, "Bad Request", 400)
			log.Println("error decoding group data to add new group: ", err)
			return
		}

		if err := ctrl.AddPolicy(policy); err != nil {
			http.Error(w, err.Error(), 500)
			log.Println("error adding policy: ", err)
			return
		}

		w.Write([]byte("OK"))
	default:
		http.NotFound(w, r)
		return
	}

}

func registrationTokens(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":

		registrations, err := ctrl.Registrations()
		if err != nil {
			log.Println("error getting registrations: ", err)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		data := []TokensData{}

		for _, reg := range registrations {
			data = append(data, TokensData{
				Username:   reg.Username,
				Token:      reg.Token,
				Groups:     reg.Groups,
				Overwrites: reg.Overwrites,
				Uses:       reg.NumUses,
			})
		}

		b, err := json.Marshal(data)
		if err != nil {
			log.Println("unable to marshal registration_tokens data: ", err)
			http.Error(w, "Server error", 500)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
		return

	case "DELETE":

		var tokens []string

		err := json.NewDecoder(r.Body).Decode(&tokens)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, token := range tokens {
			err := ctrl.DeleteRegistration(token)
			if err != nil {
				log.Println("Error deleting registration token: ", token, "err:", err)
			}
		}
		w.Write([]byte("OK"))

	case "POST":

		var b struct {
			Username   string
			Token      string
			Overwrites string
			Groups     string
			Uses       string
		}

		defer r.Body.Close()
		err := json.NewDecoder(r.Body).Decode(&b)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		uses, err := strconv.Atoi(b.Uses)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if uses <= 0 {
			http.Error(w, "cannot create token with <= 0 uses", 400)
			return
		}

		var groups []string
		if len(b.Groups) > 0 {
			groups = strings.Split(b.Groups, ",")
		}

		_, err = ctrl.NewRegistration(b.Token, b.Username, b.Overwrites, uses, groups...)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		w.Write([]byte("OK"))

	default:
		http.NotFound(w, r)
	}

}

func manageUsers(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		users, err := ctrl.ListUsers("")
		if err != nil {
			log.Println("error getting users: ", err)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		usersData := []UsersData{}

		for _, u := range users {
			devices, _ := ctrl.ListDevice(u.Username)

			groups, err := data.GetUserGroupMembership(u.Username)
			if err != nil {
				log.Println("unable to get users groups: ", err)
				http.Error(w, "Server error", 500)
				return
			}

			usersData = append(usersData, UsersData{
				Username: u.Username,
				Locked:   u.Locked,
				Devices:  len(devices),
				Groups:   groups,
				MFAType:  u.MfaType,
			})
		}

		b, err := json.Marshal(usersData)
		if err != nil {
			log.Println("unable to marshal users data: ", err)
			http.Error(w, "Server error", 500)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "PUT":
		var action struct {
			Action    string   `json:"action"`
			Usernames []string `json:"usernames"`
		}

		err := json.NewDecoder(r.Body).Decode(&action)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		var errs []string
		for _, username := range action.Usernames {
			var err error
			switch action.Action {
			case "lock":
				err = ctrl.LockUser(username)

			case "unlock":
				err = ctrl.UnlockUser(username)

			case "resetMFA":
				err = ctrl.ResetUserMFA(username)

			default:
				http.Error(w, "invalid action", 400)
				return
			}

			if err != nil {
				errs = append(errs, err.Error())
			}
		}

		if len(errs) > 0 {
			http.Error(w, fmt.Sprintf("%d/%d failed with errors:\n%s", len(errs), len(action.Usernames), strings.Join(errs, "\n")), 400)
			return
		}

		w.Write([]byte("OK"))

	case "DELETE":
		var usernames []string

		err := json.NewDecoder(r.Body).Decode(&usernames)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, user := range usernames {
			err := ctrl.DeleteUser(user)
			if err != nil {
				log.Println("Error deleting user: ", user, "err: ", err)
			}
		}
		w.Write([]byte("OK"))

	default:
		http.NotFound(w, r)
	}

}

func devicesMgmt(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		allDevices, err := ctrl.ListDevice("")
		if err != nil {
			log.Println("error getting devices: ", err)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		lockout, err := data.GetLockout()
		if err != nil {
			log.Println("error getting lockout: ", err)

			w.WriteHeader(http.StatusInternalServerError)
			renderDefaults(w, r, nil, "error.html")
			return
		}

		data := []DevicesData{}

		for _, dev := range allDevices {
			data = append(data, DevicesData{
				Owner:        dev.Username,
				Locked:       dev.Attempts >= lockout,
				InternalIP:   dev.Address,
				PublicKey:    dev.Publickey,
				LastEndpoint: dev.Endpoint.String(),
				Active:       dev.Active,
			})
		}

		b, err := json.Marshal(data)
		if err != nil {

			log.Println("unable to marshal devices data: ", err)
			http.Error(w, "Server error", 500)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	case "PUT":
		var action struct {
			Action    string   `json:"action"`
			Addresses []string `json:"addresses"`
		}

		err := json.NewDecoder(r.Body).Decode(&action)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, address := range action.Addresses {
			switch action.Action {
			case "lock":
				err := ctrl.LockDevice(address)
				if err != nil {
					log.Println("Error locking device: ", address, " err:", err)
				}
			case "unlock":
				err := ctrl.UnlockDevice(address)
				if err != nil {
					log.Println("Error unlocking device: ", address, " err:", err)
				}
			default:
				http.Error(w, "invalid action", 400)
				return
			}
		}

		w.Write([]byte("OK"))

	case "DELETE":
		var addresses []string

		err := json.NewDecoder(r.Body).Decode(&addresses)
		if err != nil {
			http.Error(w, "Bad request", 400)
			return
		}

		for _, address := range addresses {
			err := ctrl.DeleteDevice(address)
			if err != nil {
				log.Println("Error Deleting device: ", address, "err:", err)
			}
		}
		w.Write([]byte("OK"))

	default:
		http.NotFound(w, r)
	}

}

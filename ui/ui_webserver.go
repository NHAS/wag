package ui

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/NHAS/session"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control/wagctl"
	"github.com/NHAS/wag/pkg/httputils"
	"github.com/NHAS/wag/pkg/queue"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var (
	sessionManager *session.SessionStore[data.AdminModel]
	ctrl           *wagctl.CtrlClient

	oidcProvider rp.RelyingParty

	WagVersion string

	LogQueue = queue.NewQueue(40)

	HTTPSServer *http.Server
	HTTPServer  *http.Server
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

	var (
		parsed *template.Template
		err    error
	)

	funcsMap := template.FuncMap{
		"csrfToken": func() template.HTML {
			t, _ := sessionManager.GenerateCSRFTokenTemplateHTML(r)

			return t
		},
		"staticContent": func(functionalityName string) template.HTML {

			functionalityName = html.EscapeString(functionalityName)

			if config.Values.ManagementUI.Debug {
				functionalityName += ".js"
			} else {
				functionalityName += ".min.js"
			}

			return template.HTML(fmt.Sprintf("<script src=\"/js/%s\"></script>", functionalityName))
		},
		"notifications": func() []Notification {
			return getNotifications()
		},
		"mod": func(i, j int) bool { return i%j == 0 },
		"User": func() *data.AdminModel {
			_, u := sessionManager.GetSessionFromRequest(r)
			return u
		},
		"WagVersion": func() string {
			return WagVersion
		},
		"ClusterState": func() string {
			return clusterState
		},
		"ServerID": func() string {
			return serverID
		},
	}

	if !config.Values.ManagementUI.Debug {
		parsed, err = template.New(name).Funcs(funcsMap).ParseFS(templatesContent, content...)
	} else {

		var realFiles []string
		for _, c := range content {
			realFiles = append(realFiles, filepath.Join("ui/", c))
		}

		parsed, err = template.New(name).Funcs(funcsMap).ParseFiles(realFiles...)
	}

	if err != nil {
		return fmt.Errorf("parse %s: %v", content, err)
	}

	if err := parsed.Execute(w, model); err != nil {
		return fmt.Errorf("execute %s: %v", content, err)
	}

	return nil
}

func doLogin(w http.ResponseWriter, r *http.Request) {

	msg := Login{
		SSO:      config.Values.ManagementUI.OIDC.Enabled,
		Password: *config.Values.ManagementUI.Password.Enabled,
	}

	switch r.Method {
	case "GET":

		err := render(w, r, msg, "templates/login.html")

		if err != nil {
			log.Println("unable to render login template:", err)
			renderDefaults(w, r, nil, "error.html")

			return
		}
	case "POST":
		if *config.Values.ManagementUI.Password.Enabled {
			err := r.ParseForm()
			if err != nil {
				log.Println("bad form value: ", err)

				render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			err = data.IncrementAdminAuthenticationAttempt(r.Form.Get("username"))
			if err != nil {
				log.Println("admin login failed for user", r.Form.Get("username"), ": ", err)

				render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			err = data.CompareAdminKeys(r.Form.Get("username"), r.Form.Get("password"))
			if err != nil {
				log.Println("admin login failed for user", r.Form.Get("username"), ": ", err)

				render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			if err := data.SetLastLoginInformation(r.Form.Get("username"), r.RemoteAddr); err != nil {
				log.Println("unable to login: ", err)

				render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			adminDetails, err := data.GetAdminUser(r.Form.Get("username"))
			if err != nil {
				log.Println("unable to login: ", err)

				render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			sessionManager.StartSession(w, r, adminDetails, nil)

			log.Println(r.Form.Get("username"), r.RemoteAddr, "admin logged in")

			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

		} else {
			http.NotFound(w, r)
		}

	default:
		http.NotFound(w, r)
	}

}

func oidcCallback(w http.ResponseWriter, r *http.Request) {

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {

		adminLogin := data.AdminModel{
			Username: tokens.IDTokenClaims.PreferredUsername,
			Type:     "oidc",
		}

		sessionManager.StartSession(w, r, adminLogin, nil)
		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), oidcProvider)(w, r)
}

func StartWebServer(errs chan<- error) error {

	if !config.Values.ManagementUI.Enabled {
		log.Println("Management Web UI is disabled")
		return nil
	}

	ctrl = wagctl.NewControlClient(config.Values.Socket)

	var err error
	WagVersion, err = ctrl.GetVersion()
	if err != nil {
		return err
	}

	if config.Values.ManagementUI.OIDC.Enabled {
		key, err := utils.GenerateRandom(32)
		if err != nil {
			return errors.New("failed to get random key: " + err.Error())
		}

		hashkey, err := utils.GenerateRandom(32)
		if err != nil {
			return errors.New("failed to get random hash key: " + err.Error())
		}

		cookieHandler := httphelper.NewCookieHandler([]byte(hashkey), []byte(key), httphelper.WithUnsecure())

		options := []rp.Option{
			rp.WithCookieHandler(cookieHandler),
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		}

		u, err := url.Parse(config.Values.ManagementUI.OIDC.AdminDomainURL)
		if err != nil {
			return fmt.Errorf("failed to parse admin url: %q, err: %s", config.Values.ManagementUI.OIDC.AdminDomainURL, err)
		}

		u.Path = path.Join(u.Path, "/login/oidc/callback")
		log.Println("Admin OIDC callback: ", u.String())
		log.Println("Connecting to Admin UI OIDC provider: ", config.Values.ManagementUI.OIDC.IssuerURL)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		oidcProvider, err = rp.NewRelyingPartyOIDC(ctx, config.Values.ManagementUI.OIDC.IssuerURL, config.Values.ManagementUI.OIDC.ClientID, config.Values.ManagementUI.OIDC.ClientSecret, u.String(), []string{"openid"}, options...)
		cancel()
		if err != nil {
			return fmt.Errorf("unable to connect to oidc provider for admin ui. err %s", err)
		}

		log.Println("Connected to admin oidc provider!")
	}

	admins, err := ctrl.ListAdminUsers("")
	if err != nil {
		return err
	}

	if len(admins) == 0 {
		log.Println("[INFO] *************** Web interface enabled but no administrator users exist, generating new ones CREDENTIALS FOLLOW ***************")

		username, err := utils.GenerateRandomHex(8)
		if err != nil {
			return err
		}

		password, err := utils.GenerateRandomHex(16)
		if err != nil {
			return err
		}

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

	clusterState = "starting"
	if data.HasLeader() {
		clusterState = "healthy"
	}
	serverID = data.GetServerID().String()

	_, err = data.RegisterClusterHealthListener(watchClusterHealth)
	if err != nil {
		return err
	}

	log.SetOutput(io.MultiWriter(os.Stdout, LogQueue))

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

	go func() {

		static := http.FileServer(http.FS(staticContent))

		protectedRoutes := httputils.NewMux()
		allRoutes := httputils.NewMux()
		allRoutes.GetOrPost("/login", doLogin)
		if config.Values.ManagementUI.OIDC.Enabled {

			allRoutes.Get("/login/oidc", func(w http.ResponseWriter, r *http.Request) {
				rp.AuthURLHandler(func() string {
					r, _ := utils.GenerateRandomHex(32)
					return r
				}, oidcProvider)(w, r)
			})

			allRoutes.GetOrPost("/login/oidc/callback", oidcCallback)
		}

		if config.Values.ManagementUI.Debug {
			static := http.FileServer(http.Dir("./ui/src/"))
			allRoutes.Handle("/js/", static)
		} else {
			allRoutes.Handle("/js/", static)
		}

		allRoutes.Handle("/css/", static)
		allRoutes.Handle("/img/", static)
		allRoutes.Handle("/fonts/", static)
		allRoutes.Handle("/vendor/", static)

		allRoutes.Handle("/", sessionManager.AuthorisationChecks(protectedRoutes,
			func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			},
			func(w http.ResponseWriter, r *http.Request, dAdmin data.AdminModel) bool {

				key, adminDetails := sessionManager.GetSessionFromRequest(r)
				if adminDetails != nil {
					if adminDetails.Type == "" || adminDetails.Type == data.LocalUser {
						d, err := data.GetAdminUser(dAdmin.Username)
						if err != nil {
							sessionManager.DeleteSession(w, r)
							http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
							return false
						}

						sessionManager.UpdateSession(key, d)
					}

					// Otherwise the admin type is OIDC, and will no be in the local db
				}

				return true
			}))

		protectedRoutes.Get("/dashboard", populateDashboard)

		protectedRoutes.Get("/cluster/members/", clusterMembersUI)
		protectedRoutes.PostJSON("/cluster/members/new", newNode)
		protectedRoutes.PostJSON("/cluster/members/control", nodeControl)

		protectedRoutes.Get("/cluster/events/", clusterEventsUI)
		protectedRoutes.Post("/cluster/events/acknowledge", clusterEventsAcknowledge)

		protectedRoutes.Get("/diag/wg", wgDiagnositicsUI)
		protectedRoutes.Get("/diag/wg/data", wgDiagnositicsData)

		protectedRoutes.Get("/diag/firewall", firewallDiagnositicsUI)

		protectedRoutes.GetOrPost("/diag/check", firewallCheckTest)

		protectedRoutes.GetOrPost("/diag/acls", aclsTest)

		protectedRoutes.Get("/management/users/", usersUI)
		protectedRoutes.AllowedMethods("/management/users/data", httputils.JSON, manageUsers, http.MethodDelete, http.MethodPut, http.MethodGet)

		protectedRoutes.Get("/management/devices/", devicesMgmtUI)
		protectedRoutes.AllowedMethods("/management/devices/data", httputils.JSON, devicesMgmt, http.MethodDelete, http.MethodPut, http.MethodGet)

		protectedRoutes.Get("/management/registration_tokens/", registrationUI)
		protectedRoutes.AllowedMethods("/management/registration_tokens/data", httputils.JSON, registrationTokens, http.MethodDelete, http.MethodGet, http.MethodPost)

		protectedRoutes.Get("/policy/rules/", policiesUI)
		protectedRoutes.AllowedMethods("/policy/rules/data", httputils.JSON, policies, http.MethodDelete, http.MethodGet, http.MethodPost, http.MethodPut)

		protectedRoutes.Get("/policy/groups/", groupsUI)
		protectedRoutes.AllowedMethods("/policy/groups/data", httputils.JSON, groups, http.MethodDelete, http.MethodGet, http.MethodPost, http.MethodPut)

		protectedRoutes.Get("/settings/general", generalSettingsUI)
		protectedRoutes.PostJSON("/settings/general/data", generalSettings)

		protectedRoutes.Get("/settings/management_users", adminUsersUI)
		protectedRoutes.Get("/settings/management_users/data", adminUsersData)

		notifications := make(chan Notification, 1)
		protectedRoutes.HandleFunc("/notifications", notificationsWS(notifications))
		data.RegisterEventListener(data.NodeErrors, true, receiveErrorNotifications(notifications))
		go monitorClusterMembers(notifications)

		should, err := data.ShouldCheckUpdates()
		if err == nil && should {
			startUpdateChecker(notifications)
		}

		protectedRoutes.GetOrPost("/change_password", changePassword)

		protectedRoutes.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
			sessionManager.DeleteSession(w, r)
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		})

		protectedRoutes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		})

		if config.Values.ManagementUI.SupportsTLS() {

			go func() {

				HTTPSServer = &http.Server{
					Addr:         config.Values.ManagementUI.ListenAddress,
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					TLSConfig:    tlsConfig,
					Handler:      setSecurityHeaders(allRoutes),
				}

				if err := HTTPSServer.ListenAndServeTLS(config.Values.ManagementUI.CertPath, config.Values.ManagementUI.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errs <- fmt.Errorf("TLS management listener failed: %v", err)
				}

			}()
		} else {
			go func() {
				HTTPServer = &http.Server{
					Addr:         config.Values.ManagementUI.ListenAddress,
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      setSecurityHeaders(allRoutes),
				}
				if err := HTTPServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errs <- fmt.Errorf("webserver management listener failed: %v", HTTPServer.ListenAndServe())
				}

			}()
		}
	}()

	log.Println("Started Managemnt UI:\n\t\t\tListening:", config.Values.ManagementUI.ListenAddress)

	return nil
}

func Teardown() {

	if HTTPServer != nil {
		HTTPServer.Close()
	}

	if HTTPSServer != nil {
		HTTPSServer.Close()
	}

	if config.Values.ManagementUI.Enabled {
		log.Println("Stopped Management UI")
	}

}

func changePassword(w http.ResponseWriter, r *http.Request) {

	_, u := sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	if u.Type != data.LocalUser {
		http.NotFound(w, r)
		return
	}

	d := ChangePassword{
		Page: Page{

			Description: "Change password page",
			Title:       "Change password",
		},
	}

	switch r.Method {
	case "GET":

		err := renderDefaults(w, r, d, "change_password.html")
		if err != nil {
			log.Println("unable to render change password page: ", err)

			w.WriteHeader(http.StatusInternalServerError)
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

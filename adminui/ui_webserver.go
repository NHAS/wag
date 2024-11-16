package adminui

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control/wagctl"
	"github.com/NHAS/wag/pkg/queue"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AdminUI struct {
	sessionManager *session.SessionStore[data.AdminModel]

	ctrl     *wagctl.CtrlClient
	firewall *router.Firewall

	oidcProvider rp.RelyingParty

	logQueue *queue.Queue

	https, http *http.Server

	listenerEvents struct {
		clusterHealth string
	}

	clusterState string
	serverID     string
	wagVersion   string
}

func New(firewall *router.Firewall, errs chan<- error) (ui *AdminUI, err error) {

	if firewall == nil {
		panic("firewall was nil")
	}

	var adminUI AdminUI
	adminUI.firewall = firewall
	adminUI.logQueue = queue.NewQueue(40)

	adminUI.ctrl = wagctl.NewControlClient(config.Values.Socket)

	adminUI.wagVersion, err = adminUI.ctrl.GetVersion()
	if err != nil {
		return nil, fmt.Errorf("admin ui failed to start as we could not get wag version: %s", err)
	}

	if !config.Values.ManagementUI.OIDC.Enabled && !*config.Values.ManagementUI.Password.Enabled {
		return nil, errors.New("neither oidc or password authentication was enabled for the admin user interface, you wont be able to log in despite having it enabled")
	}

	if config.Values.ManagementUI.OIDC.Enabled {
		key, err := utils.GenerateRandom(32)
		if err != nil {
			return nil, errors.New("failed to get random key: " + err.Error())
		}

		hashkey, err := utils.GenerateRandom(32)
		if err != nil {
			return nil, errors.New("failed to get random hash key: " + err.Error())
		}

		cookieHandler := httphelper.NewCookieHandler([]byte(hashkey), []byte(key), httphelper.WithUnsecure())

		options := []rp.Option{
			rp.WithCookieHandler(cookieHandler),
			rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		}

		u, err := url.Parse(config.Values.ManagementUI.OIDC.AdminDomainURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse admin url: %q, err: %s", config.Values.ManagementUI.OIDC.AdminDomainURL, err)
		}

		u.Path = path.Join(u.Path, "/login/oidc/callback")
		log.Println("[ADMINUI] OIDC callback: ", u.String())
		log.Println("[ADMINUI] Connecting to OIDC provider: ", config.Values.ManagementUI.OIDC.IssuerURL)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		adminUI.oidcProvider, err = rp.NewRelyingPartyOIDC(ctx, config.Values.ManagementUI.OIDC.IssuerURL, config.Values.ManagementUI.OIDC.ClientID, config.Values.ManagementUI.OIDC.ClientSecret, u.String(), []string{"openid"}, options...)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("unable to connect to oidc provider for admin ui. err %s", err)
		}

		log.Println("[ADMINUI] Connected to admin oidc provider!")
	}

	if *config.Values.ManagementUI.Password.Enabled {

		admins, err := adminUI.ctrl.ListAdminUsers("")
		if err != nil {
			return nil, fmt.Errorf("failed to get all admin users for inital setup: %s", err)
		}

		if len(admins) == 0 {
			log.Println("[ADMINUI] *************** Web interface enabled but no administrator users exist, generating new ones CREDENTIALS FOLLOW ***************")

			username, err := utils.GenerateRandomHex(8)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random username: %s", err)
			}

			password, err := utils.GenerateRandomHex(16)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random password: %s", err)
			}

			log.Println("[ADMINUI] Username: ", username)
			log.Println("[ADMINUI] Password: ", password)

			log.Println("[ADMINUI] This information will not be shown again. ")

			err = adminUI.ctrl.AddAdminUser(username, password, true)
			if err != nil {
				return nil, fmt.Errorf("failed to add generated admin user: %s", err)
			}
		}
	}

	adminUI.sessionManager, err = session.NewStore[data.AdminModel]("admin", "WAG-CSRF", 1*time.Hour, 28800, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie session store: %s", err)
	}

	adminUI.clusterState = "starting"
	if data.HasLeader() {
		adminUI.clusterState = "healthy"
	}
	adminUI.serverID = data.GetServerID().String()

	adminUI.listenerEvents.clusterHealth, err = data.RegisterClusterHealthListener(adminUI.watchClusterHealth)
	if err != nil {
		return nil, fmt.Errorf("failed to register cluster health event listener: %s", err)
	}

	log.SetOutput(io.MultiWriter(os.Stdout, adminUI.logQueue))

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

		protectedRoutes := http.NewServeMux()
		allRoutes := http.NewServeMux()

		allRoutes.HandleFunc("POST /login", adminUI.doLogin)
		if config.Values.ManagementUI.OIDC.Enabled {

			allRoutes.HandleFunc("/login/oidc", func(w http.ResponseWriter, r *http.Request) {
				rp.AuthURLHandler(func() string {
					r, _ := utils.GenerateRandomHex(32)
					return r
				}, adminUI.oidcProvider)(w, r)
			})

			allRoutes.HandleFunc("/login/oidc/callback", adminUI.oidcCallback)
		}

		if config.Values.ManagementUI.Debug {
			static := http.FileServer(http.Dir("./ui/src/"))
			allRoutes.Handle("GET /js/", static)
		} else {
			allRoutes.Handle("GET /js/", static)
		}

		allRoutes.Handle("GET /css/", static)
		allRoutes.Handle("GET /img/", static)
		allRoutes.Handle("GET /fonts/", static)
		allRoutes.Handle("GET /vendor/", static)

		allRoutes.Handle("/", adminUI.sessionManager.AuthorisationChecks(protectedRoutes,
			func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			},
			func(w http.ResponseWriter, r *http.Request, dAdmin data.AdminModel) bool {

				key, adminDetails := adminUI.sessionManager.GetSessionFromRequest(r)
				if adminDetails != nil {
					if adminDetails.Type == "" || adminDetails.Type == data.LocalUser {
						d, err := data.GetAdminUser(dAdmin.Username)
						if err != nil {
							adminUI.sessionManager.DeleteSession(w, r)
							http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
							return false
						}

						adminUI.sessionManager.UpdateSession(key, d)
					}

					// Otherwise the admin type is OIDC, and will no be in the local db
				}

				return true
			}))

		protectedRoutes.HandleFunc("GET /dashboard", adminUI.populateDashboard)

		protectedRoutes.HandleFunc("POST /cluster/members/new", adminUI.newNode)
		protectedRoutes.HandleFunc("POST /cluster/members/control", adminUI.nodeControl)

		protectedRoutes.HandleFunc("PUT /cluster/events/acknowledge", adminUI.clusterEventsAcknowledge)

		protectedRoutes.HandleFunc("GET /diag/wg", adminUI.wgDiagnositicsData)
		protectedRoutes.HandleFunc("GET /diag/firewall", adminUI.getFirewallState)
		protectedRoutes.HandleFunc("POST /diag/check", adminUI.firewallCheckTest)
		protectedRoutes.HandleFunc("POST /diag/acls", adminUI.aclsTest)

		protectedRoutes.HandleFunc("GET /management/users", adminUI.getUsers)
		protectedRoutes.HandleFunc("PUT /management/users", adminUI.editUser)
		protectedRoutes.HandleFunc("DELETE /management/users", adminUI.removeUsers)

		protectedRoutes.HandleFunc("GET /management/devices", adminUI.getAllDevices)
		protectedRoutes.HandleFunc("PUT /management/devices", adminUI.editDevice)
		protectedRoutes.HandleFunc("DELETE /management/devices", adminUI.deleteDevice)

		protectedRoutes.HandleFunc("GET /management/registration_tokens", adminUI.getAllRegistrationTokens)
		protectedRoutes.HandleFunc("POST /management/registration_tokens", adminUI.createRegistrationToken)
		protectedRoutes.HandleFunc("DELETE /management/registration_tokens", adminUI.deleteRegistrationTokens)

		protectedRoutes.HandleFunc("GET /policy/rules", adminUI.getAllPolicies)
		protectedRoutes.HandleFunc("PUT /policy/rules", adminUI.editPolicy)
		protectedRoutes.HandleFunc("POST /policy/rules", adminUI.createPolicy)
		protectedRoutes.HandleFunc("DELETE /policy/rules", adminUI.deletePolices)

		protectedRoutes.HandleFunc("GET /policy/groups", adminUI.getAllGroups)
		protectedRoutes.HandleFunc("PUT /policy/groups", adminUI.editGroup)
		protectedRoutes.HandleFunc("POST /policy/groups", adminUI.createGroup)
		protectedRoutes.HandleFunc("DELETE /policy/groups", adminUI.deleteGroups)

		protectedRoutes.HandleFunc("POST /settings/general", adminUI.generalSettings)

		protectedRoutes.HandleFunc("GET /settings/management_users", adminUI.adminUsersData)

		notifications := make(chan Notification, 1)
		protectedRoutes.HandleFunc("/notifications", adminUI.notificationsWS(notifications))
		data.RegisterEventListener(data.NodeErrors, true, adminUI.receiveErrorNotifications(notifications))
		go adminUI.monitorClusterMembers(notifications)

		should, err := data.ShouldCheckUpdates()
		if err == nil && should {
			adminUI.startUpdateChecker(notifications)
		}

		protectedRoutes.HandleFunc("POST /change_password", adminUI.changePassword)

		protectedRoutes.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
			adminUI.sessionManager.DeleteSession(w, r)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		})

		protectedRoutes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		})

		if config.Values.ManagementUI.SupportsTLS() {

			go func() {

				adminUI.https = &http.Server{
					Addr:         config.Values.ManagementUI.ListenAddress,
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					TLSConfig:    tlsConfig,
					Handler:      utils.SetSecurityHeaders(allRoutes),
				}

				if err := adminUI.https.ListenAndServeTLS(config.Values.ManagementUI.CertPath, config.Values.ManagementUI.KeyPath); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errs <- fmt.Errorf("TLS management listener failed: %v", err)
				}

			}()
		} else {
			go func() {
				adminUI.http = &http.Server{
					Addr:         config.Values.ManagementUI.ListenAddress,
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 10 * time.Second,
					IdleTimeout:  120 * time.Second,
					Handler:      utils.SetSecurityHeaders(allRoutes),
				}
				if err := adminUI.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					errs <- fmt.Errorf("webserver management listener failed: %v", adminUI.http.ListenAndServe())
				}

			}()
		}
	}()

	log.Println("[ADMINUI] Started Managemnt UI listening:", config.Values.ManagementUI.ListenAddress)

	return &adminUI, nil
}

func (au *AdminUI) renderDefaults(w http.ResponseWriter, r *http.Request, model interface{}, content ...string) error {

	contentPath := []string{"templates/menus.html"}
	for _, path := range content {
		contentPath = append(contentPath, "templates/"+path)
	}

	return au.render(w, r, model, contentPath...)

}

func (au *AdminUI) render(w http.ResponseWriter, r *http.Request, model interface{}, content ...string) error {

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
			t, _ := au.sessionManager.GenerateCSRFTokenTemplateHTML(r)

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
			return au.getNotifications()
		},
		"mod": func(i, j int) bool { return i%j == 0 },
		"User": func() *data.AdminModel {
			_, u := au.sessionManager.GetSessionFromRequest(r)
			return u
		},
		"WagVersion": func() string {
			return au.wagVersion
		},
		"ClusterState": func() string {
			return au.clusterState
		},
		"ServerID": func() string {
			return au.serverID
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

func (au *AdminUI) doLogin(w http.ResponseWriter, r *http.Request) {

	msg := Login{
		SSO:      config.Values.ManagementUI.OIDC.Enabled,
		Password: *config.Values.ManagementUI.Password.Enabled,
	}

	switch r.Method {
	case "GET":

		err := au.render(w, r, msg, "templates/login.html")

		if err != nil {
			log.Println("unable to render login template:", err)
			au.renderDefaults(w, r, nil, "error.html")

			return
		}
	case "POST":
		if *config.Values.ManagementUI.Password.Enabled {

			var loginDetails data.LoginDTO

			if r.Header.Get("content-type") == "application/json" {
				err := json.NewDecoder(r.Body).Decode(&loginDetails)
				if err != nil {
					log.Println("bad json value: ", err)
					http.Error(w, "Error", http.StatusInternalServerError)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					log.Println("bad form value: ", err)

					au.render(w, r, msg.Error("Unable to login"), "templates/login.html")
					return
				}
			}

			err := data.IncrementAdminAuthenticationAttempt(loginDetails.Username)
			if err != nil {
				log.Println("admin login failed for user", loginDetails.Username, ": ", err)

				au.render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			err = data.CompareAdminKeys(loginDetails.Username, loginDetails.Password)
			if err != nil {
				log.Println("admin login failed for user", loginDetails.Username, ": ", err)

				au.render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			if err := data.SetLastLoginInformation(loginDetails.Username, r.RemoteAddr); err != nil {
				log.Println("unable to login: ", err)

				au.render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			adminDetails, err := data.GetAdminUser(loginDetails.Username)
			if err != nil {
				log.Println("unable to login: ", err)

				au.render(w, r, msg.Error("Unable to login"), "templates/login.html")
				return
			}

			au.sessionManager.StartSession(w, r, adminDetails, nil)

			log.Println(loginDetails.Username, r.RemoteAddr, "admin logged in")

			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

		} else {
			http.NotFound(w, r)
		}

	default:
		http.NotFound(w, r)
	}

}

func (au *AdminUI) oidcCallback(w http.ResponseWriter, r *http.Request) {

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {

		adminLogin, err := data.GetAdminUser(info.Subject)
		if err != nil {
			log.Printf("new admin user logged in via oidc: %q", info.PreferredUsername)

			adminLogin, err = data.CreateOidcAdminUser(info.PreferredUsername, info.Subject)
			if err != nil {
				log.Println("unable to create oidc admin entry: ", err)
				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}
		}

		log.Println(info.PreferredUsername, info.Subject, r.RemoteAddr, "oidc admin logged in")

		data.SetLastLoginInformation(info.Subject, r.RemoteAddr)

		au.sessionManager.StartSession(w, r, adminLogin, nil)
		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), au.oidcProvider)(w, r)
}

func (au *AdminUI) Close() {

	if au.http != nil {
		au.http.Close()
	}

	if au.https != nil {
		au.https.Close()
	}

	if config.Values.ManagementUI.Enabled {
		log.Println("Stopped Management UI")
	}

}

func (au *AdminUI) changePassword(w http.ResponseWriter, r *http.Request) {

	_, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	if u.Type != data.LocalUser {
		http.NotFound(w, r)
		return
	}

	var d ChangePasswordResponseDTO
	d.Type = 0
	d.Message = "Success!"

	defer func() {
		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(d)
	}()

	var req ChangePasswordRequestDTO
	err := json.NewDecoder(r.Body).Decode(&r)
	r.Body.Close()
	if err != nil {
		d.Message = "Failed"
		d.Type = 1

		return
	}

	err = data.CompareAdminKeys(u.Username, req.CurrentPassword)
	if err != nil {
		log.Println("bad password for admin")

		d.Message = "Current password is incorrect"
		d.Type = 1
		return
	}

	err = data.SetAdminPassword(u.Username, req.NewPassword)
	if err != nil {
		log.Println("unable to set new admin password for ", u.Username)

		d.Message = "Error: " + err.Error()
		d.Type = 1
		return
	}

}

package adminui

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/NHAS/session"
	"github.com/NHAS/wag/adminui/frontend"
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
	sessionManager *session.SessionStore[data.AdminUserDTO]

	ctrl     *wagctl.CtrlClient
	firewall *router.Firewall

	oidcProvider rp.RelyingParty

	logQueue *queue.Queue

	https, http *http.Server

	listenerEvents struct {
		clusterHealth string
	}

	clusterState   string
	serverID       string
	wagVersion     string
	csrfHeaderName string
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

	adminUI.csrfHeaderName = "WAG-CSRF"

	adminUI.sessionManager, err = session.NewStore[data.AdminUserDTO]("admin", adminUI.csrfHeaderName, 1*time.Hour, 28800, false)
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

		protectedRoutes := http.NewServeMux()
		allRoutes := http.NewServeMux()

		allRoutes.HandleFunc("/", frontend.Index)
		allRoutes.HandleFunc("GET /index.html", frontend.Index)

		allRoutes.HandleFunc("GET /favicon.ico", frontend.Favicon)
		allRoutes.HandleFunc("GET /assets/", frontend.Assets)

		allRoutes.HandleFunc("POST /api/login", adminUI.doLogin)
		allRoutes.HandleFunc("POST /api/refresh", adminUI.doAuthRefresh)

		if config.Values.ManagementUI.OIDC.Enabled {

			allRoutes.HandleFunc("/login/oidc", func(w http.ResponseWriter, r *http.Request) {
				rp.AuthURLHandler(func() string {
					r, _ := utils.GenerateRandomHex(32)
					return r
				}, adminUI.oidcProvider)(w, r)
			})

			allRoutes.HandleFunc("/login/oidc/callback", adminUI.oidcCallback)
		}

		allRoutes.Handle("/api/", adminUI.sessionManager.AuthorisationChecks(protectedRoutes,
			func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			},
			func(w http.ResponseWriter, r *http.Request, dAdmin data.AdminUserDTO) bool {

				key, adminDetails := adminUI.sessionManager.GetSessionFromRequest(r)
				if adminDetails != nil {
					if adminDetails.Type == "" || adminDetails.Type == data.LocalUser {
						d, err := data.GetAdminUser(dAdmin.Username)
						if err != nil {
							adminUI.sessionManager.DeleteSession(w, r)
							http.Error(w, "Unauthorized", http.StatusUnauthorized)
							return false
						}

						adminUI.sessionManager.UpdateSession(key, d)
					}

					// Otherwise the admin type is OIDC, and will no be in the local db
				}

				return true
			}))

		protectedRoutes.HandleFunc("GET /api/info", adminUI.serverInfo)
		protectedRoutes.HandleFunc("GET /api/console_log", adminUI.consoleLog)

		protectedRoutes.HandleFunc("GET /api/cluster/members", adminUI.members)
		protectedRoutes.HandleFunc("POST /api/cluster/members/new", adminUI.newNode)
		protectedRoutes.HandleFunc("POST /api/cluster/members/control", adminUI.nodeControl)

		protectedRoutes.HandleFunc("GET /api/cluster/events", adminUI.getClusterEvents)
		protectedRoutes.HandleFunc("PUT /api/cluster/events/acknowledge", adminUI.clusterEventsAcknowledge)

		protectedRoutes.HandleFunc("GET /api/diag/wg", adminUI.wgDiagnositicsData)
		protectedRoutes.HandleFunc("GET /api/diag/firewall", adminUI.getFirewallState)
		protectedRoutes.HandleFunc("POST /api/diag/check", adminUI.firewallCheckTest)
		protectedRoutes.HandleFunc("POST /api/diag/acls", adminUI.aclsTest)
		protectedRoutes.HandleFunc("POST /api/diag/notifications", adminUI.testNotifications)

		protectedRoutes.HandleFunc("GET /api/management/users", adminUI.getUsers)
		protectedRoutes.HandleFunc("PUT /api/management/users", adminUI.editUser)
		protectedRoutes.HandleFunc("DELETE /api/management/users", adminUI.removeUsers)
		protectedRoutes.HandleFunc("GET /api/management/admin_users", adminUI.adminUsersData)

		protectedRoutes.HandleFunc("GET /api/management/devices", adminUI.getAllDevices)
		protectedRoutes.HandleFunc("PUT /api/management/devices", adminUI.editDevice)
		protectedRoutes.HandleFunc("DELETE /api/management/devices", adminUI.deleteDevice)

		protectedRoutes.HandleFunc("GET /api/management/registration_tokens", adminUI.getAllRegistrationTokens)
		protectedRoutes.HandleFunc("POST /api/management/registration_tokens", adminUI.createRegistrationToken)
		protectedRoutes.HandleFunc("DELETE /api/management/registration_tokens", adminUI.deleteRegistrationTokens)

		protectedRoutes.HandleFunc("GET /api/policy/rules", adminUI.getAllPolicies)
		protectedRoutes.HandleFunc("PUT /api/policy/rules", adminUI.editPolicy)
		protectedRoutes.HandleFunc("POST /api/policy/rules", adminUI.createPolicy)
		protectedRoutes.HandleFunc("DELETE /api/policy/rules", adminUI.deletePolices)

		protectedRoutes.HandleFunc("GET /api/policy/groups", adminUI.getAllGroups)
		protectedRoutes.HandleFunc("PUT /api/policy/groups", adminUI.editGroup)
		protectedRoutes.HandleFunc("POST /api/policy/groups", adminUI.createGroup)
		protectedRoutes.HandleFunc("DELETE /api/policy/groups", adminUI.deleteGroups)

		protectedRoutes.HandleFunc("PUT /api/settings/general", adminUI.updateGeneralSettings)
		protectedRoutes.HandleFunc("PUT /api/settings/login", adminUI.updateLoginSettings)
		protectedRoutes.HandleFunc("GET /api/settings/general", adminUI.getGeneralSettings)
		protectedRoutes.HandleFunc("GET /api/settings/login", adminUI.getLoginSettings)
		protectedRoutes.HandleFunc("GET /api/settings/all_mfa_methods", adminUI.getAllMfaMethods)

		notifications := make(chan NotificationDTO, 1)
		protectedRoutes.HandleFunc("GET /api/notifications", adminUI.notificationsWS(notifications))
		data.RegisterEventListener(data.NodeErrors, true, adminUI.receiveErrorNotifications(notifications))
		go adminUI.monitorClusterMembers(notifications)

		should, err := data.ShouldCheckUpdates()
		if err == nil && should {
			adminUI.startUpdateChecker(notifications)
		}

		protectedRoutes.HandleFunc("PUT /api/change_password", adminUI.changePassword)

		protectedRoutes.HandleFunc("GET /api/logout", func(w http.ResponseWriter, r *http.Request) {
			adminUI.sessionManager.DeleteSession(w, r)
			w.WriteHeader(http.StatusNoContent)
		})

		protectedRoutes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
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

func (au *AdminUI) doAuthRefresh(w http.ResponseWriter, r *http.Request) {
	sessId, user := au.sessionManager.GetSessionFromRequest(r)
	if user == nil {
		http.Error(w, "Bad", http.StatusUnauthorized)
		return
	}

	var (
		resp LoginResponsetDTO
		err  error
	)

	defer func() {
		resp.Success = err == nil
		resp.CsrfHeader = au.csrfHeaderName

		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}()

	resp.CsrfToken, err = au.sessionManager.GenerateCSRFFromSession(sessId)
	if err != nil {
		return
	}

	resp.User = *user
}

func (au *AdminUI) doLogin(w http.ResponseWriter, r *http.Request) {

	if !*config.Values.ManagementUI.Password.Enabled {
		http.NotFound(w, r)
		return
	}

	if r.Header.Get("content-type") != "application/json" {
		http.Error(w, "Error", http.StatusBadRequest)
		return
	}

	var (
		loginDetails  LoginRequestDTO
		loginResponse LoginResponsetDTO
	)

	err := json.NewDecoder(r.Body).Decode(&loginDetails)
	if err != nil {
		log.Println("bad json value: ", err)
		http.Error(w, "Error", http.StatusInternalServerError)
		return
	}
	defer func() {
		loginResponse.Success = err == nil
		loginResponse.CsrfHeader = au.csrfHeaderName
		if !loginResponse.Success {
			w.WriteHeader(http.StatusUnauthorized)
		}

		w.Header().Set("content-type", "application/json")
		json.NewEncoder(w).Encode(loginResponse)
	}()

	err = data.IncrementAdminAuthenticationAttempt(loginDetails.Username)
	if err != nil {
		log.Println("admin login failed for user", loginDetails.Username, ": ", err)
		return
	}

	err = data.CompareAdminKeys(loginDetails.Username, loginDetails.Password)
	if err != nil {
		log.Println("admin login failed for user", loginDetails.Username, ": ", err)

		return
	}

	if err := data.SetLastLoginInformation(loginDetails.Username, r.RemoteAddr); err != nil {
		log.Println("unable to login: ", err)

		return
	}

	loginResponse.User, err = data.GetAdminUser(loginDetails.Username)
	if err != nil {
		log.Println("unable to login: ", err)
		return
	}

	sessId := au.sessionManager.StartSession(w, r, loginResponse.User, nil)
	loginResponse.CsrfToken, err = au.sessionManager.GenerateCSRFFromSession(sessId)
	if err != nil {
		log.Println("unable to login: ", err)
		return
	}

	log.Println(loginDetails.Username, r.RemoteAddr, "admin logged in")
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

	sessKey, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	if u.Type != data.LocalUser {
		http.NotFound(w, r)
		return
	}

	var (
		err error
	)
	defer func() { au.respond(err, w) }()

	var req ChangePasswordRequestDTO
	err = json.NewDecoder(r.Body).Decode(&req)
	r.Body.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = data.CompareAdminKeys(u.Username, req.CurrentPassword)
	if err != nil {
		log.Println("bad password for admin (password change)")
		err = errors.New("current password is incorrect")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = data.SetAdminPassword(u.Username, req.NewPassword)
	if err != nil {
		log.Println("unable to set new admin password for ", u.Username)

		err = fmt.Errorf("error setting password: %w", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	u.Change = false

	au.sessionManager.UpdateSession(sessKey, *u)

	log.Printf("admin %q changed their password", u.Username)

}

package adminui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/NHAS/session"
	"github.com/NHAS/tetcd/watch"
	"github.com/NHAS/wag/adminui/frontend"
	"github.com/NHAS/wag/internal/autotls"
	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/interfaces"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/pkg/control/wagctl"
	"github.com/NHAS/wag/pkg/queue"
	"github.com/NHAS/wag/pkg/safedecoder"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type AdminUI struct {
	sessionManager *session.SessionStore[config.AdminUserDTO]

	ctrl     *wagctl.CtrlClient
	firewall *router.Firewall

	oidcProvider rp.RelyingParty

	logQueue *clonerWriter

	listenerEvents struct {
		clusterHealth  string
		watchersCancel context.CancelFunc
	}

	clusterState   string
	serverID       string
	wagVersion     string
	csrfHeaderName string

	db interfaces.Database
}

type clonerWriter struct {
	w *queue.Queue[string]
}

func (c *clonerWriter) Write(b []byte) (int, error) {
	_, err := c.w.Write(string(b))
	return len(b), err
}

func New(db interfaces.Database, firewall *router.Firewall, errs chan<- error) (ui *AdminUI, err error) {

	if firewall == nil {
		panic("firewall was nil")
	}

	if db == nil {
		panic("invalid database passed, was nil")
	}

	var adminUI AdminUI
	adminUI.db = db
	adminUI.firewall = firewall
	adminUI.logQueue = &clonerWriter{
		queue.NewQueue[string](40),
	}

	adminUI.ctrl = wagctl.NewControlClient(config.Values.Socket)

	adminUI.wagVersion, err = adminUI.ctrl.GetVersion()
	if err != nil {
		return nil, fmt.Errorf("admin ui failed to start as we could not get wag version: %s", err)
	}

	if !config.Values.Webserver.Management.OIDC.Enabled && !*config.Values.Webserver.Management.Password.Enabled {
		return nil, errors.New("neither oidc or password authentication was enabled for the admin user interface, you wont be able to log in despite having it enabled")
	}

	if config.Values.Webserver.Management.OIDC.Enabled {
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

		u, err := url.Parse(config.Values.Webserver.Management.HTTPSettings.Domain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse admin url: %q, err: %s", config.Values.Webserver.Management.HTTPSettings.Domain, err)
		}

		u.Path = path.Join(u.Path, "/login/oidc/callback")

		log.Info().Str("oidc_callback", u.String()).Send()
		log.Info().Str("provider", config.Values.Webserver.Management.OIDC.IssuerURL).Msg("Connecting to OIDC provider")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		adminUI.oidcProvider, err = rp.NewRelyingPartyOIDC(ctx, config.Values.Webserver.Management.OIDC.IssuerURL, config.Values.Webserver.Management.OIDC.ClientID, config.Values.Webserver.Management.OIDC.ClientSecret, u.String(), []string{"openid"}, options...)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("unable to connect to oidc provider for admin ui. err %s", err)
		}

		log.Info().Str("provider", config.Values.Webserver.Management.OIDC.IssuerURL).Msg("Connected to admin OIDC provider!")

	}

	if *config.Values.Webserver.Management.Password.Enabled {

		admins, err := adminUI.ctrl.ListAdminUsers("")
		if err != nil {
			return nil, fmt.Errorf("failed to get all admin users for inital setup: %s", err)
		}

		if len(admins) == 0 {

			username, err := utils.GenerateRandomHex(8)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random username: %s", err)
			}

			password, err := utils.GenerateRandomHex(16)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random password: %s", err)
			}

			log.Info().Bool("credentials", true).Str("username", username).Str("password", password).Msg("********** ONE TIME CREDENTIALS This information will not be shown again. ********")

			err = adminUI.ctrl.AddAdminUser(username, password, true)
			if err != nil {
				return nil, fmt.Errorf("failed to add generated admin user: %s", err)
			}
		}
	}

	adminUI.csrfHeaderName = "WAG-CSRF"

	adminUI.sessionManager, err = session.NewStore[config.AdminUserDTO]("admin", adminUI.csrfHeaderName, 1*time.Hour, 28800, false)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie session store: %s", err)
	}

	if db.ClusterManagementEnabled() {

		adminUI.clusterState = "starting"
		if db.ClusterHasLeader() {
			adminUI.clusterState = "healthy"
		}
		adminUI.serverID = db.GetCurrentNodeID().String()

		adminUI.listenerEvents.clusterHealth, err = db.RegisterClusterHealthListener(adminUI.watchClusterHealth)
		if err != nil {
			return nil, fmt.Errorf("failed to register cluster health event listener: %s", err)
		}
	}

	log.Logger = log.Output(io.MultiWriter(os.Stdout, adminUI.logQueue)).With().Caller().Logger()

	protectedRoutes := http.NewServeMux()
	allRoutes := http.NewServeMux()

	allRoutes.HandleFunc("/", frontend.Index)
	allRoutes.HandleFunc("GET /index.html", frontend.Index)

	allRoutes.HandleFunc("GET /favicon.ico", frontend.Favicon)
	allRoutes.HandleFunc("GET /logo.png", frontend.Logo)
	allRoutes.HandleFunc("GET /assets/", frontend.Assets)

	allRoutes.HandleFunc("POST /api/login", adminUI.doLogin)
	allRoutes.HandleFunc("GET /api/config", adminUI.uiConfig)
	allRoutes.HandleFunc("POST /api/refresh", adminUI.doAuthRefresh)

	if config.Values.Webserver.Management.OIDC.Enabled {
		allRoutes.HandleFunc("GET /login/oidc", func(w http.ResponseWriter, r *http.Request) {
			rp.AuthURLHandler(func() string {
				r, _ := utils.GenerateRandomHex(32)
				return r
			}, adminUI.oidcProvider)(w, r)
		})

		allRoutes.HandleFunc("GET /login/oidc/callback", adminUI.oidcCallback)
	}

	allRoutes.Handle("/api/", adminUI.sessionManager.AuthorisationChecks(protectedRoutes,
		func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		},
		func(w http.ResponseWriter, r *http.Request, d config.AdminUserDTO) bool {

			key, adminDetails := adminUI.sessionManager.GetSessionFromRequest(r)
			if adminDetails != nil {
				if adminDetails.Type == "" || adminDetails.Type == data.LocalUser {

					admin, err := adminUI.ctrl.GetAdminUser(d.Username)
					if err != nil {
						adminUI.sessionManager.DeleteSession(w, r)
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return false
					}

					adminUI.sessionManager.UpdateSession(key, admin)
				}

				// Otherwise the admin type is OIDC, and will no be in the local db
			}

			return true
		}))

	protectedRoutes.HandleFunc("GET /api/info", adminUI.serverInfo)
	protectedRoutes.HandleFunc("GET /api/console_log", adminUI.consoleLog)

	if db.ClusterManagementEnabled() {
		protectedRoutes.HandleFunc("GET /api/cluster/members", adminUI.members)
		protectedRoutes.HandleFunc("POST /api/cluster/members", adminUI.newNode)
		protectedRoutes.HandleFunc("PUT /api/cluster/members", adminUI.nodeControl)
	}

	protectedRoutes.HandleFunc("GET /api/cluster/events", adminUI.getClusterEvents)
	protectedRoutes.HandleFunc("PUT /api/cluster/events", adminUI.clusterEventsAcknowledge)

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

	protectedRoutes.HandleFunc("GET /api/management/sessions", adminUI.getSessions)

	protectedRoutes.HandleFunc("GET /api/management/registration_tokens", adminUI.getAllRegistrationTokens)
	protectedRoutes.HandleFunc("POST /api/management/registration_tokens", adminUI.createRegistrationToken)
	protectedRoutes.HandleFunc("DELETE /api/management/registration_tokens", adminUI.deleteRegistrationTokens)

	protectedRoutes.HandleFunc("GET /api/management/webhooks/ws", adminUI.webhookWebSocket)
	protectedRoutes.HandleFunc("GET /api/management/webhooks", adminUI.getWebhooks)
	protectedRoutes.HandleFunc("POST /api/management/webhook/request", adminUI.getWebhookLastRequest)
	protectedRoutes.HandleFunc("POST /api/management/webhooks", adminUI.createWebhook)
	protectedRoutes.HandleFunc("DELETE /api/management/webhooks", adminUI.deleteWebhooks)

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

	protectedRoutes.HandleFunc("GET /api/settings/webservers", adminUI.getAllWebserverConfigs)
	protectedRoutes.HandleFunc("PUT /api/settings/webserver", adminUI.editWebserverConfig)

	protectedRoutes.HandleFunc("GET /api/settings/acme", adminUI.getAcmeDetails)
	protectedRoutes.HandleFunc("PUT /api/settings/acme/email", adminUI.editAcmeEmail)
	protectedRoutes.HandleFunc("PUT /api/settings/acme/provider_url", adminUI.editAcmeProvider)
	protectedRoutes.HandleFunc("PUT /api/settings/acme/cloudflare_api_key", adminUI.editCloudflareApiToken)

	notifications := make(chan NotificationDTO, 1)
	protectedRoutes.HandleFunc("GET /api/notifications", adminUI.notificationsWS(notifications))

	ctx, cancel := context.WithCancel(context.Background())
	adminUI.listenerEvents.watchersCancel = cancel
	err = data.InternalConfig.Nodes.Errors().Watch(ctx, db.Raw()).Start(
		watch.All(adminUI.receiveErrorNotifications(notifications)),
	)
	if err != nil {
		log.Warn().Err(err).Msg("failed to register websockets listener")
	}

	if db.ClusterManagementEnabled() {
		go adminUI.monitorClusterMembers(notifications)
	}

	should, err := db.ShouldCheckUpdates()
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

	if err := autotls.Do.DynamicListener(data.Management, utils.SetSecurityHeaders(allRoutes)); err != nil {
		return nil, err
	}

	log.Info().Str("listen_address", config.Values.Webserver.Management.HTTPSettings.ListenAddress).Msg("Started Management UI")

	return &adminUI, nil
}

func (au *AdminUI) uiConfig(w http.ResponseWriter, r *http.Request) {
	m := ConfigResponseDTO{
		SSO:      config.Values.Webserver.Management.OIDC.Enabled,
		Password: *config.Values.Webserver.Management.Password.Enabled,
	}

	json.NewEncoder(w).Encode(m)
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
		log.Error().Err(err).Msg("failed to generate CSRF token")
		return
	}

	resp.User = *user
}

func (au *AdminUI) doLogin(w http.ResponseWriter, r *http.Request) {

	if !*config.Values.Webserver.Management.Password.Enabled {
		http.NotFound(w, r)
		return
	}

	if r.Header.Get("content-type") != "application/json" {
		log.Warn().Msg("failed to generate CSRF token")

		http.Error(w, "Error", http.StatusBadRequest)
		return
	}

	var (
		loginDetails  LoginRequestDTO
		loginResponse LoginResponsetDTO
	)

	err := safedecoder.Decoder(r.Body).Decode(&loginDetails)
	if err != nil {
		log.Warn().Err(err).Msg("failed to json body")
		http.Error(w, "Error", http.StatusBadRequest)
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

	err = au.db.IncrementAdminAuthenticationAttempt(loginDetails.Username)
	if err != nil {
		log.Warn().Err(err).Str("username", loginDetails.Username).Msg("admin login failed for user")
		return
	}

	err = au.db.CompareAdminKeys(loginDetails.Username, loginDetails.Password)
	if err != nil {
		log.Warn().Err(err).Str("username", loginDetails.Username).Msg("admin login failed for user")
		return
	}

	if err := au.db.SetLastLoginInformation(loginDetails.Username, r.RemoteAddr); err != nil {
		log.Error().Err(err).Str("username", loginDetails.Username).Msg("unable to login could not set last login information")
		return
	}

	loginResponse.User, err = au.ctrl.GetAdminUser(loginDetails.Username)
	if err != nil {
		log.Error().Err(err).Str("username", loginDetails.Username).Msg("could not fetch admin user information")
		return
	}

	sessId := au.sessionManager.StartSession(w, r, loginResponse.User, nil)
	loginResponse.CsrfToken, err = au.sessionManager.GenerateCSRFFromSession(sessId)
	if err != nil {
		log.Error().Err(err).Msg("unable to login")
		return
	}

	log.Info().Str("username", loginDetails.Username).Str("remote_addr", r.RemoteAddr).Msg("admin logged in")
}

func (au *AdminUI) oidcCallback(w http.ResponseWriter, r *http.Request) {

	marshalUserinfo := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty, info *oidc.UserInfo) {

		adminLogin, err := au.ctrl.GetAdminUser(info.Subject)
		if err != nil {
			log.Info().Str("idp_admin_username", info.PreferredUsername).Msg("new admin user logged in via oidc")

			adminLogin, err = au.db.CreateOidcAdminUser(info.PreferredUsername, info.Subject)
			if err != nil {
				log.Error().Err(err).Msg("unable to create OIDC user admin entry")

				http.Error(w, "Server Error", http.StatusInternalServerError)
				return
			}
		}

		err = au.db.SetLastLoginInformation(info.Subject, r.RemoteAddr)
		if err != nil {
			log.Error().Err(err).Str("username", info.PreferredUsername).Str("subject", info.Subject).Str("remote_addr", r.RemoteAddr).Bool("oidc", true).Msg("unable to login could not set last login information")
			http.Error(w, "Server Error", http.StatusInternalServerError)
			return

		}

		log.Info().Str("username", info.PreferredUsername).Str("subject", info.Subject).Str("remote_addr", r.RemoteAddr).Bool("oidc", true).Msg("admin logged in")

		au.sessionManager.StartSession(w, r, adminLogin, nil)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}

	rp.CodeExchangeHandler(rp.UserinfoCallback(marshalUserinfo), au.oidcProvider)(w, r)
}

func (au *AdminUI) Close() {

	autotls.Do.Close(data.Management)

	if config.Values.Webserver.Management.Enabled {
		log.Info().Msg("Stopped Management UI")
	}
}

func (au *AdminUI) changePassword(w http.ResponseWriter, r *http.Request) {

	sessKey, u := au.sessionManager.GetSessionFromRequest(r)
	if u == nil {
		http.NotFound(w, r)
		return
	}

	if u.Type != data.LocalUser {
		http.NotFound(w, r)
		log.Info().Str("username", u.Username).Str("subject", u.OidcGUID).Msg("oidc user attempted to change their local password")

		return
	}

	var (
		err error
	)
	defer func() { au.respond(err, w) }()

	var req ChangePasswordRequestDTO
	err = safedecoder.Decoder(r.Body).Decode(&req)
	r.Body.Close()
	if err != nil {
		log.Warn().Str("username", u.Username).Err(err).Msg("failed to decode json body")

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = au.db.CompareAdminKeys(u.Username, req.CurrentPassword)
	if err != nil {
		log.Warn().Err(err).Str("username", u.Username).Msg("bad password for admin (password change)")

		err = errors.New("current password is incorrect")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	err = au.ctrl.SetAdminUserPassword(u.Username, req.NewPassword)
	if err != nil {
		log.Error().Err(err).Str("username", u.Username).Msg("unable to set new admin password")

		err = fmt.Errorf("error setting password: %w", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	u.Change = false

	au.sessionManager.UpdateSession(sessKey, *u)

	log.Info().Str("username", u.Username).Msg("changed their password")
}

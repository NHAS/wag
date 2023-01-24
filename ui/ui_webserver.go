package ui

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/pkg/control/wagctl"
	"github.com/NHAS/wag/pkg/session"
)

var (
	uiTemplates map[string]*template.Template = map[string]*template.Template{
		"dashboard":           template.Must(template.ParseFS(templatesContent, "template.html", "templates/management/dashboard.html")),
		"users":               template.Must(template.ParseFS(templatesContent, "template.html", "templates/management/users.html")),
		"devices":             template.Must(template.ParseFS(templatesContent, "template.html", "templates/management/devices.html")),
		"registration_tokens": template.Must(template.ParseFS(templatesContent, "template.html", "templates/management/registration_tokens.html")),
		"rules":               template.Must(template.ParseFS(templatesContent, "template.html", "templates/policy/rules.html")),
		"general":             template.Must(template.ParseFS(templatesContent, "template.html", "templates/settings/general.html")),
		"management_users":    template.Must(template.ParseFS(templatesContent, "template.html", "templates/settings/management_users.html")),
		"change_password":     template.Must(template.ParseFS(templatesContent, "template.html", "templates/change_password.html")),
		"404":                 template.Must(template.ParseFS(templatesContent, "template.html", "templates/404.html")),
		"login":               template.Must(template.ParseFS(templatesContent, "login.html")),
	}

	sessions = session.NewSessionManager()
	ctrl     *wagctl.CtrlClient
)

type AdminContextKey string

const adminKey AdminContextKey = "admin"

type authMiddleware struct {
	next http.Handler
}

func (sh *authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("admin")
	if err != nil {
		log.Println("attempted to get admin page without admin cookie")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	user, err := sessions.GetSession(cookie.Value)
	if err != nil {
		log.Println("attempted to get admin page without session")
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	ctx := context.WithValue(r.Context(), adminKey, user)

	sh.next.ServeHTTP(w, r.WithContext(ctx))
}

func setAuth(f http.Handler) http.Handler {
	return &authMiddleware{
		next: f,
	}
}

type AdminUser struct {
	Username string
}

func doLogin(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case "GET":
		err := uiTemplates["login"].Execute(w, nil)

		if err != nil {
			log.Println("unable to render login template:", err)
			return
		}
	case "POST":
		err := r.ParseForm()
		if err != nil {
			log.Println("bad form value: ", err)
			return
		}

		err = data.CompareAdminKeys(r.Form.Get("username"), r.Form.Get("password"))
		if err != nil {
			log.Println("unable to login: ", err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:  "admin",
			Value: sessions.StartSession(AdminUser{Username: r.Form.Get("username")}),
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)

	default:
		http.NotFound(w, r)
	}

}

func populateDashboard(w http.ResponseWriter, r *http.Request) {
	u, ok := r.Context().Value(adminKey).(AdminUser)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	allUsers, err := ctrl.ListUsers("")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		log.Println("error getting users: ", err)
		return
	}

	unenforcedMFA := 0
	for _, u := range allUsers {
		if u.Enforcing {
			unenforcedMFA++
		}
	}

	allDevices, err := ctrl.ListDevice("")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		log.Println("error getting devices: ", err)
		return
	}

	lockout := config.Values().Lockout
	lockedDevices := 0
	for _, d := range allDevices {
		if d.Attempts >= lockout {
			lockedDevices++
		}
	}

	registrations, err := ctrl.Registrations()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		log.Println("error getting registrations: ", err)
		return
	}

	session, err := ctrl.Sessions()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		log.Println("error getting sessions: ", err)
		return
	}

	pubkey, port, err := router.ServerDetails()
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		log.Println("error getting server details: ", err)
		return
	}

	d := Dashboard{
		Page: Page{
			Description: "Dashboard",
			Title:       "Dashboard",
			User:        u.Username,
		},

		Port:            port,
		PublicKey:       pubkey.String(),
		ExternalAddress: config.Values().ExternalAddress,
		Subnet:          config.Values().Wireguard.Range.String(),

		NumUsers:           len(allUsers),
		ActiveSessions:     len(session),
		RegistrationTokens: len(registrations),
		Devices:            len(allDevices),
		LockedDevices:      lockedDevices,
		UnenforcedMFA:      unenforcedMFA,
	}

	err = uiTemplates["dashboard"].Execute(w, d)

	if err != nil {
		log.Println("unable to render dashboard page: ", err)
		return
	}
}
func StartWebServer(errs chan<- error) {

	if config.Values().Webserver.Management.ListenAddress == "" {
		log.Println("Management web interface disabled as listen address not defined")
		return
	}

	ctrl = wagctl.NewControlClient(config.Values().Socket)

	go func() {

		static := http.FileServer(http.FS(staticContent))

		protectedRoutes := http.NewServeMux()
		allRoutes := http.NewServeMux()
		allRoutes.HandleFunc("/login", doLogin)
		allRoutes.Handle("/css/", static)
		allRoutes.Handle("/js/", static)
		allRoutes.Handle("/vendor/", static)
		allRoutes.Handle("/img/", static)
		allRoutes.Handle("/", setAuth(protectedRoutes))

		protectedRoutes.HandleFunc("/dashboard", populateDashboard)

		protectedRoutes.HandleFunc("/management/users/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			u, ok := r.Context().Value(adminKey).(AdminUser)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Description: "Users Management Page",
				Title:       "Users",
				User:        u.Username,
			}

			err := uiTemplates["users"].Execute(w, d)

			if err != nil {
				log.Println("unable to render users page")
				return
			}
		})

		protectedRoutes.HandleFunc("/management/users/data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			users, err := ctrl.ListUsers("")
			if err != nil {
				log.Println("error getting users: ", err)
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			var m struct {
				Data []UsersData `json:"data"`
			}

			for _, u := range users {
				devices, _ := ctrl.ListDevice(u.Username)

				m.Data = append(m.Data, UsersData{
					Username:  u.Username,
					Enforcing: u.Enforcing,
					Locked:    u.Locked,
					Devices:   len(devices),
					Groups:    strings.Join(config.Values().Acls.Groups[u.Username], ","),
				})
			}

			b, err := json.Marshal(m)
			if err != nil {
				log.Println("unable to marshal users data")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})

		protectedRoutes.HandleFunc("/management/devices/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			u, ok := r.Context().Value(adminKey).(AdminUser)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Description: "Devices Management Page",
				Title:       "Devices",
				User:        u.Username,
			}

			err := uiTemplates["devices"].Execute(w, d)

			if err != nil {
				log.Println("unable to render devices page")
				return
			}
		})

		protectedRoutes.HandleFunc("/management/devices/data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			allDevices, err := ctrl.ListDevice("")
			if err != nil {
				log.Println("error getting devices: ", err)
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			var jsonDevices struct {
				Data []DevicesData `json:"data"`
			}

			lockout := config.Values().Lockout

			for _, dev := range allDevices {
				jsonDevices.Data = append(jsonDevices.Data, DevicesData{
					Owner:        dev.Username,
					Locked:       dev.Attempts >= lockout,
					InternalIP:   dev.Address,
					PublicKey:    dev.Publickey,
					LastEndpoint: dev.Endpoint.String(),
				})
			}

			b, err := json.Marshal(jsonDevices)
			if err != nil {

				log.Println("unable to marshal devices data")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})

		protectedRoutes.HandleFunc("/management/registration_tokens/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			u, ok := r.Context().Value(adminKey).(AdminUser)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Description: "Registration Tokens Management Page",
				Title:       "Registration",
				User:        u.Username,
			}

			err := uiTemplates["registration_tokens"].Execute(w, d)

			if err != nil {
				log.Println("unable to render registration_tokens page")
				return
			}
		})

		protectedRoutes.HandleFunc("/management/registration_tokens/data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			registrations, err := ctrl.Registrations()
			if err != nil {
				log.Println("error getting registrations: ", err)
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			var data struct {
				Data []TokensData `json:"data"`
			}

			data.Data = []TokensData{}

			for _, reg := range registrations {
				data.Data = append(data.Data, TokensData{
					Username:   reg.Username,
					Token:      reg.Token,
					Groups:     strings.Join(reg.Groups, ","),
					Overwrites: reg.Overwrites,
				})
			}

			b, err := json.Marshal(data)
			if err != nil {
				log.Println("unable to marshal registration_tokens data")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})

		protectedRoutes.HandleFunc("/policy/rules/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			u, ok := r.Context().Value(adminKey).(AdminUser)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Description: "Firewall rules",
				Title:       "Rules",
				User:        u.Username,
			}

			err := uiTemplates["rules"].Execute(w, d)

			if err != nil {
				log.Println("unable to render rules page")
				return
			}
		})

		protectedRoutes.HandleFunc("/policy/rules/data", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			var data struct {
				Data []PolicyData `json:"data"`
			}

			for k, v := range config.Values().Acls.Policies {
				data.Data = append(data.Data, PolicyData{
					Effects:         k,
					NumPublicRoutes: len(v.Allow),
					NumbMfaRoutes:   len(v.Mfa),
				})
			}

			b, err := json.Marshal(data)
			if err != nil {
				log.Println("unable to marshal rules data")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})

		protectedRoutes.HandleFunc("/settings/general", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			u, ok := r.Context().Value(adminKey).(AdminUser)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			c := config.Values()

			d := GeneralSettings{
				Page: Page{
					Description: "Wag settings",
					Title:       "Settings - General",
					User:        u.Username,
				},

				ExternalAddress:          c.ExternalAddress,
				Lockout:                  c.Lockout,
				Issuer:                   c.Authenticators.Issuer,
				Domain:                   c.Authenticators.DomainURL,
				InactivityTimeoutMinutes: c.SessionInactivityTimeoutMinutes,
				SessionLifeTimeMinutes:   c.MaxSessionLifetimeMinutes,
				HelpMail:                 c.HelpMail,
				DNS:                      strings.Join(c.Wireguard.DNS, ","),
				TotpEnabled:              true,
				OidcEnabled:              false,
				WebauthnEnabled:          false,
			}

			err := uiTemplates["general"].Execute(w, d)

			if err != nil {
				log.Println("unable to settings general")
				return
			}
		})

		protectedRoutes.HandleFunc("/settings/management_users", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				http.NotFound(w, r)
				return
			}

			u, ok := r.Context().Value(adminKey).(AdminUser)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
				return
			}

			d := Page{
				Description: "Wag settings",
				Title:       "Settings - Admin Users",
				User:        u.Username,
			}

			err := uiTemplates["management_users"].Execute(w, d)

			if err != nil {
				log.Println("unable to settings management_users")
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

			var data struct {
				Data []data.AdminModel `json:"data"`
			}

			data.Data = adminUsers

			b, err := json.Marshal(adminUsers)
			if err != nil {
				log.Println("unable to marshal management users data")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		})

		protectedRoutes.HandleFunc("/change_password", changePassword)

		protectedRoutes.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
		})

		errs <- http.ListenAndServe(config.Values().Webserver.Management.ListenAddress, allRoutes)

	}()
}

func changePassword(w http.ResponseWriter, r *http.Request) {

	u, ok := r.Context().Value(adminKey).(AdminUser)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	switch r.Method {
	case "GET":
		d := Page{
			Description: "Change password page",
			Title:       "Change password",
			User:        u.Username,
		}

		err := uiTemplates["change_password"].Execute(w, d)

		if err != nil {
			log.Println("unable to render change password page")
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		return
	case "POST":
		err := r.ParseForm()
		if err != nil {
			log.Println("bad form")
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		err = data.CompareAdminKeys(u.Username, r.FormValue("current_password"))
		if err != nil {
			log.Println("bad password for admin")
			http.Redirect(w, r, "/change_password", http.StatusTemporaryRedirect)
			return
		}

		if r.FormValue("password1") != r.FormValue("password2") {
			log.Println("passwords do not match")
			http.Redirect(w, r, "/change_password", http.StatusTemporaryRedirect)
			return
		}

		err = data.SetAdminPassword(u.Username, r.FormValue("current_password"))
		if err != nil {
			log.Println("unable to set new admin password for ", u.Username)
			http.Redirect(w, r, "/change_password", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)

	}

}

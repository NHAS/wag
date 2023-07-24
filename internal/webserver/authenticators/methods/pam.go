package methods

import (
	"errors"
	"log"
	"net/http"

	"github.com/NHAS/wag/internal/config"
	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/NHAS/wag/internal/webserver/authenticators"
	"github.com/NHAS/wag/internal/webserver/resources"
	"github.com/msteinert/pam"
)

// Supported is true when built with PAM
var Supported = true
var serviceName = ""

type Pam struct {
}

func (t *Pam) Init(settings map[string]string) error {
	serviceName = settings["ServiceName"]
	return nil
}

func (t *Pam) Type() string {
	return authenticators.PamMFA
}

func (t *Pam) FriendlyName() string {
	return "Pam OTP"
}

func (t *Pam) RegistrationAPI(w http.ResponseWriter, r *http.Request) {
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

	switch r.Method {
	case "GET":
		err = data.SetUserMfa(user.Username, "PAMauth", authenticators.PamMFA)
		if err != nil {
			log.Println(user.Username, clientTunnelIp, "unable to save PAM key to db:", err)
			http.Error(w, "Unknown error", 500)
			return
		}

		jsonResponse(w, user.Username, 200)

	case "POST":
		err = user.Authenticate(clientTunnelIp.String(), t.Type(), t.AuthoriseFunc(w, r))
		msg, status := resultMessage(err)
		jsonResponse(w, msg, status)

		if err != nil {
			log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
			return
		}

		log.Println(user.Username, clientTunnelIp, "authorised")
		user.EnforceMFA()

	default:
		http.NotFound(w, r)
		return
	}
}

func (t *Pam) AuthorisationAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
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

	err = user.Authenticate(clientTunnelIp.String(), t.Type(), t.AuthoriseFunc(w, r))

	msg, status := resultMessage(err)
	jsonResponse(w, msg, status)

	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
		return
	}

	log.Println(user.Username, clientTunnelIp, "authorised")

}

func (t *Pam) AuthoriseFunc(w http.ResponseWriter, r *http.Request) authenticators.AuthenticatorFunc {
	return func(mfaSecret, username string) error {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Bad request", 400)
			return err
		}

		passwd := r.FormValue("code")

		t, err := pam.StartFunc(serviceName, username, func(s pam.Style, msg string) (string, error) {
			switch s {
			case pam.PromptEchoOff:
				return passwd, nil
			case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
				return "", nil
			}
			return "", errors.New("unrecognized PAM message style")
		})
		if err != nil {
			return errors.New("PAM start failed")
		}

		if err = t.Authenticate(0); err != nil {
			return errors.New("PAM authentication failed")
		}

		if err = t.AcctMgmt(0); err != nil {
			return errors.New("PAM account failed")
		}

		// PAM login names might suffer transformations in the PAM stack.
		// We should take whatever the PAM stack returns for it.
		user, err := t.GetItem(pam.User)
		if err != nil {
			return errors.New("PAM get user '" + user + "' failed")
		} else {
			return nil
		}
	}
}

func (t *Pam) MFAPromptUI(w http.ResponseWriter, r *http.Request, username, ip string) {
	if err := resources.Render("prompt_mfa_pam.html", w, &resources.Msg{
		HelpMail:   config.Values().HelpMail,
		NumMethods: len(authenticators.MFA),
	}); err != nil {
		log.Println(username, ip, "unable to render pam prompt template: ", err)
	}
}

func (t *Pam) RegistrationUI(w http.ResponseWriter, r *http.Request, username, ip string) {
	if err := resources.Render("register_mfa_pam.html", w, &resources.Msg{
		HelpMail:   config.Values().HelpMail,
		NumMethods: len(authenticators.MFA),
	}); err != nil {
		log.Println(username, ip, "unable to render pam mfa template: ", err)
	}
}

func (t *Pam) LogoutPath() string {
	return "/"
}

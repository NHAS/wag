package authenticators

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"path"

	"fmt"

	"github.com/NHAS/wag/internal/data"
	"github.com/NHAS/wag/internal/mfaportal/authenticators/types"
	"github.com/NHAS/wag/internal/router"
	"github.com/NHAS/wag/internal/users"
	"github.com/NHAS/wag/internal/utils"
	"github.com/msteinert/pam"
)

type Pam struct {
	enable

	fw *router.Firewall
}

func (t *Pam) Initialise(fw *router.Firewall, initiallyEnabled bool) (routes *http.ServeMux, err error) {
	t.fw = fw

	routes = http.NewServeMux()
	routes.HandleFunc("POST /register/complete", isUnregisteredFunc(
		isUnauthedFunc(t.completeRegistration, fw)),
	)
	routes.HandleFunc("POST /authorise",
		isUnauthedFunc(t.authorise, fw),
	)

	return nil, nil
}

func (t *Pam) ReloadSettings() error {
	return nil
}

func (t *Pam) Type() string {
	return string(types.Pam)
}

func (t *Pam) FriendlyName() string {
	return "System Login"
}

func (t *Pam) completeRegistration(w http.ResponseWriter, r *http.Request) {
	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	err := data.SetUserMfa(user.Username, "PAMauth", t.Type())
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "unable to save PAM key to db:", err)
		http.Error(w, "Unknown error", 500)
		return
	}

	err = user.Authenticate(clientTunnelIp.String(), t.Type(), t.AuthoriseFunc(w, r))

	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
		msg, status := resultMessage(err)
		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  msg,
		}, status)

		return
	}

	log.Println(user.Username, clientTunnelIp, "authorised")
	jsonResponse(w, AuthResponse{
		Status: "success",
	}, http.StatusOK)
}

func (t *Pam) authorise(w http.ResponseWriter, r *http.Request) {

	clientTunnelIp := utils.GetIPFromRequest(r)
	user := users.GetUserFromContext(r.Context())

	if !user.IsEnforcingMFA() {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	err := user.Authenticate(clientTunnelIp.String(), t.Type(), t.AuthoriseFunc(w, r))
	if err != nil {
		log.Println(user.Username, clientTunnelIp, "failed to authorise: ", err.Error())
		msg, status := resultMessage(err)
		jsonResponse(w, AuthResponse{
			Status: "error",
			Error:  msg,
		}, status)
		return
	}

	jsonResponse(w, AuthResponse{
		Status: "success",
	}, http.StatusOK)
	log.Println(user.Username, clientTunnelIp, "authorised")

}

func (t *Pam) AuthoriseFunc(w http.ResponseWriter, r *http.Request) types.AuthenticatorFunc {
	return func(mfaSecret, username string) error {
		defer r.Body.Close()

		clientTunnelIp := utils.GetIPFromRequest(r)

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var suppliedDetails PAMRequestDTO
		err := dec.Decode(&suppliedDetails)
		if err != nil {
			return fmt.Errorf("failed to decode pam details: %s", err)
		}

		pamDetails, err := data.GetPAM()
		if err != nil {
			return err
		}

		serviceFilePath := path.Join("/etc/pam.d/", path.Join("/", path.Clean(pamDetails.ServiceName)))
		pamRulesFile := "config " + serviceFilePath
		if pamDetails.ServiceName == "" {
			pamDetails.ServiceName = "login"
			pamRulesFile = "default PAM /etc/pam.d/login"
		}

		log.Printf("%q %s attempting to authorise with PAM (using %q )", username, clientTunnelIp, pamRulesFile)
		t, err := pam.StartFunc(pamDetails.ServiceName, username, func(s pam.Style, msg string) (string, error) {

			switch s {
			case pam.PromptEchoOff:
				return suppliedDetails.Password, nil
			case pam.PromptEchoOn, pam.ErrorMsg, pam.TextInfo:
				return "", nil
			}
			return "", errors.New("unrecognized PAM message style")
		})
		if err != nil {
			return errors.New("PAM start failed: " + err.Error())
		}

		if err = t.Authenticate(0); err != nil {
			return errors.New("PAM authentication failed: " + err.Error())
		}

		if err = t.AcctMgmt(0); err != nil {
			return errors.New("PAM account failed: " + err.Error())
		}

		// PAM login names might suffer transformations in the PAM stack.
		// We should take whatever the PAM stack returns for it.
		pamUsername, err := t.GetItem(pam.User)
		if err != nil {
			return fmt.Errorf("PAM get user %q (%s) failed: %s", pamUsername, username, err)
		}

		return nil
	}
}
